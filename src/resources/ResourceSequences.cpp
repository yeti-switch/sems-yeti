#include "ResourceRedisConnection.h"
#include <sstream>
#include <algorithm>
#include "ResourceControl.h"

using namespace std; 

template<typename... Args>
inline bool postReadRedisRequestFmt(
    ResourceRedisConnection* conn,
    AmObject *user_data,
    int user_type_id,
    const char *fmt, Args... args)
{
    return postRedisRequestFmt(
        conn->get_read_conn(),
        conn->get_queue_name(),
        conn->get_queue_name(), false,
        user_data, user_type_id,
        fmt, args...);
}
#define SEQ_REDIS_READ(fmt, args...) postReadRedisRequestFmt(conn, this, user_type_id, fmt, ##args)

template<typename... Args>
inline bool postWriteRedisRequestFmt(
    ResourceRedisConnection* conn,
    AmObject *user_data,
    int user_type_id,
    const char *fmt, Args... args)
{
    return postRedisRequestFmt(
        conn->get_write_conn(),
        conn->get_queue_name(),
        conn->get_queue_name(), false,
        user_data, user_type_id,
        fmt, args...);
}
#define SEQ_REDIS_WRITE(fmt, args...) postWriteRedisRequestFmt(conn, this, user_type_id, fmt, ##args)

static string get_key(Resource &r)
{
    ostringstream ss;
    ss << "r:" << r.type << ":" << r.id;
    return ss.str();
}

static bool isArgNumber(const AmArg& arg)
{
    return isArgInt(arg) || isArgLongLong(arg) || isArgDouble(arg);
}

long int Reply2Int(AmArg& r)
{
    long int ret = 0;
    char *s;
    if(isArgNumber(r))
        ret = r.asLongLong();
    else if(isArgUndef(r))//non existent key
        ret = 0;
    else if(isArgCStr(r)) {//string response
        s = (char*)r.asCStr();
        if(!str2long(s,ret)){
            ERROR("Reply2Int: conversion falied for: '%s'",r.asCStr());
            throw ReplyDataException("invalid response from redis");
        }
    } else if(isArgArray(r)) { //we have array reply. return sum of all elements");
        for(size_t i=0; i < r.size(); i++)
            ret+=Reply2Int(r[i]);
    } else if(isArgStruct(r) && r.hasMember("error")) {
        ERROR("reply error: '%s'",r["error"].asCStr());
        throw ReplyDataException("unexpected reply");
    } else {
        throw ReplyTypeException("reply type is not desired",r.getType());
    }

    return ret;
}

InvalidateResources::InvalidateResources(ResourceRedisConnection* conn)
  : ResourceSequenceBase(conn, REDIS_REPLY_INITIAL_SEQ),
    state(INITIAL),
    initial(true)
{}

void InvalidateResources::cleanup()
{
    commands_count = 0;
    state = INITIAL;
    initial = false;
}

bool InvalidateResources::perform()
{
    if(state == INITIAL) {
        if(!SEQ_REDIS_WRITE("KEYS r:*:*")) {
            on_error("error on post redis request: state INITIAL");
            return false;
        }
        state = GET_KEYS;
    } else {
        on_error("perform called in the not INITIAL state: %d", state);
        return false;
    }

    return true;
}

bool InvalidateResources::processRedisReply(RedisReplyEvent &reply)
{
    if(state == INITIAL) {
        on_error("redis reply in the INITIAL state");
    } else if(state == GET_KEYS) {
        if(reply.result != RedisReplyEvent::SuccessReply) {
            on_error("reply error in request: state GET_KEYS, result_type %d", reply.result);
        } else if(isArgUndef(reply.data)){
            INFO("empty database. skip resources initialization");
            state = FINISH;
        } else if(isArgArray(reply.data)) {
            SEQ_REDIS_WRITE("MULTI");
            for(size_t i = 0;i < reply.data.size(); i++) {
                SEQ_REDIS_WRITE("HSET %s %d 0",
                                reply.data[i].asCStr(), AmConfig.node_id);
            }
            SEQ_REDIS_WRITE("EXEC");
            state = CLEAN_RES;
            commands_count = 2 + reply.data.size();
        } else {
            on_error("unexpected type of the result data: state GET_KEYS");
        }
    } else if(state == CLEAN_RES) {
        commands_count--;
        if((commands_count && reply.result != RedisReplyEvent::StatusReply) ||
            (!commands_count && reply.result != RedisReplyEvent::SuccessReply))
        {
            on_error("reply error in the request: state CLEAN_RES, commands_count %d, result_type %d",
                     commands_count, reply.result);
        } else if(!commands_count && reply.result == RedisReplyEvent::SuccessReply) {
            state = FINISH;
        }
    }

    //always persistent
    return false;
}

void InvalidateResources::on_error(const char* error, ...)
{
    static char err[1024];
    va_list argptr;
    va_start (argptr, error);
    vsprintf(err, error, argptr);
    ERROR("failed to init resources(%s). stop", err);
    va_end(argptr);
    if(initial) kill(getpid(),SIGTERM);
}

OperationResources::OperationResources(ResourceRedisConnection* conn, const ResourceOperationList& rl)
  : ResourceSequenceBase(conn, REDIS_REPLY_OP_SEQ),
    state(INITIAL),
    res_list(rl),
    iserror(false)
{}

bool OperationResources::perform()
{
    if(state == INITIAL) {
        for(auto res = res_list.begin(); res != res_list.end();) {
            //filter out inactive and taken resources
            if((res->op == ResourceOperation::RES_GET && !res->active) ||
               (res->op == ResourceOperation::RES_PUT && !res->taken) ||
               res->op == ResourceOperation::RES_NONE) {
                    res = res_list.erase(res);
            } else res++;
        }

        if(res_list.empty()) {
            //ask to be deleted by caller
            return false;
        }

        if(!SEQ_REDIS_WRITE("MULTI")) {
            on_error("failed to post redis request");
            return false;
        }
        state = MULTI_START;
    } else {
        on_error("perform called in the not INITIAL state: %d", state);
        return false;
    }

    return true;
}

bool OperationResources::processRedisReply(RedisReplyEvent &reply)
{
    if(state == INITIAL) {
        on_error("redis reply in the INITIAL state");
    } else if(state == MULTI_START) {
        for(auto& res : res_list) {
            if(res.op == ResourceOperation::RES_GET && res.active)
                SEQ_REDIS_WRITE("HINCRBY %s %d %d", get_key(res).c_str(), AmConfig.node_id, res.takes);
            else if(res.op == ResourceOperation::RES_PUT && res.taken)
                SEQ_REDIS_WRITE("HINCRBY %s %d -%d", get_key(res).c_str(), AmConfig.node_id, res.takes);
            commands_count++;
        }
        SEQ_REDIS_WRITE("EXEC");
        commands_count++;
        state = OP_RES;
    } else if(state == OP_RES) {
        commands_count--;
        if((commands_count && reply.result != RedisReplyEvent::StatusReply) ||
           (!commands_count && reply.result != RedisReplyEvent::SuccessReply))
        {
            if(!iserror) on_error("reply error in the request: state OP_RES, commands_count %d, result_type %d",\
                                  commands_count, reply.result);
        }
        if(!commands_count) {
            state = FINISH;
        }
    }

    return state == FINISH;
}

void OperationResources::on_error(const char* error, ...)
{
    static char err[1024];
    va_list argptr;
    va_start (argptr, error);
    vsprintf(err, error, argptr);
    ERROR("failed to do operation on resources(%s). stop", err);
    va_end(argptr);
    iserror = true;
}

GetAllResources::GetAllResources(ResourceRedisConnection* conn,
                                 const JsonRpcRequestEvent& event,
                                 int type, int id)
  : ResourceSequenceBase(conn, REDIS_REPLY_GET_ALL_KEYS_SEQ),
    req(event),
    iserror(false),
    unit_test(false),
    callback(0)
{
    if(type != ANY_VALUE && id != ANY_VALUE) {
        Resource r;
        r.type = type;
        r.id = id;
        res_key = get_key(r);
        state = GET_SINGLE_KEY;
    } else {
        #define int2key(v) (v==ANY_VALUE) ? "*" : int2str(v)
        res_key = "r:";
        res_key += int2key(type);
        res_key.append(":");
        res_key.append(int2key(id));
        #undef int2key
        state = INITIAL;
    }
}

GetAllResources::GetAllResources(ResourceRedisConnection* conn,
                                 cb_func* cb, int type, int id)
: GetAllResources(conn, JsonRpcRequestEvent(""), type, id)
{
    callback = cb;
    unit_test = true;
}

bool GetAllResources::perform()
{
    if(state == INITIAL) {
        if(!SEQ_REDIS_READ("KEYS %s",res_key.c_str())) {
            on_error(500, "failed to post redis request");
            return false;
        }
        state = GET_KEYS;
    } else if(state == GET_SINGLE_KEY) {
        keys.push_back(res_key);
        if(!SEQ_REDIS_READ("HGETALL %s", res_key.c_str())) {
            on_error(500, "failed to post redis request");
            return false;
        }
        commands_count++;
        state = GET_DATA;
    } else {
        on_error(500, "perform called in the not INITIAL or GET_SINGLE_KEY state: %d", state);
        return false;
    }

    return true;
}

bool GetAllResources::processRedisReply(RedisReplyEvent &reply)
{
    if(state == INITIAL) {
        on_error(500, "redis reply in the INITIAL state");
    } else if(state == GET_KEYS) {
        if(reply.result != RedisReplyEvent::SuccessReply){
            on_error(500, "no reply from storage");
            state = FINISH;
        } else if(isArgUndef(reply.data) ||(
            isArgArray(reply.data) && !reply.data.size())){
            on_error(404, "no resources matched");
            state = FINISH;
        } else if(isArgArray(reply.data)) {
            for(size_t i = 0;i < reply.data.size(); i++) {
                keys.push_back(reply.data[i].asCStr());
                SEQ_REDIS_READ("HGETALL %s", keys.back().c_str());
            }
            state = GET_DATA;
            commands_count = reply.data.size();
        } else {
            on_error(500, "unexpected type of the result data");
            state = FINISH;
        }
    } else if(state == GET_DATA) {
        commands_count--;
        if(reply.result != RedisReplyEvent::SuccessReply){
            on_error(500, "reply error in the request");
        } else if(isArgUndef(reply.data)){
            on_error(500, "undesired reply from the storage");
        } else if(isArgArray(reply.data)){
            string key = keys[keys.size() - commands_count - 1];
            result.push(key,AmArg());
            AmArg &q = result[key];
            for(size_t j = 0; j < reply.data.size(); j+=2){
                try {
                    q.push(int2str((unsigned int)Reply2Int(reply.data[j])),	//node_id
                            AmArg(Reply2Int(reply.data[j+1])));				//value*/
                } catch(...) {
                    on_error(500, "can't parse response");
                }
            }
        }
        if(!commands_count) {
            if(!iserror) {
                if(unit_test) {
                    if(callback) callback(false, result);
                } else {
                    postJsonRpcReply(req, result);
                }
            }
            state = FINISH;
        }
    }

    return state == FINISH;
}

void GetAllResources::on_error(int code, const char* error, ...)
{
    static char err[1024];

    if(iserror) return;
    iserror = true;

    va_list argptr;
    va_start (argptr, error);
    vsprintf(err, error, argptr);

    DBG("error %s", err);

    AmArg ret;
    ret["message"] = err;
    ret["code"] = code;
    if(unit_test) {
        if(callback) callback(true, result);
    } else {
        postJsonRpcReply(req, ret, true);
    }
}

CheckResources::CheckResources(ResourceRedisConnection* conn, const ResourceList& rl)
  : ResourceSequenceBase(conn, REDIS_REPLY_CHECK_SEQ),
    state(INITIAL),
    resources(rl),
    finished(false),
    iserror(false)
{}

bool CheckResources::perform()
{
    if(state == INITIAL) {
        for(auto& res : resources) {
            commands_count++;
            SEQ_REDIS_READ("HVALS %s", get_key(res).c_str());
        }
        state = GET_VALS;
    } else {
        on_error("perform called in the not INITIAL state: %d", state);
        return false;
    }

    return true;
}

bool CheckResources::processRedisReply(RedisReplyEvent &reply)
{
    if(state == INITIAL) {
        on_error("redis reply in the INITIAL state");
    } else if(state == GET_VALS) {
        commands_count--;
        if(reply.result != RedisReplyEvent::SuccessReply) {
            on_error("reply error in the request");
        } else {
            try {
                long int now = Reply2Int(reply.data);
                result.push(now);
            } catch(...) {
                on_error("failed to parse response");
            }
        }
    }

    if(!commands_count) {
        finished.set(true);
        state = FINISH;
    }

    //do not delete on finish without errors because result is used in ResourceRedisConnection::get
    return state==FINISH && iserror;
}

void CheckResources::on_error(const char* error, ...)
{
    static char err[1024];

    va_list argptr;
    va_start (argptr, error);
    vsprintf(err, error, argptr);
    va_end(argptr);

    ERROR("failed to check resources(%s)", err);

    iserror = true;
    finished.set(true);
}

bool CheckResources::wait_finish(int timeout)
{
    bool ret = finished.wait_for_to(timeout);
    if(!ret) iserror = true;
    return ret;
}
