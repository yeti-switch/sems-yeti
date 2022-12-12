#include "ResourceRedisConnection.h"
#include <sstream>
#include <algorithm>
#include "ResourceControl.h"

using namespace std; 

static string get_key(Resource &r){
	ostringstream ss;
	ss << "r:" << r.type << ":" << r.id;
	return ss.str();
}

void InvalidateResources::runSequence(RedisReplyEvent* event)
{
    if(!event && state != INITIAL) {
        on_error((char*)"connection[%p] error: state of the initial sequence is incorrect", conn);
    } else if(state == INITIAL) {
        if(!postRedisRequestFmt(conn->get_write_conn(), conn->get_queue_name(), conn->get_queue_name(), false, this, REDIS_REPLY_INITIAL_SEQ, "KEYS r:*"))
            on_error((char*)"error on post redis request: state INITIAL");
        state = GET_KEYS;
    } else if(state == GET_KEYS) {
        if(event->result != RedisReplyEvent::SuccessReply){
            on_error((char*)"reply error in request: state GET_KEYS, result_type %d", event->result);
        } else if(isArgUndef(event->data)){
            INFO("empty database. skip resources initialization");
            state = FINISH;
        } else if(isArgArray(event->data)){
            postRedisRequestFmt(conn->get_write_conn(), conn->get_queue_name(), conn->get_queue_name(), false, this, REDIS_REPLY_INITIAL_SEQ, "MULTI");
            for(size_t i = 0;i < event->data.size(); i++) {
                postRedisRequestFmt(conn->get_write_conn(), conn->get_queue_name(), conn->get_queue_name(), false, this, REDIS_REPLY_INITIAL_SEQ, "HSET %s %d 0", event->data[i].asCStr(), AmConfig.node_id);
            }
            postRedisRequestFmt(conn->get_write_conn(), conn->get_queue_name(), conn->get_queue_name(), false, this, REDIS_REPLY_INITIAL_SEQ, "EXEC");
            state = CLEAN_RES;
            command_size = 2 + event->data.size();
        } else {
            on_error((char*)"unexpected type of the result data: state GET_KEYS");
        }
    } else if(state == CLEAN_RES) {
        command_size--;
        if((command_size && event->result != RedisReplyEvent::StatusReply) ||
            (!command_size && event->result != RedisReplyEvent::SuccessReply)){
            on_error((char*)"reply error in the request: state CLEAN_RES, command_size %d, result_type %d", command_size, event->result);
        } else if(!command_size && event->result == RedisReplyEvent::SuccessReply) {
            state = FINISH;
        }
    }
}

void InvalidateResources::on_error(char* error, ...)
{
    static char err[1024];
    va_list argptr;
    va_start (argptr, error);
    vsprintf(err, error, argptr);
    ERROR("failed to init resources(%s). stop", err);
    va_end(argptr);
    if(initial) kill(getpid(),SIGTERM);
}

void OperationResources::runSequence(RedisReplyEvent* event)
{
    if(!event && state != INITIAL) {
        on_error((char*)"connection[%p] error: state of the put sequence is incorrect", conn);
    } else if(state == INITIAL) {
        postRedisRequestFmt(conn->get_write_conn(), conn->get_queue_name(), conn->get_queue_name(), false, this, REDIS_REPLY_OP_SEQ, "MULTI");
        state = MULTI_START;
    } else if(state == MULTI_START) {
        for(auto& res : res_list) {
            int node_id = AmConfig.node_id;
            if(res.op == ResourceOperation::RES_GET && res.active)
                postRedisRequestFmt(conn->get_write_conn(), conn->get_queue_name(), conn->get_queue_name(), false, this, REDIS_REPLY_OP_SEQ, "HINCRBY %s %d %d", get_key(res).c_str(), node_id, res.takes);
            else if(res.op == ResourceOperation::RES_PUT && res.taken)
                postRedisRequestFmt(conn->get_write_conn(), conn->get_queue_name(), conn->get_queue_name(), false, this, REDIS_REPLY_OP_SEQ, "HINCRBY %s %d -%d", get_key(res).c_str(), node_id, res.takes);
            command_size++;
        }
        postRedisRequestFmt(conn->get_write_conn(), conn->get_queue_name(), conn->get_queue_name(), false, this, REDIS_REPLY_OP_SEQ, "EXEC");
        command_size++;
        state = OP_RES;
    } else if(state == OP_RES) {
        command_size--;
        if((command_size && event->result != RedisReplyEvent::StatusReply) ||
           (!command_size && event->result != RedisReplyEvent::SuccessReply)){
                if(!iserror) on_error((char*)"reply error in the request: state OP_RES, command_size %d, result_type %d", command_size, event->result);
        } 
        if(!command_size) {
            state = FINISH;
        }
    }
}

void OperationResources::on_error(char* error, ...)
{
    static char err[1024];
    va_list argptr;
    va_start (argptr, error);
    vsprintf(err, error, argptr);
    ERROR("failed to do operation on resources(%s). stop", err);
    va_end(argptr);
    iserror = true;
}

static bool isArgNumber(const AmArg& arg) {
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
            ERROR("Reply2Int: conversion falied for: '%s'",s);
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

void GetAllResources::cleanup(int type, int id)
{
    command_size = 0;
    if(type != ANY_VALUE && id != ANY_VALUE) {
        Resource r;
        r.type = type;
        r.id = id;
        //prepare request
        res_key = get_key(r);
        state = GET_KEYS;
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

void GetAllResources::runSequence(RedisReplyEvent* event)
{
    if(state == INITIAL) {
        postRedisRequestFmt(conn->get_read_conn(), conn->get_queue_name(), conn->get_queue_name(), false, this, REDIS_REPLY_GET_ALL_KEYS_SEQ, "KEYS %s",res_key.c_str());
        state = GET_KEYS;
    } else if(state == GET_KEYS && event) {
        if(event->result != RedisReplyEvent::SuccessReply){
            on_error(500, (char*)"no reply from storage");
            state = FINISH;
        } else if(isArgUndef(event->data) ||(
            isArgArray(event->data) && !event->data.size())){
            on_error(404, (char*)"no resources matched");
            state = FINISH;
        } else if(isArgArray(event->data)){
            for(size_t i = 0;i < event->data.size(); i++) {
                keys.push_back(event->data[i].asCStr());
                postRedisRequestFmt(conn->get_read_conn(), conn->get_queue_name(), conn->get_queue_name(), false, this, REDIS_REPLY_GET_ALL_KEYS_SEQ, "HGETALL %s", keys.back().c_str());
            }
            state = GET_ALL;
            command_size = event->data.size();
        } else {
            on_error(500, (char*)"unexpected type of the result data");
            state = FINISH;
        }
    } else if(state == GET_KEYS && !event) {
        keys.push_back(res_key);
        postRedisRequestFmt(conn->get_read_conn(), conn->get_queue_name(), conn->get_queue_name(), false, this, REDIS_REPLY_GET_ALL_KEYS_SEQ, "HGETALL %s", res_key.c_str());
        command_size++;
        state = GET_ALL;
    } else if(state == GET_ALL) {
        command_size--;
        if(event->result != RedisReplyEvent::SuccessReply){
            on_error(500, (char*)"reply error in the request");
        } else if(isArgUndef(event->data)){
            on_error(500, (char*)"undesired reply from the storage");
        } else if(isArgArray(event->data)){
            string key = keys[keys.size() - command_size - 1];
            result.push(key,AmArg());
            AmArg &q = result[key];
            for(size_t j = 0; j < event->data.size(); j+=2){
                try {
                    q.push(int2str((unsigned int)Reply2Int(event->data[j])),	//node_id
                            AmArg(Reply2Int(event->data[j+1])));				//value*/
                } catch(...){
                    on_error(500, (char*)"can't parse response");
                }
            }
        }
        if(!command_size) {
            if(!iserror) postJsonRpcReply(req, result);
            state = FINISH;
        }
    }
}

void GetAllResources::on_error(int code, char* error, ...)
{
    if(iserror) return;
    iserror = true;
    static char err[1024];
    va_list argptr;
    va_start (argptr, error);
    vsprintf(err, error, argptr);
    DBG("error %s", err);
    AmArg ret;
    ret["message"] = err;
    ret["code"] = code;
    postJsonRpcReply(req, ret, true);
}

void CheckResources::runSequence(RedisReplyEvent* event)
{
    if(state == INITIAL) {
        for(auto& res : resources) {
            command_size++;
            postRedisRequestFmt(conn->get_read_conn(), conn->get_queue_name(), conn->get_queue_name(), false, this, REDIS_REPLY_CHECK_SEQ, "HVALS %s", get_key(res).c_str());
        }
        state = GET_VALS;
    } else if(state == GET_VALS) {
        command_size--;
        if(event->result != RedisReplyEvent::SuccessReply){
            on_error((char*)"reply error in the request");
        } else {
            try {
                long int now = Reply2Int(event->data);
                result.push(now);
            } catch(...){
                on_error((char*)"failed to parse response");
            }
        }
    }
    if(!command_size) {
        finished.set(true);
        state = FINISH;
    }
}

void CheckResources::on_error(char* error, ...)
{
    static char err[1024];
    va_list argptr;
    va_start (argptr, error);
    vsprintf(err, error, argptr);
    ERROR("failed to check resources(%s)", err);
    va_end(argptr);
    iserror = true;
    finished.set(true);
}

bool CheckResources::wait_finish(int timeout)
{
    bool ret = finished.wait_for_to(timeout);
    if(!ret) iserror = true;
    return ret;
}

