#ifndef RESOURCE_SEQUENCES_H
#define RESOURCE_SEQUENCES_H

#include "Resource.h"
#include "../RedisConnectionPool.h"
#include <ampi/JsonRPCEvents.h>

#define REDIS_REPLY_INITIAL_SEQ 1
#define REDIS_REPLY_OP_SEQ 2
#define REDIS_REPLY_GET_ALL_KEYS_SEQ 3
#define REDIS_REPLY_CHECK_SEQ 4

class ResourceRedisConnection;

class JsonRpcRequest : public AmObject, public JsonRpcRequestEvent
{
public:
    JsonRpcRequest(const JsonRpcRequestEvent& event)
    : JsonRpcRequestEvent(event){}
};

class InvalidateResources : public AmObject
{
    ResourceRedisConnection* conn;
    enum {
        INITIAL = 0,
        GET_KEYS,
        CLEAN_RES,
        FINISH
    } state;
    int command_size;
    bool initial;
public:
    InvalidateResources(ResourceRedisConnection* conn)
    : conn(conn), state(INITIAL), command_size(0), initial(false){}

    void runSequence(RedisReplyEvent* event);
    void cleanup(bool init) {
        state = INITIAL;
        command_size = 0;
        initial = init;
    }
    bool is_finish() { return state == FINISH; }
    bool is_initial() { return initial; }
    void on_error(char* error, ...);
    int get_state() { return state; }
};

class ResourceOperation : public Resource
{
public:
    enum Operation {
        RES_PUT,
        RES_GET
    } op;
    ResourceOperation(Operation op_, const Resource& res)
    : Resource(res), op(op_){}
};

typedef ResList<ResourceOperation> ResourceOperationList;

class OperationResources : public AmObject
{
    ResourceRedisConnection* conn;
    enum {
        INITIAL = 0,
        MULTI_START,
        OP_RES,
        FINISH
    } state;
    int command_size;
    ResourceOperationList res_list;
    bool iserror;
public:
    OperationResources(ResourceRedisConnection* conn)
    : conn(conn), state(INITIAL), command_size(0), iserror(false){}

    void runSequence(RedisReplyEvent* event);
    void cleanup(const ResourceOperationList& rl) {
        state = INITIAL;
        command_size = 0;
        res_list = rl;
    }
    bool is_finish() { return state == FINISH; }
    void on_error(char* error, ...);
    bool is_error() { return iserror; }
};

class GetAllResources : public AmObject
{
    ResourceRedisConnection* conn;
    JsonRpcRequest req;

    string res_key;
    enum {
        INITIAL = 0,
        GET_KEYS,
        GET_ALL,
        FINISH
    } state;
    int command_size;
    vector<string> keys;
    AmArg result;
    bool iserror;
public:
    GetAllResources(ResourceRedisConnection* conn, const JsonRpcRequestEvent& event)
    : conn(conn), req(event), state(INITIAL), command_size(0), iserror(false){}

    void runSequence(RedisReplyEvent* event);
    void cleanup(int type, int id);
    bool is_finish() { return state == FINISH; }
    void on_error(int code, char* error, ...);
    bool is_error() { return iserror; }
};

class CheckResources : public AmObject
{
    ResourceRedisConnection* conn;
    enum {
        INITIAL = 0,
        GET_VALS,
        FINISH
    } state;
    int command_size;
    ResourceList resources;
    AmCondition<bool> finished;
    bool iserror;
    AmArg result;
public:
    CheckResources(ResourceRedisConnection* conn)
    : conn(conn), state(INITIAL), command_size(0), iserror(false){}

    void runSequence(RedisReplyEvent* event);
    void cleanup(const ResourceList& rl) {
        resources = rl;
    }
    bool wait_finish(int timeout);
    bool is_finish() { return state == FINISH; }
    void on_error(char* error, ...);
    bool is_error() { return iserror; }
    AmArg get_result() { return result; }
};

#endif/*RESOURCE_SEQUENCES_H*/
