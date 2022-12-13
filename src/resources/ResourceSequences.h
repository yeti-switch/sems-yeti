#pragma once

#include "Resource.h"
#include "../RedisConnectionPool.h"
#include <ampi/JsonRPCEvents.h>

class ResourceRedisConnection;

class ResourceSequenceBase
  : public AmObject
{
  public:
    enum seq_id {
        REDIS_REPLY_INITIAL_SEQ = 1,
        REDIS_REPLY_OP_SEQ,
        REDIS_REPLY_GET_ALL_KEYS_SEQ,
        REDIS_REPLY_CHECK_SEQ
    };

  protected:
    ResourceRedisConnection* conn;
    int user_type_id;
    int commands_count;

  public:
    ResourceSequenceBase(ResourceRedisConnection* conn, int user_type_id)
      : conn(conn),
        user_type_id(user_type_id),
        commands_count(0)
    { }
    virtual ~ResourceSequenceBase() { }

    //run sequence. returns false on errors
    virtual bool perform() = 0;

    //process redis reply, generate new queries, change internal FSM state, save result
    //return: true if finished and can be destroyed
    virtual bool processRedisReply(RedisReplyEvent& reply) = 0;
};

class ResourceOperation
  : public Resource
{
  public:
    enum Operation {
        RES_PUT,
        RES_GET
    } op;

    ResourceOperation(Operation op_, const Resource& res)
      : Resource(res),
        op(op_)
    {}
};

typedef ResList<ResourceOperation> ResourceOperationList;

class InvalidateResources
  : public ResourceSequenceBase
{
    enum {
        INITIAL = 0,
        GET_KEYS,
        CLEAN_RES,
        FINISH
    } state;
    bool initial;

  public:
    InvalidateResources(ResourceRedisConnection* conn);

    bool perform() override;
    bool processRedisReply(RedisReplyEvent &reply) override;
    void cleanup();
    void on_error(char* error, ...);

    bool is_finish() { return state == FINISH; }
    bool is_initial() { return initial; }
    int get_state() { return state; }
};

class OperationResources
  : public ResourceSequenceBase
{
    enum {
        INITIAL = 0,
        MULTI_START,
        OP_RES,
        FINISH
    } state;
    ResourceOperationList res_list;
    bool iserror;

  public:
    OperationResources(ResourceRedisConnection* conn, const ResourceOperationList& rl);

    bool perform() override;
    bool processRedisReply(RedisReplyEvent &reply) override;
    void on_error(char* error, ...);

    bool is_finish() { return state == FINISH; }
    bool is_error() { return iserror; }
};

class GetAllResources
  : public ResourceSequenceBase
{
    JsonRpcRequestEvent req;

    string res_key;
    enum {
        INITIAL = 0,
        GET_KEYS,
        GET_SINGLE_KEY,
        GET_DATA,
        FINISH
    } state;
    vector<string> keys;
    AmArg result;
    bool iserror;

  public:
    GetAllResources(ResourceRedisConnection* conn,
                    const JsonRpcRequestEvent& event,
                    int type, int id);

    bool perform() override;
    bool processRedisReply(RedisReplyEvent &reply) override;
    void on_error(int code, char* error, ...);

    bool is_finish() { return state == FINISH; }
    bool is_error() { return iserror; }
};

class CheckResources
  : public ResourceSequenceBase
{
    enum {
        INITIAL = 0,
        GET_VALS,
        FINISH
    } state;
    ResourceList resources;
    AmCondition<bool> finished;
    bool iserror;
    AmArg result;

  public:
    CheckResources(ResourceRedisConnection* conn, const ResourceList& rl);

    bool perform() override;
    bool processRedisReply(RedisReplyEvent &reply) override;
    void on_error(char* error, ...);
    bool wait_finish(int timeout);

    bool is_finish() { return state == FINISH; }
    bool is_error() { return iserror; }
    AmArg get_result() { return result; }
};
