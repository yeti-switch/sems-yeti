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
    void on_error(const char* error, ...);

    bool is_finish() { return state == FINISH; }
    bool is_initial() { return initial; }
    void clear_initial() { initial = false; }
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
    void on_error(const char* error, ...);

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

    //for unit tests
    bool unit_test;
    typedef void cb_func(bool is_error, const AmArg& result);
    cb_func *callback;
  public:
    GetAllResources(ResourceRedisConnection* conn,
                    const JsonRpcRequestEvent& event,
                    int type, int id);
    //for unit tests
    GetAllResources(ResourceRedisConnection* conn,
                    cb_func* cb,
                    int type, int id);

    bool perform() override;
    bool processRedisReply(RedisReplyEvent &reply) override;
    void on_error(int code, const char* error, ...);

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
    void on_error(const char* error, ...);
    bool wait_finish(int timeout);

    bool is_finish() { return state == FINISH; }
    bool is_error() { return iserror; }
    AmArg get_result() { return result; }
};
