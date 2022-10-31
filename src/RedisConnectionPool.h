#ifndef REDIS_CONNECTION_POOL_H
#define REDIS_CONNECTION_POOL_H

#include <AmArg.h>
#include <AmEventFdQueue.h>
#include <AmSessionContainer.h>

#include "RedisInstance.h"

#define REDIS_REQUEST_EVENT_ID 0
#define REDIS_REPLY_EVENT_ID 1

class RedisConnection;

struct RedisRequestEvent
  : public AmEvent
{
    RedisConnection *c;
    std::unique_ptr<char> cmd;
    size_t cmd_size;

    bool cmd_allocated_by_redis;
    bool persistent_ctx;

    string src_id;

    //onwership will be transferred to RedisReplyEvent via redisReplyCtx
    std::unique_ptr<AmObject> user_data;
    int user_type_id;

    RedisConnection* getConnection() { return c; }

    RedisRequestEvent(RedisConnection *c,
                      const string &src_id,
                      char *cmd, size_t cmd_size,
                      bool cmd_allocated_by_redis,
                      bool persistent_ctx = false,
                      AmObject *user_data = nullptr, int user_type_id = 0)
      : AmEvent(REDIS_REQUEST_EVENT_ID),
        c(c), cmd(cmd), cmd_size(cmd_size),
        cmd_allocated_by_redis(cmd_allocated_by_redis),
        persistent_ctx(persistent_ctx),
        src_id(src_id),
        user_data(user_data),
        user_type_id(user_type_id)
    {}

    RedisRequestEvent(const RedisRequestEvent& rhs) = delete;
    RedisRequestEvent(RedisRequestEvent&& rhs) = default;

    virtual ~RedisRequestEvent();
};

struct RedisReplyCtx {
    RedisConnection *c;

    bool persistent_ctx;
    string src_id;
    std::unique_ptr<AmObject> user_data;
    int user_type_id;

    RedisReplyCtx(RedisConnection *c, RedisRequestEvent &r)
      : c(c),
        persistent_ctx(r.persistent_ctx),
        src_id(std::move(r.src_id)),
        user_data(std::move(r.user_data)),
        user_type_id(r.user_type_id)
    {}
    //~RedisReplyCtx() { CLASS_DBG("~RedisReplyCtx()"); }
};

struct RedisReplyEvent
  : public AmEvent
{
    enum result_type {
        SuccessReply = 0,
        ErrorReply,
        StatusReply,
        IOError,
        NotConnected,
        FailedToSend
    } result;

    AmArg data;
    std::unique_ptr<AmObject> user_data;
    int user_type_id;

    RedisReplyEvent(redisReply *reply, RedisReplyCtx &ctx);
    RedisReplyEvent(result_type result, RedisRequestEvent &request);
    virtual ~RedisReplyEvent();
};

class RedisConnectionPool
  : public AmThread,
    public AmEventFdQueue,
    public AmEventHandler
{
    int epoll_fd;
    const char *name;
    string queue_name;

    AmEventFd stop_event;
    AmCondition<bool> stopped;

    AmTimerFd reconnect_timer;

    std::list<RedisReplyCtx *> persistent_reply_contexts;
    std::list<RedisConnection*> connections;
protected:
    int init();
public:
    RedisConnectionPool(const char *name, const string &queue_name);
    virtual ~RedisConnectionPool();
    void run() override;
    void on_stop() override;

    void on_reconnect();
    void process(AmEvent* ev) override;
    void process_request_event(RedisRequestEvent &event);
    void process_stop_event();
    RedisConnection* addConnection(const string &_host, int _port);
    string get_queue_name() { return queue_name; }

    virtual void process_reply_event(RedisReplyEvent& event) = 0;
    virtual void on_connect(RedisConnection* c){}
    virtual void on_disconnect(RedisConnection* c){}
};

static inline bool postRedisRequest(RedisConnection* c, const string &queue_name, const string &src_tag,
                                    char *cmd, size_t cmd_size,
                                    bool cmd_allocated_by_redis,
                                    bool persistent_ctx = false,
                                    AmObject *user_data = nullptr, int user_type_id = 0)
{
    return AmSessionContainer::instance()->postEvent(
        queue_name,
        new RedisRequestEvent(c, src_tag,
                              cmd,cmd_size,
                              cmd_allocated_by_redis,
                              persistent_ctx,
                              user_data,user_type_id));
}

static inline bool postRedisRequestFmt(RedisConnection* c, const string &queue_name,
                                       const string &src_tag,
                                       bool persistent_ctx,
                                       const char *fmt...)
{
    char *cmd;
    int ret;

    va_list args;
    va_start(args, fmt);
    ret = redis::redisvFormatCommand(&cmd, fmt, args);
    va_end(args);
    if(ret <= 0)
        return false;
    return postRedisRequest(c, queue_name, src_tag,
                            cmd, static_cast<size_t>(ret),
                            true, persistent_ctx);
}

static inline bool postRedisRequestFmt(RedisConnection* c, const string &queue_name,
                                       const string &src_tag,
                                       bool persistent_ctx,
                                       AmObject *user_data, int user_type_id,
                                       const char *fmt...)
{
    char *cmd;
    int ret;

    va_list args;
    va_start(args, fmt);
    ret = redis::redisvFormatCommand(&cmd, fmt, args);
    va_end(args);

    if(ret <= 0)
        return false;

    return postRedisRequest(c, queue_name, src_tag,
                            cmd, static_cast<size_t>(ret),
                            true, persistent_ctx,
                            user_data,user_type_id);
}

#endif/*REDIS_CONNECTION_POOL_H*/
