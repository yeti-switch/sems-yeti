#pragma once

#include <AmThread.h>
#include <AmEventFdQueue.h>
#include <AmSessionContainer.h>
#include <AmArg.h>

#include <hiredis/hiredis.h>
#include <hiredis/async.h>

#include <memory>
#include <cmath>

#define REDIS_REQUEST_EVENT_ID 0
#define REDIS_REPLY_EVENT_ID 1

template <typename T>
inline unsigned int len_in_chars(T s)
{
    if(s == 0) return 1;
    return static_cast<unsigned int>(log10(s) + 1);
}

struct RedisScript
  : AmObject
{
    string name;
    string queue_name;
    string hash;

    RedisScript(const string &name, const string &queue_name)
      : name(name),
        queue_name(queue_name)
    {}

    int load(const string &script_path,  int reply_type_id);
};

struct RedisRequestEvent
  : public AmEvent
{
    std::unique_ptr<char> cmd;
    size_t cmd_size;

    bool cmd_allocated_by_redis;
    bool persistent_ctx;

    string src_id;

    //onwership will be transferred to RedisReplyEvent via redisReplyCtx
    std::unique_ptr<AmObject> user_data;
    int user_type_id;

    RedisRequestEvent(const string &src_id,
                      char *cmd, size_t cmd_size,
                      bool cmd_allocated_by_redis,
                      bool persistent_ctx = false,
                      AmObject *user_data = nullptr, int user_type_id = 0)
      : AmEvent(REDIS_REQUEST_EVENT_ID),
        cmd(cmd), cmd_size(cmd_size),
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

class RedisConnection;

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

class RedisConnection
  : public AmThread,
    public AmEventFdQueue,
    public AmEventHandler
{
  private:
    int epoll_fd;
    int redis_fd;

    const char *name;
    string host;
    int port;

    redisAsyncContext *async_context;
    int mask;

    AmEventFd stop_event;
    AmCondition<bool> stopped;

    AmTimerFd reconnect_timer;
    bool connected;

    std::list<RedisReplyCtx *> persistent_reply_contexts;

    int init_async_context();

    void on_reconnect();

  protected:
    string queue_name;

    virtual void on_connect() {}

  public:

    RedisConnection(const char *name, const string &queue_name);
    virtual ~RedisConnection();
    int init(const string &host, int port);
    void run();
    void on_stop();

    virtual void process(AmEvent* ev);
    void process_request_event(RedisRequestEvent &event);
    virtual void process_reply_event(RedisReplyEvent &event) = 0;

    redisAsyncContext *getRedisCtx() { return async_context; }

    redisConnectCallback connectCallback;
    redisDisconnectCallback disconnectCallback;

    void on_redis_reply(RedisReplyCtx &ctx, redisReply *reply);

    int add_event(int flag);
    int del_event(int flag);
    void cleanup();
};

static inline bool postRedisRequest(const string &queue_name, const string &src_tag,
                                    char *cmd, size_t cmd_size,
                                    bool cmd_allocated_by_redis,
                                    bool persistent_ctx = false,
                                    AmObject *user_data = nullptr, int user_type_id = 0)
{
    return AmSessionContainer::instance()->postEvent(
        queue_name,
        new RedisRequestEvent(src_tag,
                              cmd,cmd_size,
                              cmd_allocated_by_redis,
                              persistent_ctx,
                              user_data,user_type_id));
}

static inline bool postRedisRequestFmt(const string &queue_name,
                                       const string &src_tag,
                                       bool persistent_ctx,
                                       const char *fmt...)
{
    char *cmd;
    int ret;

    va_list args;
    va_start(args, fmt);
    ret = redisvFormatCommand(&cmd, fmt, args);
    va_end(args);
    if(ret <= 0)
        return false;
    return postRedisRequest(queue_name, src_tag,
                            cmd, static_cast<size_t>(ret),
                            true, persistent_ctx);
}

static inline bool postRedisRequestFmt(const string &queue_name,
                                       const string &src_tag,
                                       bool persistent_ctx,
                                       AmObject *user_data, int user_type_id,
                                       const char *fmt...)
{
    char *cmd;
    int ret;

    va_list args;
    va_start(args, fmt);
    ret = redisvFormatCommand(&cmd, fmt, args);
    va_end(args);

    if(ret <= 0)
        return false;

    return postRedisRequest(queue_name, src_tag,
                            cmd, static_cast<size_t>(ret),
                            true, persistent_ctx,
                            user_data,user_type_id);
}
