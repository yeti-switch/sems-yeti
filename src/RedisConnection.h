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

static string ASYNC_REDIS_QUEUE("async_redis");

struct RedisScript
  : AmObject
{
    string name;
    string hash;

    RedisScript(const string &name)
      : name(name)
    {}

    int load(const string &script_path);
};

extern RedisScript yeti_register;
extern RedisScript yeti_aor_lookup;
extern RedisScript yeti_rpc_aor_lookup;

template <typename T>
inline unsigned int len_in_chars(T s)
{
    if(s == 0) return 1;
    return static_cast<unsigned int>(log10(s) + 1);
}

struct RedisRequestEvent
  : public AmEvent
{
    std::unique_ptr<char> cmd;
    size_t cmd_size;

    string src_id;

    //onwership will be transferred to RedisReplyEvent via redisReplyCtx
    std::unique_ptr<AmObject> user_data;
    int user_type_id;

    RedisRequestEvent(const string &src_id, char *cmd, size_t cmd_size,
                      AmObject *user_data = nullptr, int user_type_id = 0)
      : AmEvent(REDIS_REQUEST_EVENT_ID),
        cmd(cmd), cmd_size(cmd_size),
        src_id(src_id),
        user_data(user_data),
        user_type_id(user_type_id)
    {}

    RedisRequestEvent(const RedisRequestEvent& rhs) = delete;
    RedisRequestEvent(RedisRequestEvent&& rhs) = default;


    virtual ~RedisRequestEvent();
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

    RedisReplyEvent(redisReply *reply, RedisRequestEvent &request);
    RedisReplyEvent(result_type result, RedisRequestEvent &request);
    virtual ~RedisReplyEvent();
};

class RedisConnection
  : public AmThread,
    public AmEventFdQueue,
    public AmEventHandler
{
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
    bool ready;

    int scripts_to_load;

    int init_async_context();

    void on_reconnect();

  public:

    struct redisReplyCtx {
        RedisRequestEvent r;
        RedisConnection *c;
        redisReplyCtx(RedisConnection *c, RedisRequestEvent &&r)
          :  r(std::move(r)), c(c)
        {}
    };

    RedisConnection(const char *name);
    ~RedisConnection();
    int init(const string &host, int port);
    void run();
    void on_stop();

    void process(AmEvent* ev);
    void process_request_event(RedisRequestEvent &event);
    void process_reply_event(RedisReplyEvent &event);

    redisAsyncContext *getRedisCtx() { return async_context; }

    redisConnectCallback connectCallback;
    redisDisconnectCallback disconnectCallback;
    void on_redis_reply(RedisRequestEvent &request, redisReply *reply);

    int add_event(int flag);
    int del_event(int flag);
};

static inline bool postRedisRequest(const string &src_tag,
                                    char *cmd, size_t cmd_size,
                                    AmObject *user_data = nullptr, int user_type_id = 0)
{
    return AmSessionContainer::instance()->postEvent(
        ASYNC_REDIS_QUEUE,
        new RedisRequestEvent(src_tag,cmd,cmd_size,user_data,user_type_id));
}

static inline bool postRedisRequestFmt(const string &src_tag,
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
    return postRedisRequest(src_tag, cmd, static_cast<size_t>(ret));
}

static inline bool postRedisRequestFmt(const string &src_tag,
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

    return postRedisRequest(src_tag, cmd, static_cast<size_t>(ret),
                            user_data,user_type_id);
}

