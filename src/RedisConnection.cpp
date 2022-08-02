#include "RedisConnection.h"

#include "AmEventDispatcher.h"
#include "AmSessionContainer.h"

#include <fstream>
#include <string>

#define EPOLL_MAX_EVENTS 2048

int RedisScript::load(const string &script_path, int reply_type_id)
{
    try {
        std::ifstream f(script_path);
        if(!f) {
            ERROR("failed to open: %s",script_path.c_str());
            return -1;
        }

        std::string data((std::istreambuf_iterator<char>(f)),
                         (std::istreambuf_iterator<char>()));

        postRedisRequestFmt(
            queue_name, queue_name, false, this, reply_type_id,
            "SCRIPT LOAD %s",data.c_str());

        return 0;
    } catch(...) {
        ERROR("failed to load %s",script_path.c_str());
        return -1;
    }
}

RedisRequestEvent::~RedisRequestEvent()
{
    //use redisFreeCommand() for cmd buffer allocated by redisvFormatCommand()
    if(cmd_allocated_by_redis && cmd.get()) {
        redis::redisFreeCommand(cmd.release());
    }
}

RedisReplyEvent::RedisReplyEvent(redisReply *reply, RedisReplyCtx &ctx)
  : AmEvent(REDIS_REPLY_EVENT_ID),
    user_data(std::move(ctx.user_data)),
    user_type_id(ctx.user_type_id)
{
    if(!reply) {
        result = IOError;
        return;
    }
    //serialize redisReply to AmArg
    if(redis::isReplyError(reply)) {
        result = ErrorReply;
        //data = string("error: ") + string(reply->str,reply->len);
    } else if(redis::isReplyStatus(reply)) {
        result = StatusReply;
        //data = string("status: ") + string(reply->str,reply->len);
    } else {
        result = SuccessReply;
    }

    redisReply2Amarg(data, reply);
}

RedisReplyEvent::RedisReplyEvent(result_type result, RedisRequestEvent &request)
  : AmEvent(REDIS_REPLY_EVENT_ID),
    result(result),
    user_data(std::move(request.user_data)),
    user_type_id(request.user_type_id)
{ }

RedisReplyEvent::~RedisReplyEvent()
{}

RedisConnection::RedisConnection(const char *name, const string &queue_name)
  : AmEventFdQueue(this),
    epoll_fd(-1),
    name(name),
    async_context(nullptr),
    stopped(false),
    connected(false),
    queue_name(queue_name)
{
    RedisConnection::host = "127.0.0.1";
    RedisConnection::port = 6379;
}

RedisConnection::~RedisConnection()
{
    CLASS_DBG("RedisConnection::~RedisConnection()");
    for(auto &ctx: persistent_reply_contexts)
        delete ctx;
}

static void connectCallback_static(const redisAsyncContext *c, int status)
{
    static_cast<RedisConnection *>(redis::redisAsyncGetData(c))->connectCallback(c,status);
}
void RedisConnection::connectCallback(const struct redisAsyncContext* c, int status)
{
    if(status == REDIS_OK) {
        connected = true;
        INFO("redis %s %s:%d connected", name, host.c_str(), port);
        on_connect();
    } else {
        ERROR("redis %s[%p] %s:%d: %s",name, c, host.c_str(), port, redis::redisGetError((void*)c));
    }
}

static void disconnectCallback_static(const redisAsyncContext *c, int status)
{
    static_cast<RedisConnection *>(redis::redisAsyncGetData(c))->disconnectCallback(c,status);
}
void RedisConnection::disconnectCallback(const struct redisAsyncContext* c, int status)
{
    connected = false;
    if(status == REDIS_OK) {
        INFO("redis %s %s:%d disconnected", name, host.c_str(), port);
    } else {
        ERROR("redis %s %s:%d: %s",name, host.c_str(), port, redis::redisGetError((void*)c));
    }
}

static int add_event_static(void *c, int flag)
{
    return static_cast<RedisConnection *>(c)->add_event(flag);
}

int RedisConnection::add_event(int flag)
{
    struct epoll_event ee = {};
    int op = mask ? EPOLL_CTL_MOD : EPOLL_CTL_ADD ;

    ee.events = static_cast<uint32_t>(mask |= flag);
    ee.data.ptr = async_context;

    return epoll_ctl(epoll_fd, op, redis::redisGetFd(async_context), &ee);
}

static int del_event_static(void *c, int flag)
{
    return static_cast<RedisConnection *>(c)->del_event(flag);
}

int RedisConnection::del_event(int flag)
{
    struct epoll_event  ee = {};

    ee.events = static_cast<uint32_t>(mask &= ~flag);
    ee.data.ptr = async_context;

    return epoll_ctl(epoll_fd, mask ?  EPOLL_CTL_MOD : EPOLL_CTL_DEL, redis::redisGetFd(async_context), &ee);
}

void RedisConnection::cleanup()
{
    async_context = nullptr;
}

static void redisAddRead(void *ctx)
{
    add_event_static(ctx,  EPOLLIN);
}
static void redisDelRead(void *ctx)

{
    del_event_static(ctx,  EPOLLIN);
}

static void redisAddWrite(void *ctx)
{
    add_event_static(ctx,  EPOLLOUT);
}

static void redisDelWrite(void *ctx)
{
    del_event_static(ctx,  EPOLLOUT);
}

static void redisCleanup(void *ctx)
{
    return static_cast<RedisConnection *>(ctx)->cleanup();
}

int RedisConnection::init_async_context()
{
    if(async_context) {
        CLASS_DBG("%s: has pending async context %p. do nothing", name, async_context);
        return 0;
    }
    async_context = redis::redisAsyncConnect(host.c_str(), port);
    if(!async_context || redis::redisGetErrorNumber(async_context)) {
        CLASS_ERROR("%s redisAsyncContext: %s", name, redis::redisGetError(async_context));
        return -1;
    }

    mask = 0;

    //init ctx
    redis::EpollCallbacks ev;
    ev.data = this;
    ev.addRead = redisAddRead;
    ev.delRead = redisDelRead;
    ev.addWrite = redisAddWrite;
    ev.delWrite = redisDelWrite;
    ev.cleanup = redisCleanup;
    redis::redisAsyncSetEpollCallbacks(async_context, ev);

    redis::redisAsyncSetConnectCallback(async_context, connectCallback_static);
    redis::redisAsyncSetDisconnectCallback(async_context, disconnectCallback_static);

    return 0;
}

int RedisConnection::init(const string &_host, int _port)
{
    host = _host;
    port = _port;

    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    stop_event.link(epoll_fd,true);

    if(init_async_context()) {
        return -1;
    }

    reconnect_timer.link(epoll_fd,true);
    reconnect_timer.set(2e6,true);

    epoll_link(epoll_fd,true);

    return 0;
}

void RedisConnection::on_reconnect()
{
    reconnect_timer.read();
    if(!connected) {
        init_async_context();
    }
}

void RedisConnection::run()
{
    int ret;
    void *p;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    AmEventDispatcher::instance()->addEventQueue(queue_name, this);

    setThreadName("async_redis");

    DBG("start async_redis");

    auto self_queue_ptr = dynamic_cast<AmEventFdQueue *>(this);
    running = true;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p = e.data.ptr;
            if(p==&reconnect_timer) {
                reconnect_timer.read();
                on_reconnect();
            } else if(p==&stop_event) {
                stop_event.read();
                if(connected)
                    redis::redisAsyncDisconnect(async_context);
                running = false;
                break;
            } else if(p==self_queue_ptr) {
                processEvents();
            } else {
                if(!async_context) {
                    CLASS_ERROR("got event on null async_context. ignore");
                    continue;
                }
                if(async_context != p) {
                    CLASS_ERROR("invalid async_context:%p received. expected:%p", p, async_context);
                    continue;
                }
                if(e.events & EPOLLIN) {
                    redis::redisAsyncHandleRead(async_context);
                }
                if(e.events & EPOLLOUT) {
                    redis::redisAsyncHandleWrite(async_context);
                }
            }
        }
    } while(running);

    AmEventDispatcher::instance()->delEventQueue(queue_name);

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("async redis connection '%s' stopped", name);

    stopped.set(true);
}

void RedisConnection::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

void RedisConnection::process(AmEvent* ev)
{
    switch(ev->event_id) {
    case E_SYSTEM: {
        AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev);
        if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown){
            stop_event.fire();
        }
        return;
    }
    case REDIS_REQUEST_EVENT_ID:
        if(RedisRequestEvent *e = dynamic_cast<RedisRequestEvent*>(ev)) {
            process_request_event(*e);
            return;
        }
        break;
    case REDIS_REPLY_EVENT_ID:
        if(RedisReplyEvent *e = dynamic_cast<RedisReplyEvent*>(ev)) {
            process_reply_event(*e);
            return;
        }
        break;
    }
    ERROR("%s: got unexpected event", name);
}

static void redis_request_cb_static(redisAsyncContext *, void *r, void *privdata)
{
    RedisReplyCtx *ctx = static_cast<RedisReplyCtx *>(privdata);
    ctx->c->on_redis_reply(*ctx, static_cast<redisReply *>(r));
    if(!ctx->persistent_ctx) delete ctx;
}

void RedisConnection::on_redis_reply(RedisReplyCtx &ctx, redisReply *reply)
{
    DBG("got reply from redis");

    if(reply == nullptr) {
        ERROR("%s: I/O error", name);
    } else if(redis::isReplyError(reply)) {
        ERROR("%s: error: %s", name, redis::getReplyError(reply));
    } else {
        //DBG("got succ reply from redis for cmd: %s",request.cmd.get());
    }

    AmSessionContainer::instance()->postEvent(
        ctx.src_id,
        new RedisReplyEvent(reply,ctx));
}

void RedisConnection::process_request_event(RedisRequestEvent &event)
{
    //DBG("process_request_event: %s",event.cmd.c_str());
    if(connected) {
        if(!event.src_id.empty()) {
            if(event.user_data && event.persistent_ctx) {
                ERROR("%s:%d user_data is not allowed for persistent context. clear it",
                    event.src_id.data(), event.user_type_id);
                event.user_data.reset();
            }

            auto ctx = new RedisReplyCtx(this,event);
            if(REDIS_OK!=redis::redisAsyncFormattedCommand(
                async_context,
                &redis_request_cb_static, ctx,
                event.cmd.get(),event.cmd_size))
            {
                AmSessionContainer::instance()->postEvent(
                    ctx->src_id,
                    new RedisReplyEvent(RedisReplyEvent::FailedToSend,event));
                delete ctx;
                return;
            }
            //set reply ctx for persistent contexts
            if(ctx->persistent_ctx) {
                persistent_reply_contexts.push_back(ctx);
            }
        } else {
            if(REDIS_OK!=redis::redisAsyncFormattedCommand(
                async_context,
                nullptr, nullptr,
                event.cmd.get(),event.cmd_size))
            { }
        }
    } else {
        if(!event.src_id.empty())
            AmSessionContainer::instance()->postEvent(
                event.src_id,
                new RedisReplyEvent(RedisReplyEvent::NotConnected,event));
    }
}
