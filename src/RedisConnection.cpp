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

static void redisReply2Amarg(AmArg &a, redisReply *r)
{
    switch(r->type) {
    case REDIS_REPLY_ERROR:
        a = string("error: ") + string(r->str,r->len);
        break;
    case REDIS_REPLY_STATUS:
        a = r->integer;
        break;
    case REDIS_REPLY_NIL:
        break;
    case REDIS_REPLY_STRING:
        a = r->str;
        break;
    case REDIS_REPLY_INTEGER:
        a = r->integer;
        break;
    case REDIS_REPLY_ARRAY:
        a.assertArray();
        for(size_t i = 0; i < r->elements; i++) {
            a.push(AmArg());
            redisReply2Amarg(a.back(), r->element[i]);
        }
        break;
    default:
        ERROR("unexpected reply type: %d", r->type);
    }
}

RedisRequestEvent::~RedisRequestEvent()
{ }

RedisReplyEvent::RedisReplyEvent(redisReply *reply, RedisRequestEvent &request)
  : AmEvent(REDIS_REPLY_EVENT_ID),
    user_data(std::move(request.user_data)),
    user_type_id(request.user_type_id)
{
    if(!reply) {
        result = IOError;
        return;
    }
    //serialize redisReply to AmArg
    switch(reply->type) {
    case REDIS_REPLY_ERROR:
        result = ErrorReply;
        data = string("error: ") + string(reply->str,reply->len);
        break;
    case REDIS_REPLY_STATUS:
        result = StatusReply;
        data = reply->integer;
        break;
    default:
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
}

static void connectCallback_static(const redisAsyncContext *c, int status)
{
    static_cast<RedisConnection *>(c->ev.data)->connectCallback(c,status);
}
void RedisConnection::connectCallback(const struct redisAsyncContext* c, int status)
{
    if(status == REDIS_OK) {
        connected = true;
        INFO("redis %s %s:%d connected", name, host.c_str(), port);
        on_connect();
    } else {
        ERROR("redis %s %s:%d: %s",name, host.c_str(), port, c->errstr);
    }
}

static void disconnectCallback_static(const redisAsyncContext *c, int status)
{
    static_cast<RedisConnection *>(c->ev.data)->disconnectCallback(c,status);
}
void RedisConnection::disconnectCallback(const struct redisAsyncContext* c, int status)
{
    connected = false;
    if(status == REDIS_OK) {
        INFO("redis %s %s:%d disconnected", name, host.c_str(), port);
    } else {
        ERROR("redis %s %s:%d: %s",name, host.c_str(), port, c->errstr);
    }
}

static int add_event_static(void *c, int flag) {
    return static_cast<RedisConnection *>(c)->add_event(flag);
}
int RedisConnection::add_event(int flag)
{
    struct epoll_event ee = {};
    int op = mask ? EPOLL_CTL_MOD : EPOLL_CTL_ADD ;

    ee.events = static_cast<uint32_t>(mask |= flag);
    ee.data.ptr = this;

    return epoll_ctl(epoll_fd, op, async_context->c.fd, &ee);
}

static int del_event_static(void *c, int flag) {
    return static_cast<RedisConnection *>(c)->del_event(flag);
}
int RedisConnection::del_event(int flag)
{
    struct epoll_event  ee = {};

    ee.events = static_cast<uint32_t>(mask &= ~flag);
    ee.data.ptr = this;

    return epoll_ctl(epoll_fd, mask ?  EPOLL_CTL_MOD : EPOLL_CTL_DEL, async_context->c.fd, &ee);
}

static void redisAddRead(void *ctx)     {   add_event_static(ctx,  EPOLLIN); }
static void redisDelRead(void *ctx)     {   del_event_static(ctx,  EPOLLIN); }
static void redisAddWrite(void *ctx)    {   add_event_static(ctx,  EPOLLOUT); }
static void redisDelWrite(void *ctx)    {   del_event_static(ctx,  EPOLLOUT); }
//static void redisCleanup(void *) {}

int RedisConnection::init_async_context()
{
    async_context = redisAsyncConnect(host.c_str(), port);
    if(!async_context || async_context->err) {
        ERROR("redisAsyncContext: %s", async_context->errstr);
        return -1;
    }

    mask = 0;

    //init ctx
    async_context->data = this;

    auto &ev = async_context->ev;

    ev.data = this;
    ev.addRead = redisAddRead;
    ev.delRead = redisDelRead;
    ev.addWrite = redisAddWrite;
    ev.delWrite = redisDelWrite;
    //ev.cleanup = redisCleanup;

    redisAsyncSetConnectCallback(async_context, connectCallback_static);
    redisAsyncSetDisconnectCallback(async_context, disconnectCallback_static);

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

    running = true;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s\n",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p = e.data.ptr;

            if(p==this) {
                if(e.events & EPOLLIN) {
                    redisAsyncHandleRead(async_context);
                }
                if(e.events & EPOLLOUT) {
                    redisAsyncHandleWrite(async_context);
                }
            } else if(p==&reconnect_timer) {
                reconnect_timer.read();
                on_reconnect();
            } else if(p==&stop_event) {
                stop_event.read();
                if(connected)
                    redisAsyncDisconnect(async_context);
                running = false;
                break;
            } else {
                processEvents();
            }
        }
    } while(running);

    AmEventDispatcher::instance()->delEventQueue(queue_name);

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("async redis connection stopped");

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
    ERROR("got unexpected event");
}

static void redis_request_cb_static(redisAsyncContext *, void *r, void *privdata)
{
    RedisConnection::redisReplyCtx *ctx = static_cast<RedisConnection::redisReplyCtx *>(privdata);
    ctx->c->on_redis_reply(ctx->r, static_cast<redisReply *>(r));
    if(!ctx->r.persistent_ctx) delete ctx;
}

void RedisConnection::on_redis_reply(RedisRequestEvent &request, redisReply *reply)
{
    //DBG("got reply from redis for cmd: %s",request.cmd.c_str());

    if(reply == nullptr) {
        ERROR("I/O");
    } else if(reply->type == REDIS_REPLY_ERROR) {
        ERROR("error: %s", reply->str);
    } else {
        //DBG("got succ reply from redis for cmd: %s",request.cmd.get());
    }

    AmSessionContainer::instance()->postEvent(
        request.src_id,
        new RedisReplyEvent(reply,request));
}

void RedisConnection::process_request_event(RedisRequestEvent &event)
{
    //DBG("process_request_event: %s",event.cmd.c_str());
    if(connected) {
        auto ctx = new redisReplyCtx(this,std::move(event));
        if(!ctx->r.src_id.empty()) {
            if(REDIS_OK!=redisAsyncFormattedCommand(
                async_context,
                &redis_request_cb_static,
                ctx,
                ctx->r.cmd.get(),ctx->r.cmd_size))
            {
                if(!event.src_id.empty())
                    AmSessionContainer::instance()->postEvent(
                        event.src_id,
                        new RedisReplyEvent(RedisReplyEvent::FailedToSend,event));
            }
        } else {
            if(REDIS_OK!=redisAsyncFormattedCommand(
                async_context,
                nullptr, nullptr,
                ctx->r.cmd.get(),ctx->r.cmd_size))
            {
                if(!event.src_id.empty())
                    AmSessionContainer::instance()->postEvent(
                        event.src_id,
                        new RedisReplyEvent(RedisReplyEvent::FailedToSend,event));
            }
        }
    } else {
        if(!event.src_id.empty())
            AmSessionContainer::instance()->postEvent(
                event.src_id,
                new RedisReplyEvent(RedisReplyEvent::NotConnected,event));
    }
}
