#include "RedisConnectionPool.h"
#include "RedisConnection.h"
#include <AmEventDispatcher.h>

#define EPOLL_MAX_EVENTS 2048

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

static void redis_request_cb_static(redisAsyncContext *, void *r, void *privdata)
{
    RedisReplyCtx *ctx = static_cast<RedisReplyCtx *>(privdata);
    redisReply* reply = static_cast<redisReply *>(r);
    //DBG("got reply from redis");
    if(reply == nullptr) {
        ERROR("%s: I/O error", ctx->src_id.c_str());
    } else if(redis::isReplyError(reply)) {
        ERROR("%s: error: %s", ctx->src_id.c_str(), redis::getReplyError(reply));
    } else {
        //DBG("got succ reply from redis for cmd: %s",request.cmd.get());
    }

    AmSessionContainer::instance()->postEvent(
        ctx->src_id,
        new RedisReplyEvent(reply,*ctx));

    if(!ctx->persistent_ctx) delete ctx;
}

RedisConnectionPool::RedisConnectionPool(const char* name, const string &queue_name)
  : AmEventFdQueue(this),
    epoll_fd(-1),
    name(name),
    queue_name(queue_name),
    stopped(false)
{}

RedisConnectionPool::~RedisConnectionPool()
{
    CLASS_DBG("RedisConnectionPool::~RedisConnectionPool()");
    for(auto &ctx: persistent_reply_contexts)
        delete ctx;
}

int RedisConnectionPool::init()
{
    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    stop_event.link(epoll_fd,true);

    reconnect_timer.link(epoll_fd,true);
    reconnect_timer.set(2e6,true);

    epoll_link(epoll_fd,true);
    return 0;
}

void RedisConnectionPool::run()
{
    int ret;
    void *p;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName(name);
    AmEventDispatcher::instance()->addEventQueue(queue_name, this);

    DBG("start async redis '%s'", name);

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
                process_stop_event();
                stop_event.read();
                running = false;
                break;
            } else if(p==self_queue_ptr) {
                processEvents();
            } else {
                if(!p) {
                    CLASS_ERROR("got event on null async_context. ignore");
                    continue;
                }
                if(e.events & EPOLLIN) {
                    redis::redisAsyncHandleRead((redisAsyncContext*)p);
                }
                if(e.events & EPOLLOUT) {
                    redis::redisAsyncHandleWrite((redisAsyncContext*)p);
                }
            }
        }
    } while(running);

    AmEventDispatcher::instance()->delEventQueue(queue_name);

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("async redis '%s' stopped", name);

    stopped.set(true);
}

void RedisConnectionPool::process(AmEvent* ev)
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

void RedisConnectionPool::process_request_event(RedisRequestEvent& event)
{
    RedisConnection* c = event.getConnection();
    redisAsyncContext* context = c->get_async_context();
    if(c->is_connected()) {
        if(!event.src_id.empty()) {
            if(event.user_data && event.persistent_ctx) {
                ERROR("%s:%d user_data is not allowed for persistent context. clear it",
                    event.src_id.data(), event.user_type_id);
                event.user_data.reset();
            }

            auto ctx = new RedisReplyCtx(c,event);
            if(REDIS_OK!=redis::redisAsyncFormattedCommand(
                context,
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
                context,
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

void RedisConnectionPool::process_stop_event()
{
    for(auto& connection : connections){
        if(connection->is_connected())
            redis::redisAsyncDisconnect(connection->get_async_context());
    }
}

RedisConnection * RedisConnectionPool::addConnection(const std::string& _host, int _port)
{
    RedisConnection* conn = new RedisConnection(name, this);
    if(conn->init(epoll_fd, _host, _port)) {
        delete conn;
        return 0;
    }

    connections.push_back(conn);
    return conn;
}

void RedisConnectionPool::on_reconnect()
{
    for(auto& connection : connections){
        connection->on_reconnect();
    }
}

void RedisConnectionPool::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}
