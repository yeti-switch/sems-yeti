#include "RedisConnection.h"

#include "AmEventDispatcher.h"
#include "AmSessionContainer.h"

#include <fstream>
#include <string>
#include "RedisConnectionPool.h"

#define EPOLL_MAX_EVENTS 2048

int RedisScript::load(RedisConnection* c, const string &script_path, int reply_type_id)
{
    try {
        std::ifstream f(script_path);
        if(!f) {
            ERROR("failed to open: %s",script_path.c_str());
            return -1;
        }

        std::string data((std::istreambuf_iterator<char>(f)),
                         (std::istreambuf_iterator<char>()));

        postRedisRequestFmt(c,
            queue_name, queue_name, false, this, reply_type_id,
            "SCRIPT LOAD %s",data.c_str());

        return 0;
    } catch(...) {
        ERROR("failed to load %s",script_path.c_str());
        return -1;
    }
}

RedisConnection::RedisConnection(const char* name, RedisConnectionPool* pool)
  : async_context(0),
    connected(false),
    name(name),
    pool(pool)
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
    RedisConnection *conn = static_cast<RedisConnection*>(redis::redisAsyncGetData(c));
    conn->connectCallback(c,status);
}
void RedisConnection::connectCallback(const struct redisAsyncContext* c, int status)
{
    if(status == REDIS_OK) {
        INFO("redis %s[%p] %s:%d connected", name.c_str(), c, host.c_str(), port);
        on_connect();
    } else {
        ERROR("redis %s[%p] %s:%d: %s",name.c_str(), c, host.c_str(), port, redis::redisGetError((void*)c));
    }
}

static void disconnectCallback_static(const redisAsyncContext *c, int status)
{
    RedisConnection *conn = static_cast<RedisConnection*>(redis::redisAsyncGetData(c));
    conn->disconnectCallback(c, status);
}
void RedisConnection::disconnectCallback(const redisAsyncContext *c, int status)
{
    on_disconnect();
    if(status == REDIS_OK) {
        INFO("redis %s[%p] %s:%d disconnected", name.c_str(), c, host.c_str(), port);
    } else {
        ERROR("redis %s[%p] %s:%d: %s",name.c_str(), c, host.c_str(), port, redis::redisGetError((void*)c));
    }
}

static int add_event_static(void *c, int flag)
{
    RedisConnection* conn = static_cast<RedisConnection*>(c);
    return conn->add_event(flag);
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
    RedisConnection* conn = static_cast<RedisConnection*>(c);
    return conn->del_event(flag);
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
    async_context = 0;
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
    RedisConnection* conn = static_cast<RedisConnection*>(ctx);
    return conn->cleanup();
}

int RedisConnection::init(int fd, const string &_host, int _port)
{
    host = _host;
    port = _port;
    epoll_fd = fd;

    if(async_context) return 0;
    async_context = redis::redisAsyncConnect(_host.c_str(), _port);
    if(!async_context || redis::redisGetErrorNumber(async_context)) {
        CLASS_ERROR("%s redisAsyncContext: %s", name.c_str(), redis::redisGetError(async_context));
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

void RedisConnection::on_reconnect()
{
    if(!connected.get()) {
        init(epoll_fd, host, port);
    }
}

void RedisConnection::on_connect() {
    connected = true;
    pool->on_connect(this);
}
void RedisConnection::on_disconnect() {
    connected = false;
    pool->on_disconnect(this);
}
