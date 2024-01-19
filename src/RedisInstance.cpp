#include "RedisInstance.h"
#include "../unit_tests/RedisTestServer.h"
#include "hiredis/hiredis.h"
#include "hiredis/async.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <log.h>
#include <AmUtils.h>

#include <queue>

using std::queue;

struct redisInstanceContext;
static void connectCallback(const struct redisAsyncContext* ctx, int status);
static void disconnectCallback(const struct redisAsyncContext* ctx, int status);

class RedisInstance
{
protected:
    redisInstanceContext* async_context;
    redisConnectCallback* connect_callback;
    redisDisconnectCallback* disconnect_callback;
public:
    RedisInstance()
    : async_context(0)
    , connect_callback(0)
    , disconnect_callback(0){}
    virtual ~RedisInstance(){}

    void onConnect(int status) {
        connect_callback((redisAsyncContext*)async_context, status);
    }
    void onDisconnect(int status) {
        disconnect_callback((redisAsyncContext*)async_context, status);
        redis::redisFree((redisAsyncContext*)async_context);
    }

    virtual redisAsyncContext *redisAsyncConnect(const char *ip, int port) = 0;
    virtual void redisAsyncDisconnect(redisAsyncContext *ac) = 0;
    virtual redisContext * redisConnectWithTimeout(const char* ip, int port, const struct timeval tv) = 0;
    virtual redisContext *redisConnectUnixWithTimeout(const char *path, const struct timeval tv) = 0;
    virtual int redisAppendCommand(redisContext* c, const char* format, va_list list) = 0;
    virtual int redisAsyncSetConnectCallback(redisAsyncContext *ac, redisConnectCallback *fn) = 0;
    virtual int redisAsyncSetDisconnectCallback(redisAsyncContext *ac, redisDisconnectCallback *fn) = 0;
    virtual void redisAsyncHandleRead(redisAsyncContext *ac) = 0;
    virtual void redisAsyncHandleWrite(redisAsyncContext *ac) = 0;
    virtual int redisGetReply(redisContext* c, void ** reply) = 0;
    virtual int redisAsyncFormattedCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *cmd, size_t len) = 0;
    virtual void freeReplyObject(void *reply) = 0;
    virtual void redisFree(redisContext* ctx) = 0;
    virtual RedisInstance* clone(redisInstanceContext* async_context) = 0;
};

struct redisInstanceContext {
    RedisInstance* instance;
    union {
        redisAsyncContext* ac;
        redisContext* c;
    } original;
    bool async;
};

static RedisInstance* _instance_ = 0;

static void connectCallback(const struct redisAsyncContext* ctx, int status) {
    RedisInstance* instance = (RedisInstance*)ctx->data;
    instance->onConnect(status);
}

static void disconnectCallback(const struct redisAsyncContext* ctx, int status) {
    RedisInstance* instance = (RedisInstance*)ctx->data;
    instance->onDisconnect(status);
}

class RedisRealConnection : public RedisInstance
{
public:
    RedisRealConnection(){}

    redisAsyncContext *redisAsyncConnect(const char *ip, int port) override
    {
        return ::redisAsyncConnect(ip, port);
    }

    void redisAsyncDisconnect(redisAsyncContext *ac) override
    {
        ::redisAsyncDisconnect(ac);
    }

    redisContext * redisConnectWithTimeout(const char* ip, int port, const struct timeval tv) override
    {
        return ::redisConnectWithTimeout(ip, port, tv);
    }

    redisContext *redisConnectUnixWithTimeout(const char *path, const struct timeval tv) override
    {
        return ::redisConnectUnixWithTimeout(path, tv);
    }

    void redisFree(redisContext* ctx) override
    {
        ::redisFree(ctx);
    }

    int redisAppendCommand(redisContext* c, const char* format, va_list argptr) override
    {
        return ::redisvAppendCommand(c, format, argptr);
    }

    int redisAsyncSetConnectCallback(redisAsyncContext *ac, redisConnectCallback *fn) override
    {
        connect_callback = fn;
        return ::redisAsyncSetConnectCallback(ac, &connectCallback);
    }

    int redisAsyncSetDisconnectCallback(redisAsyncContext *ac, redisDisconnectCallback *fn) override
    {
        disconnect_callback = fn;
        return ::redisAsyncSetDisconnectCallback(ac, &disconnectCallback);
    }

    void redisAsyncHandleRead(redisAsyncContext *ac) override
    {
        ::redisAsyncHandleRead(ac);
    }

    void redisAsyncHandleWrite(redisAsyncContext *ac) override
    {
        ::redisAsyncHandleWrite(ac);
    }

    int redisAsyncFormattedCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *cmd, size_t len) override
    {
        return ::redisAsyncFormattedCommand(ac, fn, privdata, cmd, len);
    }

    int redisGetReply(redisContext* c, void ** reply) override
    {
        return ::redisGetReply(c, reply);
    }

    void freeReplyObject(void *reply) override
    {
        ::freeReplyObject(reply);
    }

    RedisInstance* clone(redisInstanceContext* async_context) override {
        RedisRealConnection* instance = new RedisRealConnection();
        instance->async_context = async_context;
        return instance;
    }
};

class RedisTest : public RedisInstance
{
    RedisTestServer* server;
    bool async_connected;
    struct Command{
        redisCallbackFn *replyfn;
        void* privdata;
        string command;
    };

    queue<Command> q;
public:
    RedisTest(RedisTestServer* server)
    : server(server)
    , async_connected(false){}

    redisAsyncContext *redisAsyncConnect(const char *ip, int port) override
    {
        redisAsyncContext* ctx = (redisAsyncContext*)malloc(sizeof(redisAsyncContext));
        memset(ctx, 0, sizeof(redisAsyncContext));
        ctx->c.tcp.host = strdup(ip);
        ctx->c.tcp.source_addr = strdup(ip);
        ctx->c.tcp.port = port;
        ctx->c.connection_type = REDIS_CONN_TCP;
        ctx->c.fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        return ctx;
    }

    void redisAsyncDisconnect(redisAsyncContext *ac) override
    {
        if(ac->ev.cleanup)
            ac->ev.cleanup(ac->ev.data);
        redisFree(&ac->c);
        if(ac->onDisconnect)
            ac->onDisconnect(ac, REDIS_OK);
    }

    redisContext * redisConnectWithTimeout(const char* ip, int port, const struct timeval tv) override
    {
        redisContext* ctx = (redisContext*)malloc(sizeof(redisContext));
        memset(ctx, 0, sizeof(redisContext));
        ctx->tcp.host = strdup(ip);
        ctx->tcp.source_addr = strdup(ip);
        ctx->tcp.port = port;
        ctx->connection_type = REDIS_CONN_TCP;
#if HIREDIS_MAJOR > 0
        ctx->connect_timeout = (struct timeval*)malloc(sizeof(struct timeval));
        *ctx->connect_timeout = tv;

        ctx->command_timeout = (struct timeval*)malloc(sizeof(struct timeval));
        *ctx->command_timeout = tv;
#else
        ctx->timeout = (struct timeval*)malloc(sizeof(struct timeval));
        *ctx->timeout = tv;
#endif
        ctx->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        return ctx;
    }

    redisContext *redisConnectUnixWithTimeout(const char *path, const struct timeval tv) override
    {
        redisContext* ctx = (redisContext*)malloc(sizeof(redisContext));
        memset(ctx, 0, sizeof(redisContext));
        ctx->unix_sock.path = strdup(path);
        ctx->connection_type = REDIS_CONN_UNIX;
#if HIREDIS_MAJOR > 0
        ctx->connect_timeout = (struct timeval*)malloc(sizeof(struct timeval));
        *ctx->connect_timeout = tv;

        ctx->command_timeout = (struct timeval*)malloc(sizeof(struct timeval));
        *ctx->command_timeout = tv;
#else
        ctx->timeout = (struct timeval*)malloc(sizeof(struct timeval));
        *ctx->timeout = tv;
#endif
        ctx->fd = socket(AF_UNIX, SOCK_STREAM, 0);
        return ctx;
    }

    void redisFree(redisContext* ctx) override
    {
        if(ctx->tcp.host) free(ctx->tcp.host);
        if(ctx->tcp.source_addr) free(ctx->tcp.source_addr);
        if(ctx->unix_sock.path) free(ctx->unix_sock.path);
#if HIREDIS_MAJOR > 0
        if(ctx->connect_timeout) free(ctx->connect_timeout);
        if(ctx->command_timeout) free(ctx->command_timeout);
#else
        if(ctx->timeout) free(ctx->timeout);
#endif
        close(ctx->fd);
        free(ctx);
    }

    int redisAsyncSetConnectCallback(redisAsyncContext *ac, redisConnectCallback *fn) override
    {
        connect_callback = fn;
        ac->onConnect = &connectCallback;
        if(ac->ev.addWrite) {
            ac->ev.addWrite(ac->ev.data);
        } else {
            ERROR("absent event function in redis context");
        }
        return REDIS_OK;
    }

    int redisAsyncSetDisconnectCallback(redisAsyncContext *ac, redisDisconnectCallback *fn) override
    {
        disconnect_callback = fn;
        ac->onDisconnect = &disconnectCallback;
        return REDIS_OK;
    }

    void redisAsyncHandleRead(redisAsyncContext *) override {}
    void redisAsyncHandleWrite(redisAsyncContext *ac) override
    {
        if(!async_connected && ac->onConnect) {
            async_connected = true;
            ac->onConnect(ac, REDIS_OK);
            if(ac->ev.delWrite) {
                ac->ev.delWrite(ac->ev.data);
            } else {
                ERROR("absent event function in redis context");
            }
        } else {
            redisReply* reply;
            Command cmd = q.front();
            redisGetReply(&ac->c, (void**)&reply);
            if(cmd.replyfn)
                cmd.replyfn(ac, reply, cmd.privdata);
            freeReplyObject(reply);
            if(q.empty()) {
                if(ac->ev.delWrite) {
                    ac->ev.delWrite(ac->ev.data);
                } else {
                    ERROR("absent event function in redis context");
                }
            }
        }
    }

    int redisAsyncFormattedCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata_, const char *cmd, size_t len) override
    {
        if(ac->ev.addWrite)
           ac->ev.addWrite(ac->ev.data);
        Command current;
        current.replyfn = fn;
        current.privdata = privdata_;
        current.command = string(cmd, len);
        q.push(current);
        return REDIS_OK;
    }

    int redisAppendCommand(redisContext* , const char* format, va_list argptr) override
    {
        Command current;
        current.replyfn = 0;
        current.privdata = 0;
        char* cmd;
        redisvFormatCommand(&cmd, format, argptr);
        current.command = cmd;
        q.push(current);
        redisFreeCommand(cmd);
        return REDIS_OK;
    }

    int redisGetReply(redisContext* c, void ** reply) override
    {
        Command& cmd = q.front();

        AmArg r;
        if(server) {
            AmArg res;
            while(server->getResponse(cmd.command, res)) 
                r.push(res);
        }
        Amarg2redisReply(r, (redisReply**)reply);
        //INFO("redisGetReply type %d", (*(redisReply**)reply)->type);
        redisReply* _reply = (redisReply*)*reply;
        if(server && server->getStatus(cmd.command) == REDIS_REPLY_STATUS && _reply->type == REDIS_REPLY_NIL) {
            q.pop();
            _reply->type = REDIS_REPLY_STATUS;
            return REDIS_OK;
        } else if(server && _reply->type != server->getStatus(cmd.command)) {
            q.pop();
            _reply->type = REDIS_REPLY_ERROR;
            c->err = REDIS_REPLY_ERROR;
            return REDIS_REPLY_ERROR;
        }
        q.pop();
        return REDIS_OK;
    }

    void freeReplyObject(void *reply) override
    {
        if(!reply) return;
        redisReply* _reply = (redisReply*)reply;
        if(_reply->str) free(_reply->str);
        if(_reply->element) {
            for(size_t i = 0; i < _reply->elements; i++)
                freeReplyObject(_reply->element[i]);
            free(_reply->element);
        }
        free(reply);
    }

    RedisInstance* clone(redisInstanceContext* async_context) override {
        RedisTest* instance = new RedisTest(server);
        instance->async_context = async_context;
        return instance;
    }
};

namespace redis {

int redisAppendCommand(redisContext* c, const char* format, ...)
{
    va_list argptr;
    va_start (argptr, format);
    redisInstanceContext* context = (redisInstanceContext*)c;
    int ret = context->instance->redisAppendCommand(context->original.c, format, argptr);
    va_end(argptr);
    return ret;
}

int redisGetReply(redisContext* c, void ** reply)
{
    redisInstanceContext* context = (redisInstanceContext*)c;
    return context->instance->redisGetReply(context->original.c, reply);
}

bool isReplyError(redisReply* reply)
{
    return reply->type == REDIS_REPLY_ERROR;
}

bool isReplyStatus(redisReply* reply)
{
    return reply->type == REDIS_REPLY_STATUS;
}

char* getReplyError(redisReply* reply)
{
    return reply->str;
}

void freeReplyObject(redisContext* c, void* reply)
{
    redisInstanceContext* context = (redisInstanceContext*)c;
    context->instance->freeReplyObject(reply);
}

int redisvFormatCommand(char ** cmd, const char* fmt, va_list args)
{
    return ::redisvFormatCommand(cmd, fmt, args);
}

int redisFormatCommand(char** cmd, const  char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int ret = redis::redisvFormatCommand(cmd, fmt, args);
    va_end(args);
    return ret;
}

void redisFreeCommand(char* cmd)
{
    ::redisFreeCommand(cmd);
}

int redisAsyncFormattedCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *cmd, size_t len)
{
    redisInstanceContext* context = (redisInstanceContext*)ac;
    return context->instance->redisAsyncFormattedCommand(context->original.ac, fn, privdata, cmd, len);
}

redisAsyncContext *redisAsyncConnect(const char *ip, int port)
{
    if(!_instance_) return 0;
    redisInstanceContext* context = (redisInstanceContext*)malloc(sizeof(redisInstanceContext));
    context->original.ac = _instance_->redisAsyncConnect(ip, port);
    context->async = true;
    context->original.ac->data = context->instance = _instance_->clone(context);
    return (redisAsyncContext*)context;
}

void redisAsyncDisconnect(redisAsyncContext *ac)
{
    redisInstanceContext* context = (redisInstanceContext*)ac;
    if(!context) {
        DBG("empty context");
        return;
    }

    if(!context->async) {
        ERROR("trying to free not async redis context");
        return;
    }

    context->instance->redisAsyncDisconnect(context->original.ac);
}

redisContext * redisConnectWithTimeout(const char* ip, int port, const struct timeval tv)
{
    if(!_instance_) return 0;
    redisInstanceContext* context = (redisInstanceContext*)malloc(sizeof(redisInstanceContext));
    context->original.c = _instance_->redisConnectWithTimeout(ip, port, tv);
    context->async = false;
    context->instance = _instance_->clone(context);
    return (redisContext*)context;
}

redisContext *redisConnectUnixWithTimeout(const char *path, const struct timeval tv)
{
    if(!_instance_) return 0;
    redisInstanceContext* context = (redisInstanceContext*)malloc(sizeof(redisInstanceContext));
    context->original.c = _instance_->redisConnectUnixWithTimeout(path, tv);
    context->async = false;
    context->instance = _instance_->clone(context);
    return (redisContext*)context;
}

void redisFree(redisContext* ctx)
{
    redisInstanceContext* context = (redisInstanceContext*)ctx;
    if(context->async) {
        ERROR("trying freed async redis context");
        return;
    }
    context->instance->redisFree(context->original.c);
    delete context->instance;
    free(context);
}

void redisFree(redisAsyncContext* ctx)
{
    redisInstanceContext* context = (redisInstanceContext*)ctx;
    if(!context->async) {
        ERROR("trying freed not async redis context");
        return;
    }
    delete context->instance;
    free(context);
}

char * redisGetError(void* c)
{
    redisInstanceContext* context = (redisInstanceContext*)c;
    return context->async ? context->original.ac->errstr : context->original.c->errstr;
}

int redisGetErrorNumber(void* c)
{
    redisInstanceContext* context = (redisInstanceContext*)c;
    return context->async ? context->original.ac->err : context->original.c->err;
}

int redisAsyncSetConnectCallback(redisAsyncContext *ac, redisConnectCallback *fn)
{
    redisInstanceContext* context = (redisInstanceContext*)ac;
    if(!context->async) {
        ERROR("using async function for not async redis context");
        return REDIS_ERR;
    }
    return context->instance->redisAsyncSetConnectCallback(context->original.ac, fn);
}

int redisAsyncSetDisconnectCallback(redisAsyncContext *ac, redisDisconnectCallback *fn)
{
    redisInstanceContext* context = (redisInstanceContext*)ac;
    if(!context->async) {
        ERROR("using async function for not async redis context");
        return REDIS_ERR;
    }
    return context->instance->redisAsyncSetDisconnectCallback(context->original.ac, fn);
}

void redisAsyncSetEpollCallbacks(redisAsyncContext *ac, EpollCallbacks ev)
{
    redisInstanceContext* context = (redisInstanceContext*)ac;
    if(!context->async) {
        ERROR("using async function for not async redis context");
        return;
    }
    context->original.ac->ev.data = ev.data;
    context->original.ac->ev.addRead = ev.addRead;
    context->original.ac->ev.addWrite = ev.addWrite;
    context->original.ac->ev.delRead = ev.delRead;
    context->original.ac->ev.delWrite = ev.delWrite;
    context->original.ac->ev.cleanup = ev.cleanup;
}

void* redisAsyncGetData(const redisAsyncContext * ctx)
{
    redisInstanceContext* context = (redisInstanceContext*)ctx;
    if(!context->async) {
        ERROR("using async function for not async redis context");
        return 0;
    }
    return context->original.ac->ev.data;
}

int redisGetFd(void* c)
{
    redisInstanceContext* context = (redisInstanceContext*)c;
    return context->original.c->fd;
}

void redisAsyncHandleRead(redisAsyncContext *ac)
{
    redisInstanceContext* context = (redisInstanceContext*)ac;
    context->instance->redisAsyncHandleRead(context->original.ac);
}

void redisAsyncHandleWrite(redisAsyncContext *ac)
{
    redisInstanceContext* context = (redisInstanceContext*)ac;
    context->instance->redisAsyncHandleWrite(context->original.ac);
}

}

void makeRedisInstance(bool test, RedisTestServer* server)
{
    if(_instance_)
        return;

    if(test)
        _instance_ = new RedisTest(server);
    else
        _instance_ = new RedisRealConnection;
}

void freeRedisInstance()
{
    if(_instance_)
        delete _instance_;
    _instance_ = 0;
}

void redisReply2Amarg(AmArg &a, redisReply *reply)
{
    switch(reply->type) {
    case REDIS_REPLY_ERROR:
        a.assertStruct();
        a["error"] = string(reply->str,reply->len);
        break;
    case REDIS_REPLY_STATUS:
        a.assertStruct();
        a["status"] = string(reply->str,reply->len);
        break;
    case REDIS_REPLY_NIL:
        break;
    case REDIS_REPLY_STRING:
        a = reply->str;
        break;
    case REDIS_REPLY_INTEGER:
        a = reply->integer;
        break;
    case REDIS_REPLY_ARRAY:
        a.assertArray();
        for(size_t i = 0; i < reply->elements; i++) {
            a.push(AmArg());
            redisReply2Amarg(a.back(), reply->element[i]);
        }
        break;
    default:
        ERROR("unexpected reply type: %d", reply->type);
    }
}

static bool isArgNumber(const AmArg& arg) {
    return isArgInt(arg) || isArgLongLong(arg) || isArgDouble(arg);
}

void Amarg2redisReply(const AmArg& a, redisReply** r)
{
    *r = (redisReply*)malloc(sizeof(redisReply));
    memset(*r, 0, sizeof(redisReply));
    if(isArgNumber(a)) {
        (*r)->type = REDIS_REPLY_INTEGER;
        (*r)->integer = a.asLongLong();
    } else if(isArgCStr(a)) {
        (*r)->type = REDIS_REPLY_STRING;
        (*r)->str = strdup(a.asCStr());
        (*r)->len = strlen(a.asCStr());
    } else if(isArgArray(a)){
        (*r)->type = REDIS_REPLY_ARRAY;
        (*r)->elements = a.size();
        (*r)->element = (redisReply**)malloc(sizeof(redisReply*)*a.size());
        for(size_t i = 0; i < a.size(); i++)
            Amarg2redisReply(a[i], (*r)->element + i);
    } else if(isArgUndef(a)) {
        (*r)->type = REDIS_REPLY_NIL;
    } else {
        ERROR("incorrect AmArg for redisReply");
    }
}

static void checkReplyType(redisContext * ctx, redisReply* reply, int state, int expected, const char* log) noexcept(false)
{
    if(state!=REDIS_OK)
        throw GetReplyException(string(log) + ": redis::redisGetReply() != REDIS_OK",state);
    if(reply==NULL)
        throw GetReplyException(string(log) + ": reply == NULL",state);
    if(reply->type != expected){
        if(reply->type==REDIS_REPLY_ERROR) {
            redis::freeReplyObject(ctx, reply);
            throw ReplyDataException(reply->str);
        }
        redis::freeReplyObject(ctx, reply);
        throw ReplyTypeException(string(log) + ": type not desired",reply->type);
    }
}

AmArg runMultiCommand(redisContext * ctx, const vector<string>& commands, const char* log) noexcept(false)
{
    redisReply* reply;
    AmArg ret;
    redis::redisAppendCommand(ctx,"MULTI");
    for(auto& cmd : commands){
        redis::redisAppendCommand(ctx, cmd.c_str());
    }
    redis::redisAppendCommand(ctx,"EXEC");

    int checkStatusNum = commands.size() + 1;

    for(int i = 0; i < checkStatusNum; i++) {
        int state = redis::redisGetReply(ctx,(void **)&reply);
        checkReplyType(ctx, reply, state, REDIS_REPLY_STATUS, log);
        redis::freeReplyObject(ctx, reply);
    }

    int state = redis::redisGetReply(ctx,(void **)&reply);
    checkReplyType(ctx, reply, state, REDIS_REPLY_ARRAY, log);
    redisReply2Amarg(ret, reply);
    redis::freeReplyObject(ctx, reply);
    return ret;
}
