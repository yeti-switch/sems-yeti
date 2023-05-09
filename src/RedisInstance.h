#ifndef REDIS_INSTANCE_H
#define REDIS_INSTANCE_H

#include <time.h>
#include <AmArg.h>

struct redisContext;
struct redisAsyncContext;
struct redisReply;
class RedisTestServer;

#define REDIS_OK 0
#define REDIS_ERR -1

/* Connection callback prototypes */
typedef void (redisDisconnectCallback)(const struct redisAsyncContext*, int status);
typedef void (redisConnectCallback)(const struct redisAsyncContext*, int status);
typedef void (redisCallbackFn)(struct redisAsyncContext*, void*, void*);

namespace redis {
struct EpollCallbacks{
    void *data;

    /* Hooks that are called when the library expects to start
        * reading/writing. These functions should be idempotent. */
    void (*addRead)(void *privdata);
    void (*delRead)(void *privdata);
    void (*addWrite)(void *privdata);
    void (*delWrite)(void *privdata);
    void (*cleanup)(void *privdata);
};

redisContext *redisConnectWithTimeout(const char *ip, int port, const struct timeval tv);
redisContext *redisConnectUnixWithTimeout(const char *path, const struct timeval tv);
redisAsyncContext *redisAsyncConnect(const char *ip, int port);
void redisAsyncDisconnect(redisAsyncContext *ac);
void redisAsyncSetEpollCallbacks(redisAsyncContext *ac, EpollCallbacks ev);
void redisFree(redisContext * ctx);
void redisFree(redisAsyncContext * ctx);
void* redisAsyncGetData(const redisAsyncContext * ctx);
int redisGetFd(void* c);
char* redisGetError(void *c);
int redisGetErrorNumber(void *c);

int redisAsyncSetConnectCallback(redisAsyncContext *ac, redisConnectCallback *fn);
int redisAsyncSetDisconnectCallback(redisAsyncContext *ac, redisDisconnectCallback *fn);

void redisAsyncHandleRead(redisAsyncContext *ac);
void redisAsyncHandleWrite(redisAsyncContext *ac);

int redisAppendCommand(redisContext *c, const char *format, ...);
int redisGetReply(redisContext *c, void **reply);
int redisAsyncFormattedCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *cmd, size_t len);

bool isReplyError(redisReply* reply);
bool isReplyStatus(redisReply* reply);
char* getReplyError(redisReply* reply);
void freeReplyObject(redisContext* context, void *reply);

int redisvFormatCommand(char** cmd, const  char* fmt, va_list args);
int redisFormatCommand(char** cmd, const  char* fmt, ...);
void redisFreeCommand(char* cmd);
}

struct GetReplyException {
	std::string what;
	int status;
	GetReplyException(std::string w, int s): what(w), status(s) {}
};

struct ReplyTypeException {
	std::string what;
	int type;
	ReplyTypeException(std::string w, int t): what(w), type(t) {}
};

struct ReplyDataException {
	std::string what;
	ReplyDataException(std::string w): what(w) {}
};

void makeRedisInstance(bool test, RedisTestServer* server = 0);
void freeRedisInstance();

AmArg runMultiCommand(redisContext * ctx, const std::vector<std::string>& commands, const char* log) noexcept(false);
void redisReply2Amarg(AmArg &a, redisReply *r);
void Amarg2redisReply(const AmArg &a, redisReply **r);

#endif/*REDIS_INSTANCE_H*/
