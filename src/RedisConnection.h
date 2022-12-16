#pragma once

#include <AmThread.h>
#include <AmEventFdQueue.h>
#include <AmSessionContainer.h>
#include <AmArg.h>

#include "RedisInstance.h"

#include <memory>
#include <cmath>

template <typename T>
inline unsigned int len_in_chars(T s)
{
    if(s == 0) return 1;
    return static_cast<unsigned int>(log10(s) + 1);
}

class RedisConnection;
class RedisConnectionPool;

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

    int load(RedisConnection* c, const string &script_path,  int reply_type_id);
};

class RedisConnection
{
  private:
    int epoll_fd;
    int redis_fd;

    string host;
    int port;

    redisAsyncContext* async_context;
    AmCondition<bool> connected;
    int mask;

  protected:
    string name;
    RedisConnectionPool* pool;

    friend class RedisConnectionPool;
    void on_reconnect();
    void on_connect();
    void on_disconnect();
  public:

    RedisConnection(const char* name, RedisConnectionPool* pool);
    virtual ~RedisConnection();
    int init(int epoll_fd, const string &host, int port);

    redisAsyncContext* get_async_context() {return async_context; }
    void cleanup();
    bool is_connected() { return connected.get(); }

    //for unit_tests
    bool wait_connected() {
        return connected.wait_for_to(500);
    }

    redisConnectCallback connectCallback;
    redisDisconnectCallback disconnectCallback;

    int add_event(int flag);
    int del_event(int flag);
};
