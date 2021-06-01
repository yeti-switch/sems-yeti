#pragma once

#include "yeti_rpc.h"
#include "yeti_base.h"
#include "yeti_radius.h"
#include "HttpSequencer.h"
#include "CertCache.h"

#include <AmEventFdQueue.h>

#define YETI_REDIS_REGISTER_TYPE_ID 0
#define YETI_REDIS_RPC_AOR_LOOKUP_TYPE_ID 1

class Yeti
  : public YetiRpc,
    public AmThread,
    public AmEventFdQueue,
    public AmEventHandler,
    virtual public YetiBase,
    virtual public YetiRadius,
    AmObject
{
    static Yeti* _instance;
    bool stopped;
    int epoll_fd;
    AmTimerFd keepalive_timer;

    bool apply_config();

  public:

    Yeti(YetiBaseParams &params);
    ~Yeti();

    static Yeti* create_instance(YetiBaseParams params);
    static Yeti& instance();

    int onLoad();
    int configure(const std::string& config);
    int configure_registrar();

    void run();
    void on_stop();
    void process(AmEvent *ev);

    void processRedisRegisterReply(RedisReplyEvent &e);
    void processRedisRpcAorLookupReply(RedisReplyEvent &e);
    bool getCoreOptionsHandling() { return config.core_options_handling; }
};

