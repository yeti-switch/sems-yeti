#pragma once

#include "yeti_rpc.h"
#include "yeti_base.h"
#include "yeti_radius.h"

#define YETI_REDIS_REGISTER_TYPE_ID 0
#define YETI_REDIS_RPC_AOR_LOOKUP_TYPE_ID 1

static const string YETI_QUEUE_NAME(MOD_NAME);

class Yeti
  : public YetiRpc,
    public AmThread,
    public AmEventQueue,
    public AmEventHandler,
    virtual public YetiBase,
    virtual public YetiRadius,
    AmObject
{
    static Yeti* _instance;
    bool request_config();
    bool wait_and_apply_config();
    bool stopped;

    sockaddr_storage cfg_remote_address;
    unsigned long cfg_remote_timeout;
    AmCondition<bool> intial_config_received;
    bool cfg_error;

    bool core_options_handling;

    RedisConnection auth_redis;

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
    bool getCoreOptionsHandling() { return core_options_handling; }
};

