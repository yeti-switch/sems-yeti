#pragma once

#include "yeti_rpc.h"
#include "yeti_base.h"
#include "yeti_radius.h"

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
    bool load_config();
    bool stopped;

    sockaddr_storage cfg_remote_address;
    unsigned long cfg_remote_timeout;
    AmCondition<bool> intial_config_received;
    bool cfg_error;

    bool registrations_enabled;
    bool core_options_handling;

  public:
    Yeti(YetiBaseParams &params);
    ~Yeti();

    static Yeti* create_instance(YetiBaseParams params);
    static Yeti& instance();

    int onLoad();
    int configure(const std::string& config);

    void run();
    void on_stop();
    void process(AmEvent *ev);

    bool getRegistrationsEnabled() { return registrations_enabled; }
    bool getCoreOptionsHandling() { return core_options_handling; }
};

