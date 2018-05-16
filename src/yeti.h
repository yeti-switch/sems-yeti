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
    AmCondition<bool> intial_config_received;
    bool cfg_error;
  public:
    Yeti(YetiBaseParams &params);
    ~Yeti();
    static Yeti* create_instance(YetiBaseParams params);
    static Yeti& instance();
    int onLoad();
    void run();
    void on_stop();
    void process(AmEvent *ev);
};

