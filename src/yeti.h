#pragma once

#include "yeti_rpc.h"
//#include "yeti_cc.h"
#include "yeti_base.h"
#include "yeti_radius.h"

class Yeti
  : public YetiRpc,
    //public YetiCC,
    virtual public YetiBase,
    virtual public YetiRadius,
    AmObject
{
    static Yeti* _instance;
    bool read_config();
  public:
    Yeti(YetiBaseParams &params);
    ~Yeti();
    static Yeti* create_instance(YetiBaseParams params);
    static Yeti& instance();
    int onLoad();
};

