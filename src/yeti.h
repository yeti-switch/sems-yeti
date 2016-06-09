#pragma once

#include "yeti_version.h"
#include "yeti_rpc.h"
#include "yeti_cc.h"

#include "AmApi.h"
#include "SBCCallProfile.h"
#include "SBCCallLeg.h"
#include "sip/msg_sensor.h"

#include "SBCCallControlAPI.h"
#include "ampi/RadiusClientAPI.h"
#include "ExtendedCCInterface.h"

#include "yeti_base.h"
#include "yeti_radius.h"
#include "SqlCallProfile.h"
#include "cdr/Cdr.h"
#include "SqlRouter.h"
#include "hash/CdrList.h"
#include "cdr/CdrWriter.h"
#include "resources/ResourceControl.h"
#include "CallCtx.h"
#include "CodesTranslator.h"
#include "CodecsGroup.h"
#include "Sensors.h"

#include <ctime>
#include <yeti/yeticc.h>

class Yeti
  : public ExtendedCCInterface,
    public YetiRpc,
    virtual public YetiBase,
    virtual public YetiRadius,
    virtual public YetiCC,
    AmObject
{
  static Yeti* _instance;

  bool read_config();

 public:
  Yeti(
    SqlRouter &router,
    CdrList &cdr_list,
    ResourceControl &rctl);
  ~Yeti();

  static Yeti* create_instance(
    SqlRouter &router,
    CdrList &cdr_list,
    ResourceControl &rctl);

  static Yeti& instance();

  int onLoad();

  time_t start_time;
};

