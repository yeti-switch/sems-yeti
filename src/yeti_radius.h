#pragma once

#include "ampi/RadiusClientAPI.h"
#include "AmConfigReader.h"

#include "yeti_base.h"

class YetiRadius
  : virtual YetiBase
{
  protected:
    YetiRadius(YetiBase &base)
      : YetiBase(base)
    { }

    int init_radius_module(AmConfigReader& cfg);
    int init_radius_auth_connections(AmDynInvoke* radius_interface);
    int init_radius_acc_connections(AmDynInvoke* radius_interface);
};
