#pragma once

#include "ampi/RadiusClientAPI.h"
#include "AmConfigReader.h"

#include "yeti_base.h"

class YetiRadius : virtual YetiBase {
    AmDynInvoke *radius_client;

  protected:
    YetiRadius() {}

    int  init_radius_module();
    void load_radius_auth_connections(const AmArg &data);
    void load_radius_acc_connections(const AmArg &data);
    void radius_invoke(const string &method, const AmArg &args, AmArg &ret);
};
