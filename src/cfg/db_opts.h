#pragma once

#include "confuse.h"
#include "opts_helpers.h"

#define db_opts \
    DCFG_STR(host), \
    DCFG_INT(port), \
    DCFG_STR(name), \
    DCFG_STR(user), \
    DCFG_STR(pass), \
    DCFG_INT(keepalives_interval)
