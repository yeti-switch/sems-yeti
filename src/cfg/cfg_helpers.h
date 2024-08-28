#pragma once

#include "confuse.h"
#include "AmConfigReader.h"
#include "AmUtils.h"

#include <string>

bool add2hash(
    cfg_t *c,
    std::string key,std::string cfg_key,
    AmConfigReader &out);

void apply_db_cfg(
    cfg_t *c,std::string prefix,
    AmConfigReader &out);

void apply_pool_cfg(
    cfg_t *c,std::string prefix,
    AmConfigReader &out);
