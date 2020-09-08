#pragma once

#include "confuse.h"
#include "opts_helpers.h"

#define redis_pool_opts \
	DCFG_STR(socket), \
	DCFG_STR(host), \
	DCFG_INT(port), \
	DCFG_INT(size), \
	DCFG_INT(timeout)
