#pragma once

#include "confuse.h"
#include "opts_helpers.h"

#define redis_pool_opts \
	DCFG_STR(host), \
	DCFG_INT(port), \
	DCFG_INT(timeout), \
	DCFG_STR(username), \
	DCFG_STR(password)
