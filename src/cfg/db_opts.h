#pragma once

#include "confuse.h"
#include "opts_helpers.h"

#define db_opts \
	DCFG_INT(port), \
	DCFG_STR(host), \
	DCFG_STR(name), \
	DCFG_STR(user), \
	DCFG_STR(pass)
