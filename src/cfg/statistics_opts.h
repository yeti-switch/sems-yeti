#pragma once

#include <confuse.h>
#include "opts_helpers.h"

cfg_opt_t sig_yeti_statistics_acive_calls_clickhouse_opts[] = {
	DCFG_STR(table),
	DCFG_STR(queue),
	DCFG_BOOL(buffering),
	DCFG_STR_LIST(allowed_fields),
	CFG_END()
};

cfg_opt_t sig_yeti_statistics_acive_calls_opts[] = {
	DCFG_INT(period),
	DCFG_SEC(clickhouse,sig_yeti_statistics_acive_calls_clickhouse_opts,CFGF_NONE),
	CFG_END()
};

cfg_opt_t sig_yeti_statistics_opts[] = {
	DCFG_SEC(active-calls,sig_yeti_statistics_acive_calls_opts,CFGF_NONE),
	CFG_END()
};
