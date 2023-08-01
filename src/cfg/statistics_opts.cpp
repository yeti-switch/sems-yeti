#include "statistics_opts.h"
#include "opts_helpers.h"

#define SNAPSHOTS_PERIOD_DEFAULT 60

char section_name_active_calls[] = "active-calls";
char section_name_clickhouse[] = "clickhouse";

char opt_name_table[] = "table";
char opt_name_destinations[] = "destinations";
char opt_name_buffering[] = "buffering";
char opt_name_allowed_fields[] = "allowed_fields";
char opt_name_period[] = "period";

cfg_opt_t sig_yeti_statistics_acive_calls_clickhouse_opts[] = {
    CFG_STR(opt_name_table, "active_calls", CFGF_NONE),
    CFG_STR(opt_name_destinations, NULL, CFGF_LIST),
    CFG_BOOL(opt_name_buffering, cfg_false, CFGF_NONE),
    CFG_STR(opt_name_allowed_fields, NULL, CFGF_LIST),
    CFG_END()
};

cfg_opt_t sig_yeti_statistics_acive_calls_opts[] = {
    CFG_INT(opt_name_period, SNAPSHOTS_PERIOD_DEFAULT, CFGF_NONE),
    CFG_SEC(section_name_clickhouse,
            sig_yeti_statistics_acive_calls_clickhouse_opts,CFGF_NONE),
    CFG_END()
};

cfg_opt_t sig_yeti_statistics_opts[] = {
    CFG_SEC(section_name_active_calls,
            sig_yeti_statistics_acive_calls_opts,CFGF_NONE),
    CFG_END()
};
