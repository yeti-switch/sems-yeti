#include "sems.h"
#include "CdrWriter.h"
#include "log.h"
#include "AmThread.h"
#include "../yeti.h"
#include "../cfg/yeti_opts.h"
#include "../alarms.h"
#include "yeti_version.h"
#include "AuthCdr.h"
#include "AmUtils.h"

#define DISABLE_CDRS_WRITING

// affect on precision check_interval and batch_timeout handling precision
#define QUEUE_RUN_TIMEOUT_MSEC      1000
#define DEFAULT_CHECK_INTERVAL_MSEC 5000
#define DEFAULT_BATCH_SIZE          50
#define DEFAULT_BATCH_TIMEOUT_MSEC  10000

static_field cdr_static_fields[] = {
    {                      "is_master",  "boolean" },
    {                        "node_id",  "integer" },
    {                         "pop_id",  "integer" },
    {                    "attempt_num",  "integer" },
    {                        "is_last",  "boolean" },
    {     "legA_transport_protocol_id", "smallint" },
    {                  "legA_local_ip",     "inet" },
    {                "legA_local_port",  "integer" },
    {                 "legA_remote_ip",     "inet" },
    {               "legA_remote_port",  "integer" },
    {     "legB_transport_protocol_id", "smallint" },
    {                  "legB_local_ip",     "inet" },
    {                "legB_local_port",  "integer" },
    {                 "legB_remote_ip",     "inet" },
    {               "legB_remote_port",  "integer" },
    {                      "legb_ruri",  "varchar" },
    {            "legb_outbound_proxy",  "varchar" },
    {                      "time_data",     "json" }, //  timers values serialized to json
    {            "early_media_present",  "boolean" },
    {                "disconnect_code",  "integer" },
    {              "disconnect_reason",  "varchar" },
    {           "disconnect_initiator",  "integer" },
    {   "disconnect_intermediate_code",  "integer" },
    { "disconnect_intermediate_reason",  "varchar" },
    {       "disconnect_rewrited_code",  "integer" },
    {     "disconnect_rewrited_reason",  "varchar" },
    {                   "orig_call_id",  "varchar" },
    {                   "term_call_id",  "varchar" },
    {                      "local_tag",  "varchar" },
    {                 "bleg_local_tag",  "varchar" },
    {                "msg_logger_path",  "varchar" },
    {                  "dump_level_id", "smallint" },
    {           "audio_record_enabled",  "boolean" },
    {                      "rtp_stats",     "json" }, //  stats variables serialized to json
    {                    "media_stats",     "json" }, //  media stats serialized to json
    {                     "global_tag",  "varchar" },
    {                      "resources",  "varchar" },
    {               "active_resources",     "json" },
    {        "failed_resource_type_id", "smallint" },
    {             "failed_resource_id",   "bigint" },
    {                    "dtmf_events",     "json" },
    {                       "versions",     "json" },
    {                  "is_redirected",  "boolean" },
    {               "i_dynamic_fields",     "json" },
    {             "i_aleg_cdr_headers",     "json" },
    {    "i_bleg_response_cdr_headers",     "json" },
    {                "i_lega_identity",     "json" },
    /* space to optionally add
     * { "disconnect_code", "smallint" }
     * at the index 26. see: SqlRouter::configure() */
    {                          nullptr,    nullptr },
    /* space to optionally add
     * { "i_bleg_cdr_headers", "json" }
     * after i_aleg_cdr_headers. see: SqlRouter::configure() */
    {                          nullptr,    nullptr }
};

int CdrThreadCfg::cfg2CdrThCfg(cfg_t *cdr_sec, AmConfigReader &cfg)
{

    pool_size           = cfg.getParameterInt("cdr_pool_size", 10);
    check_interval      = cfg.getParameterInt("cdr_check_interval", DEFAULT_CHECK_INTERVAL_MSEC) / 1000;
    retry_interval      = check_interval;
    batch_timeout       = cfg.getParameterInt("cdr_batch_timeout", DEFAULT_BATCH_TIMEOUT_MSEC) / 1000;
    batch_size          = cfg.getParameterInt("cdr_batch_size", DEFAULT_BATCH_SIZE);
    failover_to_slave   = cfg.getParameterInt("cdr_failover_to_slave", 1);
    connection_lifetime = cfg_getint(cdr_sec, opt_name_connection_lifetime);

    masterdb.cfg2dbcfg(cfg, "mastercdr");
    slavedb.cfg2dbcfg(cfg, "slavecdr");

    return 0;
}
