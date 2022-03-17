#include "yeti_opts.h"

#include "db_opts.h"
#include "redis_opts.h"
#include "statistics_opts.h"
#include "opts_helpers.h"

#define YETI_CFG_DEFAULT_TIMEOUT 5000

#define YETI_SCTP_DEFAULT_HOST "127.0.0.1"
#define YETI_SCTP_DEFAULT_PORT 4444

#define IP_AUTH_DEFAULT_HEADER "X-ORIG-IP"

char opt_name_auth_feedback[] = "enable_auth_feedback";
char opt_name_http_events_destination[] = "http_events_destination";

char section_name_lega_cdr_headers[] = "lega_cdr_headers";
char section_name_legb_reply_cdr_headers[] = "legb_response_cdr_headers";
char section_name_identity[] = "identity";

char opt_name_core_options_handling[] = "core_options_handling";
char opt_name_pcap_memory_logger[] = "pcap_memory_logger";
char opt_name_db_refresh_interval[] = "db_refresh_interval";
char opt_name_ip_auth_reject_if_no_matched[] = "ip_auth_reject_if_no_matched";
char opt_name_ip_auth_header[] = "ip_auth_header";

char opt_identity_expires[] = "expires";
char opt_identity_http_destination[] = "http_destination";
char opt_identity_certs_cache_ttl[] = "certs_cache_ttl";
char opt_identity_certs_cache_failed_ttl[] = "certs_cache_failed_ttl";
char opt_identity_certs_cache_failed_verify_ttl[] = "certs_cache_failed_verify_ttl";

char opt_func_name_header[] = "header";

int add_aleg_cdr_header(cfg_t *cfg, cfg_opt_t *opt, int argc, const char **argv);
int add_bleg_reply_cdr_header(cfg_t *cfg, cfg_opt_t *opt, int argc, const char **argv);

//routing
cfg_opt_t sig_yeti_routing_pool_opts[] = {
	db_opts,
	DCFG_INT(size),
	DCFG_INT(check_interval),
	DCFG_INT(max_exceptions),
	DCFG_INT(statement_timeout),
	CFG_END()
};

cfg_opt_t sig_yeti_routing_opts[] = {
	DCFG_STR(schema),
	DCFG_STR(function),
	DCFG_STR(init),
	DCFG_BOOL(failover_to_slave),
	DCFG_SEC(master_pool,sig_yeti_routing_pool_opts,CFGF_NONE),
	DCFG_SEC(slave_pool,sig_yeti_routing_pool_opts,CFGF_NONE),
	CFG_END()
};


//cdr
cfg_opt_t sig_yeti_cdr_db_opts[] = {
	db_opts,
	CFG_END()
};

cfg_opt_t sig_yeti_cdr_opts[] = {
	DCFG_BOOL(failover_to_slave),
	DCFG_BOOL(failover_to_file),
	DCFG_BOOL(failover_requeue),
	DCFG_BOOL(serialize_dynamic_fields),
	DCFG_INT(pool_size),
	DCFG_INT(auth_pool_size),
	DCFG_INT(check_interval),
	DCFG_INT(batch_size),
	DCFG_INT(auth_batch_size),
	DCFG_INT(batch_timeout),
	DCFG_INT(auth_batch_timeout),
	DCFG_STR(dir),
	DCFG_STR(completed_dir),
	DCFG_STR(schema),
	DCFG_STR(function),
	DCFG_SEC(master,sig_yeti_cdr_db_opts,CFGF_NONE),
	DCFG_SEC(slave,sig_yeti_cdr_db_opts,CFGF_NONE),
	CFG_END()
};

//resources
cfg_opt_t sig_yeti_resources_pool_opts[] = {
	redis_pool_opts,
	CFG_END()
};

cfg_opt_t sig_yeti_resources_opts[] = {
	DCFG_BOOL(reject_on_error),
	DCFG_SEC(write,sig_yeti_resources_pool_opts,CFGF_NONE),
	DCFG_SEC(read,sig_yeti_resources_pool_opts,CFGF_NONE),
	CFG_END()
};

//rpc
cfg_opt_t sig_yeti_rpc_opts[] = {
	DCFG_INT(calls_show_limit),
	CFG_END()
};

//registrations
cfg_opt_t sig_yeti_reg_opts[] = {
	DCFG_INT(check_interval),
	CFG_END()
};

//registrar

cfg_opt_t sig_yeti_registrar_redis_opts[] = {
    DCFG_STR(host),
    DCFG_INT(port),
    CFG_END()
};

cfg_opt_t sig_yeti_registrar_opts[] = {
    DCFG_BOOL(enabled),
    DCFG_INT(expires_min),
    DCFG_INT(expires_max),
    DCFG_INT(expires_default),
    DCFG_SEC(redis,sig_yeti_registrar_redis_opts,CFGF_NONE),
    CFG_END()
};

//auth
cfg_opt_t sig_yeti_auth_opts[] = {
    DCFG_STR(realm),
    CFG_END()
};

cfg_opt_t lega_cdr_headers_opts[] = {
    CFG_FUNC(opt_func_name_header, add_aleg_cdr_header),
    CFG_END()
};

cfg_opt_t legb_reply_cdr_headers_opts[] = {
    CFG_FUNC(opt_func_name_header, add_bleg_reply_cdr_header),
    CFG_END()
};

cfg_opt_t identity_opts[] {
    CFG_INT(opt_identity_expires, 60,CFGF_NONE),
    CFG_STR(opt_identity_http_destination,0,CFGF_NODEFAULT),
    CFG_INT(opt_identity_certs_cache_ttl, 86400,CFGF_NONE),
    CFG_INT(opt_identity_certs_cache_failed_ttl, 86400,CFGF_NONE),
    CFG_INT(opt_identity_certs_cache_failed_verify_ttl, 86400,CFGF_NONE),
    CFG_END()
};

//yeti
cfg_opt_t yeti_opts[] = {
    DCFG_INT(pop_id),
    DCFG_STR(msg_logger_dir),
    DCFG_STR(audio_recorder_dir),
    DCFG_BOOL(audio_recorder_compress),
    DCFG_SEC(routing,sig_yeti_routing_opts,CFGF_NONE),
    DCFG_SEC(cdr,sig_yeti_cdr_opts,CFGF_NONE),
    DCFG_SEC(resources,sig_yeti_resources_opts,CFGF_NONE),
    DCFG_SEC(registrations,sig_yeti_reg_opts,CFGF_NONE),
    DCFG_SEC(registrar,sig_yeti_registrar_opts,CFGF_NONE),
    DCFG_SEC(rpc,sig_yeti_rpc_opts,CFGF_NONE),
    DCFG_SEC(statistics,sig_yeti_statistics_opts,CFGF_NONE),
    DCFG_SEC(auth,sig_yeti_auth_opts,CFGF_NONE),
    CFG_SEC(section_name_identity, identity_opts, CFGF_NODEFAULT),
    CFG_SEC(section_name_lega_cdr_headers,lega_cdr_headers_opts, CFGF_NONE),
    CFG_SEC(section_name_legb_reply_cdr_headers,legb_reply_cdr_headers_opts, CFGF_NONE),
    CFG_BOOL(opt_name_core_options_handling, cfg_true, CFGF_NONE),
    CFG_BOOL(opt_name_pcap_memory_logger, cfg_false, CFGF_NONE),
    CFG_INT(opt_name_db_refresh_interval, 300 /* 5 min */,CFGF_NONE),
    CFG_BOOL(opt_name_ip_auth_reject_if_no_matched, cfg_false, CFGF_NONE),
    CFG_BOOL(opt_name_auth_feedback, cfg_false, CFGF_NONE),
    CFG_STR(opt_name_http_events_destination,"",CFGF_NONE),
    CFG_STR(opt_name_ip_auth_header,IP_AUTH_DEFAULT_HEADER,CFGF_NONE),

    CFG_END()
};
