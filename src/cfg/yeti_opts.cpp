#include "yeti_opts.h"

#include "db_opts.h"
#include "statistics_opts.h"
#include "opts_helpers.h"

#define YETI_CFG_DEFAULT_SCRIPTS_DIR "/usr/lib/sems/scripts/yeti"

#define YETI_SCTP_DEFAULT_HOST "127.0.0.1"
#define YETI_SCTP_DEFAULT_PORT 4444

#define IP_AUTH_DEFAULT_HEADER "X-ORIG-IP"
#define YETI_DEFAULT_AUDIO_RECORDER_DIR "/var/spool/sems/record"

char opt_name_auth_feedback[] = "enable_auth_feedback";
char opt_name_http_events_destination[] = "http_events_destination";

char section_name_routing[] = "routing";
char section_name_cdr[] = "cdr";
char section_name_auth[] = "auth";
char section_name_lega_cdr_headers[] = "lega_cdr_headers";
char section_name_legb_reply_cdr_headers[] = "legb_response_cdr_headers";
char section_name_identity[] = "identity";
char section_name_statistics[] = "statistics";
char section_name_resources[] = "resources";
char section_name_redis[] = "redis";
char section_name_redis_write[] = "write";
char section_name_redis_read[] = "read";
char section_name_headers[] = "headers";

char opt_name_core_options_handling[] = "core_options_handling";
char opt_name_pcap_memory_logger[] = "pcap_memory_logger";
char opt_name_db_refresh_interval[] = "db_refresh_interval";
char opt_name_ip_auth_reject_if_no_matched[] = "ip_auth_reject_if_no_matched";
char opt_name_ip_auth_header[] = "ip_auth_header";
char opt_name_postgresql_debug[] = "postgresql_debug";
char opt_name_write_internal_disconnect_code[] = "write_internal_disconnect_code";
char opt_name_connection_lifetime[] = "connection_lifetime";
char opt_name_pass_input_interface_name[] = "pass_input_interface_name";
char opt_name_new_codec_groups[] = "new_codec_groups";
char opt_name_audio_recorder_dir[] = "audio_recorder_dir";
char opt_name_audio_recorder_compress[] = "audio_recorder_compress";
char opt_name_audio_recorder_http_destination[] = "audio_recorder_http_destination";

char opt_name_auth_realm[] = "realm";
char opt_name_auth_skip_logging_invite_challenge[] = "skip_logging_invite_challenge";
char opt_name_auth_skip_logging_invite_success[] = "skip_logging_invite_success";
char opt_name_auth_jwt_public_key[] = "jwt_public_key";

char opt_identity_expires[] = "expires";
char opt_identity_http_destination[] = "http_destination";
char opt_identity_certs_cache_ttl[] = "certs_cache_ttl";
char opt_identity_certs_cache_failed_ttl[] = "certs_cache_failed_ttl";
char opt_identity_certs_cache_failed_verify_ttl[] = "certs_cache_failed_verify_ttl";

char opt_func_name_header[] = "header";
char opt_name_cdr_headers_add_sip_reason[] = "add_sip_reason";
char opt_name_cdr_headers_add_q850_reason[] = "add_q850_reason";

char opt_resources_reduce_operations[] = "reduce_operations";
char opt_resources_scripts_dir[] = "scripts_dir";
char opt_resources_reject_on_error[] = "reject_on_error";

char opt_redis_hosts[] = "hosts";
char opt_redis_timeout[] = "timeout";
char opt_redis_username[] = "username";
char opt_redis_password[] = "password";

int add_routing_header(cfg_t *cfg, cfg_opt_t *opt, int argc, const char **argv);
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

cfg_opt_t routing_headers_opts[] = {
    CFG_FUNC(opt_func_name_header, add_routing_header),
    CFG_END()
};

cfg_opt_t sig_yeti_routing_opts[] = {
	DCFG_STR(schema),
	DCFG_STR(function),
	DCFG_STR(init),
	DCFG_BOOL(failover_to_slave),
	CFG_BOOL(opt_name_pass_input_interface_name, cfg_false, CFGF_NONE),
	CFG_BOOL(opt_name_new_codec_groups, cfg_false, CFGF_NONE),
	CFG_INT(opt_name_connection_lifetime,0,CFGF_NONE),
	DCFG_SEC(master_pool,sig_yeti_routing_pool_opts,CFGF_NONE),
	DCFG_SEC(slave_pool,sig_yeti_routing_pool_opts,CFGF_NONE),
	CFG_SEC(section_name_headers, routing_headers_opts, CFGF_NONE),
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
	CFG_INT(opt_name_connection_lifetime,0,CFGF_NONE),
	DCFG_STR(dir),
	DCFG_STR(completed_dir),
	DCFG_STR(schema),
	DCFG_STR(function),
	DCFG_SEC(master,sig_yeti_cdr_db_opts,CFGF_NONE),
	DCFG_SEC(slave,sig_yeti_cdr_db_opts,CFGF_NONE),
	CFG_END()
};

//resources
cfg_opt_t sig_yeti_redis_pool_opts[] = {
	CFG_STR_LIST(opt_redis_hosts, 0, CFGF_NODEFAULT),
	CFG_INT(opt_redis_timeout, YETI_REDIS_DEFAULT_TIMEOUT , CFGF_NONE),
	CFG_STR(opt_redis_username, "", CFGF_NONE),
	CFG_STR(opt_redis_password, "", CFGF_NONE),
	CFG_END()
};

cfg_opt_t sig_yeti_resources_opts[] = {
	CFG_BOOL(opt_resources_reject_on_error, cfg_false, CFGF_NONE),
	CFG_BOOL(opt_resources_reduce_operations, cfg_false, CFGF_NONE),
	CFG_STR(opt_resources_scripts_dir, YETI_CFG_DEFAULT_SCRIPTS_DIR, CFGF_NONE),
	DCFG_SEC(write,sig_yeti_redis_pool_opts,CFGF_NONE),
	DCFG_SEC(read,sig_yeti_redis_pool_opts,CFGF_NONE),
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

//auth
cfg_opt_t sig_yeti_auth_opts[] = {
    CFG_STR(opt_name_auth_realm, NULL, CFGF_NODEFAULT),
    CFG_STR(opt_name_auth_jwt_public_key, NULL, CFGF_NODEFAULT),
    CFG_BOOL(opt_name_auth_skip_logging_invite_challenge, cfg_false, CFGF_NODEFAULT),
    CFG_BOOL(opt_name_auth_skip_logging_invite_success, cfg_false, CFGF_NODEFAULT),
    CFG_END()
};

cfg_opt_t lega_cdr_headers_opts[] = {
    CFG_FUNC(opt_func_name_header, add_aleg_cdr_header),
    CFG_BOOL(opt_name_cdr_headers_add_sip_reason, cfg_false, CFGF_NONE),
    CFG_BOOL(opt_name_cdr_headers_add_q850_reason, cfg_false, CFGF_NONE),
    CFG_END()
};

cfg_opt_t legb_reply_cdr_headers_opts[] = {
    CFG_FUNC(opt_func_name_header, add_bleg_reply_cdr_header),
    CFG_BOOL(opt_name_cdr_headers_add_sip_reason, cfg_false, CFGF_NONE),
    CFG_BOOL(opt_name_cdr_headers_add_q850_reason, cfg_false, CFGF_NONE),
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
    CFG_STR(opt_name_audio_recorder_dir, YETI_DEFAULT_AUDIO_RECORDER_DIR, CFGF_NONE),
    CFG_STR(opt_name_audio_recorder_http_destination, "", CFGF_NONE),
    CFG_BOOL(opt_name_audio_recorder_compress, cfg_true, CFGF_NONE),
    CFG_SEC(section_name_routing, sig_yeti_routing_opts, CFGF_NONE),
    CFG_SEC(section_name_cdr, sig_yeti_cdr_opts, CFGF_NONE),
    CFG_SEC(section_name_resources, sig_yeti_resources_opts, CFGF_NONE),
    DCFG_SEC(registrations,sig_yeti_reg_opts,CFGF_NONE),
    DCFG_SEC(rpc,sig_yeti_rpc_opts,CFGF_NONE),
    CFG_SEC(section_name_statistics, sig_yeti_statistics_opts, CFGF_NONE),
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
    CFG_BOOL(opt_name_postgresql_debug, cfg_false, CFGF_NONE),
    CFG_BOOL(opt_name_write_internal_disconnect_code, cfg_false, CFGF_NONE),

    CFG_END()
};
