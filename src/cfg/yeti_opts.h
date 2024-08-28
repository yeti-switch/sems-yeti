#pragma once

#include "confuse.h"

#define YETI_REDIS_DEFAULT_TIMEOUT 5000

#define YETI_SCTP_DEFAULT_HOST "127.0.0.1"
#define YETI_SCTP_DEFAULT_PORT 4444

extern char opt_name_auth_feedback[];
extern char opt_name_http_events_destination[];

extern char section_name_routing[];
extern char section_name_cdr[];
extern char section_name_auth[];
extern char section_name_lega_cdr_headers[];
extern char section_name_legb_reply_cdr_headers[];
extern char section_name_identity[];
extern char section_name_statistics[];
extern char section_name_registrar[];
extern char section_name_resources[];
extern char section_name_redis[];
extern char section_name_redis_write[];
extern char section_name_redis_read[];

extern char opt_name_core_options_handling[];
extern char opt_name_pcap_memory_logger[];
extern char opt_name_db_refresh_interval[];
extern char opt_name_ip_auth_reject_if_no_matched[];
extern char opt_name_ip_auth_header[];
extern char opt_name_postgresql_debug[];
extern char opt_name_write_internal_disconnect_code[];
extern char opt_name_connection_lifetime[];
extern char opt_name_pass_input_interface_name[];
extern char opt_name_audio_recorder_dir[];
extern char opt_name_audio_recorder_compress[];
extern char opt_name_audio_recorder_http_destination[];

extern char opt_identity_expires[];
extern char opt_identity_http_destination[];
extern char opt_identity_certs_cache_ttl[];
extern char opt_identity_certs_cache_failed_ttl[];
extern char opt_identity_certs_cache_failed_verify_ttl[];

extern char opt_func_name_header[];
extern char opt_name_cdr_headers_add_sip_reason[];
extern char opt_name_cdr_headers_add_q850_reason[];

extern char opt_registrar_keepalive_interval[];

extern char opt_resources_reduce_operations[];
extern char opt_resources_scripts_dir[];
extern char opt_resources_reject_on_error[];

extern char opt_redis_hosts[];
extern char opt_redis_timeout[];
extern char opt_redis_username[];
extern char opt_redis_password[];

//routing
extern cfg_opt_t sig_yeti_routing_pool_opts[];
extern cfg_opt_t sig_yeti_routing_cache_opts[];
extern cfg_opt_t sig_yeti_routing_opts[];

//cdr
extern cfg_opt_t sig_yeti_cdr_db_opts[];
extern cfg_opt_t sig_yeti_cdr_opts[];

//resources
extern cfg_opt_t sig_yeti_resources_opts[];

//redis
extern cfg_opt_t sig_yeti_redis_pool_opts[];

//rpc
extern cfg_opt_t sig_yeti_rpc_opts[];

//registrations
extern cfg_opt_t sig_yeti_reg_opts[];

//auth
extern cfg_opt_t sig_yeti_auth_opts[];
extern cfg_opt_t lega_cdr_headers_opts[];

//identity
extern cfg_opt_t identity_opts[];

//yeti
extern cfg_opt_t yeti_opts[];
