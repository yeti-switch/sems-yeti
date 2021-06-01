#pragma once

/*#include "db_opts.h"
#include "redis_opts.h"
#include "statistics_opts.h"*/
//#include "opts_helpers.h"
#include "confuse.h"

#define YETI_CFG_DEFAULT_TIMEOUT 5000

#define YETI_SCTP_DEFAULT_HOST "127.0.0.1"
#define YETI_SCTP_DEFAULT_PORT 4444

extern char opt_name_auth_feedback[];
extern char opt_name_http_events_destination[];

extern char section_name_lega_cdr_headers[];
extern char section_name_identity[];

extern char opt_name_core_options_handling[];
extern char opt_name_pcap_memory_logger[];

extern char opt_identity_expires[];
extern char opt_identity_http_destination[];
extern char opt_identity_certs_cache_ttl[];

extern char opt_func_name_header[];

//extern int add_aleg_cdr_header(cfg_t *cfg, cfg_opt_t *opt, int argc, const char **argv);

//routing
extern cfg_opt_t sig_yeti_routing_pool_opts[];
extern cfg_opt_t sig_yeti_routing_cache_opts[];
extern cfg_opt_t sig_yeti_routing_opts[];

//cdr
extern cfg_opt_t sig_yeti_cdr_db_opts[];
extern cfg_opt_t sig_yeti_cdr_opts[];

//resources
extern cfg_opt_t sig_yeti_resources_pool_opts[];
extern cfg_opt_t sig_yeti_resources_opts[];

//rpc
extern cfg_opt_t sig_yeti_rpc_opts[];

//registrations
extern cfg_opt_t sig_yeti_reg_opts[];

//registrar
extern cfg_opt_t sig_yeti_registrar_redis_opts[];
extern cfg_opt_t sig_yeti_registrar_opts[];

//auth
extern cfg_opt_t sig_yeti_auth_opts[];
extern cfg_opt_t lega_cdr_headers_opts[];

//identity
extern cfg_opt_t identity_opts[];

//yeti
extern cfg_opt_t yeti_opts[];
