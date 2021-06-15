#include "YetiCfg.h"

#include "sip/resolver.h"
#include "log.h"

#include "yeti_opts.h"
#include "cfg_helpers.h"

#define LOG_BUF_SIZE 2048

cdr_headers_t cfg_aleg_cdr_headers;
cdr_headers_t cfg_bleg_reply_cdr_headers;

int add_aleg_cdr_header(cfg_t */*cfg*/, cfg_opt_t */*opt*/, int argc, const char **argv)
{
    if(argc != 2) {
        ERROR("header(%s,%s): unexpected option args count.\n"
              "expected format: header(header_name, string|array)",
              argv[0],argv[1]);
        return 1;
    }
    if(cfg_aleg_cdr_headers.add_header(argv[0],argv[1])) {
        return 1;
    }
    return 0;
}

int add_bleg_reply_cdr_header(cfg_t */*cfg*/, cfg_opt_t */*opt*/, int argc, const char **argv)
{
    if(argc != 2) {
        ERROR("header(%s,%s): unexpected option args count.\n"
              "expected format: header(header_name, string|array)",
              argv[0],argv[1]);
        return 1;
    }
    if(cfg_bleg_reply_cdr_headers.add_header(argv[0],argv[1])) {
        return 1;
    }
    return 0;
}

int YetiCfg::configure(cfg_t *cfg, AmConfigReader &am_cfg)
{
    core_options_handling = cfg_getbool(cfg, opt_name_core_options_handling);
    pcap_memory_logger = cfg_getbool(cfg, opt_name_pcap_memory_logger);
    auth_feedback = cfg_getbool(cfg, opt_name_auth_feedback);
    http_events_destination = cfg_getstr(cfg, opt_name_http_events_destination);
    aleg_cdr_headers = cfg_aleg_cdr_headers;
    bleg_reply_cdr_headers = cfg_bleg_reply_cdr_headers;

    serialize_to_amconfig(cfg, am_cfg);

    return 0;
}

void YetiCfg::serialize_to_amconfig(cfg_t *y, AmConfigReader &out)
{
	cfg_t *c;

	add2hash(y,"pop_id","pop_id",out);
	add2hash(y,"msg_logger_dir","msg_logger_dir",out);
	add2hash(y,"audio_recorder_dir","audio_recorder_dir",out);
	add2hash(y,"audio_recorder_compress","audio_recorder_compress",out);
	add2hash(y,"log_dir","log_dir",out);
		//routing
		cfg_t *r = cfg_getsec(y,"routing");
		add2hash(r,"routing_schema","schema",out);
		add2hash(r,"routing_function","function",out);
		add2hash(r,"routing_init_function","init",out);
		add2hash(r,"failover_to_slave","failover_to_slave",out);
			//master pool
			apply_pool_cfg(cfg_getsec(r,"master_pool"),"master_",out);
			//slave pool
			apply_pool_cfg(cfg_getsec(r,"slave_pool"),"slave_",out);
			//cache
			c = cfg_getsec(r,"cache");
			add2hash(c,"profiles_cache_enabled","enabled",out);
			add2hash(c,"profiles_cache_check_interval","check_interval",out);
			add2hash(c,"profiles_cache_buckets","buckets",out);

		//cdr
		c = cfg_getsec(y,"cdr");
		add2hash(c,"cdr_failover_to_slave","failover_to_slave",out);
		add2hash(c,"failover_to_file","failover_to_file",out);
		add2hash(c,"failover_requeue","failover_requeue",out);
		add2hash(c,"serialize_dynamic_fields","serialize_dynamic_fields",out);
		add2hash(c,"cdr_pool_size","pool_size",out);
		add2hash(c,"cdr_dir","dir",out);
		add2hash(c,"writecdr_schema","schema",out);
		add2hash(c,"writecdr_function","function",out);
		add2hash(c,"cdr_check_interval","check_interval",out);
		add2hash(c,"cdr_batch_timeout","batch_timeout",out);
		add2hash(c,"cdr_batch_size","batch_size",out);
			//master
			apply_db_cfg(cfg_getsec(c,"master"),"mastercdr_",out);
			//slave
			apply_db_cfg(cfg_getsec(c,"slave"),"slavecdr_",out);

		//resources
		c = cfg_getsec(y,"resources");
		add2hash(c,"reject_on_cache_error","reject_on_error",out);
			//write
			apply_redis_pool_cfg(cfg_getsec(c,"write"),"write_redis_",out);
			//read
			apply_redis_pool_cfg(cfg_getsec(c,"read"),"read_redis_",out);

		//registrations
		c = cfg_getsec(y,"registrations");
		add2hash(c,"reg_check_interval","check_interval",out);

		//registrar
		c = cfg_getsec(y,"registrar");
		add2hash(c,"registrar_enabled","enabled",out);
		add2hash(c,"registrar_expires_min","expires_min",out);
		add2hash(c,"registrar_expires_max","expires_max",out);
			c = cfg_getsec(c, "redis");
			add2hash(c,"registrar_redis_host","host",out);
			add2hash(c,"registrar_redis_port","port",out);

		//rpc
		c = cfg_getsec(y,"rpc");
		add2hash(c,"calls_show_limit","calls_show_limit",out);

		//statistics
		c = cfg_getsec(y,"statistics");
			c = cfg_getsec(c,"active-calls");
			add2hash(c,"active_calls_period","period",out);
				c = cfg_getsec(c,"clickhouse");
				add2hash(c,"active_calls_clickhouse_table","table",out);
				add2hash(c,"active_calls_clickhouse_queue","queue",out);
				add2hash(c,"active_calls_clickhouse_buffering","buffering",out);
				add2hash(c,"active_calls_clickhouse_allowed_fields","allowed_fields",out);

		//auth
		c = cfg_getsec(y,"auth");
			add2hash(c,"auth_realm","realm",out);
}
