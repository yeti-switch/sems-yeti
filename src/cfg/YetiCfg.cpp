#include "YetiCfg.h"
#include "ampi/PostgreSqlAPI.h"
#include "AmLcConfig.h"

#include "sip/resolver.h"
#include "log.h"

#include "yeti_opts.h"
#include "cfg_helpers.h"

#include <fstream>

#define LOG_BUF_SIZE 2048

cdr_headers_t cfg_aleg_cdr_headers;
cdr_headers_t cfg_bleg_cdr_headers;
cdr_headers_t cfg_bleg_reply_cdr_headers;

int add_aleg_cdr_header(cfg_t */*cfg*/, cfg_opt_t */*opt*/, int argc, const char **argv)
{
    if(argc != 2 && argc != 4) {
        ERROR(
            "unexpected option args count for header(). "
            "expected formats: "
            "header(header_name, none|string|array|smallint|integer [, active_call_key, String])",
            argv[0],argv[1]);
        return 1;
    }

    if(cfg_aleg_cdr_headers.add_header(argv[0],argv[1])) {
        return 1;
    }

    if(argc == 4) {
        if(cfg_aleg_cdr_headers.add_snapshot_header(
            argv[0], argv[2], argv[3]))
        {
            return 1;
        }
    }

    return 0;
}

int add_bleg_cdr_header(cfg_t */*cfg*/, cfg_opt_t */*opt*/, int argc, const char **argv)
{
    if(argc != 2) {
        ERROR("header(%s,%s): unexpected option args count."
              "expected format: header(header_name, string|array)",
              argv[0],argv[1]);
        return 1;
    }
    if(cfg_bleg_cdr_headers.add_header(argv[0],argv[1])) {
        return 1;
    }
    return 0;
}

int add_bleg_reply_cdr_header(cfg_t */*cfg*/, cfg_opt_t */*opt*/, int argc, const char **argv)
{
    if(argc != 2) {
        ERROR("header(%s,%s): unexpected option args count."
              "expected format: header(header_name, string|array)",
              argv[0],argv[1]);
        return 1;
    }
    if(cfg_bleg_reply_cdr_headers.add_header(argv[0],argv[1])) {
        return 1;
    }
    return 0;
}

static int check_dir_write_permissions(const string &dir)
{
    std::ofstream st;
    string testfile = dir + "/test";
    st.open(testfile.c_str(),std::ofstream::out | std::ofstream::trunc);
    if(!st.is_open()){
        ERROR("can't write test file in '%s' directory",dir.c_str());
        return 1;
    }
    st.close();
    std::remove(testfile.c_str());
    return 0;
}

void YetiCfg::headers_processing_config::leg_reasons::configure(cfg_t *cfg)
{
    add_sip_reason =
        cfg_getbool(cfg, opt_name_cdr_headers_add_sip_reason);

    add_q850_reason =
        cfg_getbool(cfg, opt_name_cdr_headers_add_q850_reason);
}

void YetiCfg::headers_processing_config::configure(cfg_t *cfg)
{
    if(cfg_t* lega_cdr_headers_sec = cfg_getsec(cfg, section_name_lega_cdr_headers))
        aleg.configure(lega_cdr_headers_sec);
    if(cfg_t* legb_cdr_headers_sec = cfg_getsec(cfg, section_name_legb_reply_cdr_headers))
        bleg.configure(legb_cdr_headers_sec);
}

int YetiCfg::configure(cfg_t *cfg, AmConfigReader &am_cfg)
{
    core_options_handling = cfg_getbool(cfg, opt_name_core_options_handling);
    pcap_memory_logger = cfg_getbool(cfg, opt_name_pcap_memory_logger);
    db_refresh_interval = std::chrono::seconds(cfg_getint(cfg, opt_name_db_refresh_interval));
    auth_feedback = cfg_getbool(cfg, opt_name_auth_feedback);
    ip_auth_reject_if_no_matched = cfg_getbool(cfg, opt_name_ip_auth_reject_if_no_matched);
    ip_auth_hdr = cfg_getstr(cfg, opt_name_ip_auth_header);
    http_events_destination = cfg_getstr(cfg, opt_name_http_events_destination);
    postgresql_debug = cfg_getbool(cfg, opt_name_postgresql_debug);
    write_internal_disconnect_code = cfg_getbool(cfg, opt_name_write_internal_disconnect_code);

    for(auto i = 0U; i < cfg_size(cfg, opt_name_supported_tags); ++i)
        supported_tags.push_back(cfg_getnstr(cfg, opt_name_supported_tags, i));

    AmConfig.options_supported_hdr_value = supported_tags;

    for(auto i = 0U; i < cfg_size(cfg, opt_name_allowed_methods); ++i)
        allowed_methods.push_back(cfg_getnstr(cfg, opt_name_allowed_methods, i));

    if(allowed_methods.empty())
        allowed_methods = allowed_methods_default;

    AmConfig.options_allow_hdr_value = allowed_methods;

    aleg_cdr_headers = cfg_aleg_cdr_headers;
    bleg_cdr_headers = cfg_bleg_cdr_headers;
    bleg_reply_cdr_headers = cfg_bleg_reply_cdr_headers;
    headers_processing.configure(cfg);

    serialize_to_amconfig(cfg, am_cfg);

    if(!am_cfg.hasParameter("pop_id")){
        ERROR("Missed parameter 'pop_id'");
        return -1;
    }
    pop_id = static_cast<int>(am_cfg.getParameterInt("pop_id"));

    early_100_trying = am_cfg.getParameterInt("early_100_trying",1)==1;

    if(!am_cfg.hasParameter("msg_logger_dir")){
        ERROR("Missed parameter 'msg_logger_dir'");
        return -1;
    }
    msg_logger_dir = am_cfg.getParameter("msg_logger_dir");
    if(check_dir_write_permissions(msg_logger_dir))
        return -1;

    audio_recorder_dir = cfg_getstr(cfg, opt_name_audio_recorder_dir);
    if(check_dir_write_permissions(audio_recorder_dir))
        return -1;

    audio_recorder_http_destination = cfg_getstr(cfg, opt_name_audio_recorder_http_destination);
    audio_recorder_compress = cfg_getbool(cfg, opt_name_audio_recorder_compress);

    routing_db_master.cfg2dbcfg(am_cfg, "master", true);

    if(!am_cfg.hasParameter("routing_schema")) {
        ERROR("Missed parameter 'routing_schema'");
        return -1;
    }
    routing_schema = am_cfg.getParameter("routing_schema");

    return 0;
}

void YetiCfg::serialize_to_amconfig(cfg_t *y, AmConfigReader &out)
{
	cfg_t *c;

	add2hash(y,"pop_id","pop_id",out);
	add2hash(y,"msg_logger_dir","msg_logger_dir",out);
	add2hash(y,"audio_recorder_dir","audio_recorder_dir",out);
	add2hash(y,"audio_recorder_compress","audio_recorder_compress",out);
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

		//cdr
		c = cfg_getsec(y,"cdr");
		add2hash(c,"cdr_failover_to_slave","failover_to_slave",out);
		add2hash(c,"cdr_pool_size","pool_size",out);
		add2hash(c,"writecdr_schema","schema",out);
		add2hash(c,"writecdr_function","function",out);
		add2hash(c,"cdr_check_interval","check_interval",out);
		add2hash(c,"cdr_batch_timeout","batch_timeout",out);
		add2hash(c,"cdr_batch_size","batch_size",out);
			//master
			apply_db_cfg(cfg_getsec(c,"master"),"mastercdr_",out);
			//slave
			apply_db_cfg(cfg_getsec(c,"slave"),"slavecdr_",out);

		//rpc
		c = cfg_getsec(y,"rpc");
		add2hash(c,"calls_show_limit","calls_show_limit",out);
}
