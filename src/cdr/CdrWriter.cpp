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

//affect on precision check_interval and batch_timeout handling precision
#define QUEUE_RUN_TIMEOUT_MSEC 1000
#define DEFAULT_CHECK_INTERVAL_MSEC 5000
#define DEFAULT_BATCH_SIZE 50
#define DEFAULT_BATCH_TIMEOUT_MSEC 10000

const static_field cdr_static_fields[] = {
	{ "is_master", "boolean" },
	{ "node_id", "integer" },
	{ "pop_id", "integer" },
	{ "attempt_num", "integer" },
	{ "is_last", "boolean" },
	{ "legA_transport_protocol_id", "smallint" },
	{ "legA_local_ip", "inet" },
	{ "legA_local_port", "integer" },
	{ "legA_remote_ip", "inet" },
	{ "legA_remote_port", "integer" },
	{ "legB_transport_protocol_id", "smallint" },
	{ "legB_local_ip", "inet" },
	{ "legB_local_port", "integer" },
	{ "legB_remote_ip", "inet" },
	{ "legB_remote_port", "integer" },
	{ "legb_ruri", "varchar" },
	{ "legb_outbound_proxy", "varchar" },
	{ "time_data", "varchar" }, //timers values serialized to json
	{ "early_media_present", "boolean" },
	{ "disconnect_code", "integer" },
	{ "disconnect_reason", "varchar" },
	{ "disconnect_initiator", "integer" },
	{ "disconnect_intermediate_code", "integer" },
	{ "disconnect_intermediate_reason", "varchar" },
	{ "disconnect_rewrited_code", "integer" },
	{ "disconnect_rewrited_reason", "varchar" },
	{ "orig_call_id", "varchar" },
	{ "term_call_id", "varchar" },
	{ "local_tag", "varchar" },
	{ "bleg_local_tag", "varchar" },
	{ "msg_logger_path", "varchar" },
	{ "dump_level_id", "integer" },
	{ "audio_record_enabled", "boolean"},
	{ "rtp_stats", "json" }, //stats variables serialized to json
	{ "media_stats", "json" }, //media stats serialized to json
	{ "global_tag", "varchar" },
	{ "resources", "varchar" },
	{ "active_resources", "json" },
	{ "failed_resource_type_id", "smallint" },
	{ "failed_resource_id", "bigint" },
	{ "dtmf_events", "json" },
	{ "versions", "json" },
	{ "is_redirected", "boolean" },
	{ "i_dynamic_fields", "json" },
	{ "i_aleg_cdr_headers", "json" },
	{ "i_bleg_response_cdr_headers", "json" },
	{ "i_lega_identity", "json" }
};

int CdrThreadCfg::cfg2CdrThCfg(AmConfigReader& cfg)
{

	pool_size=cfg.getParameterInt("cdr_pool_size",10);
	check_interval = cfg.getParameterInt("cdr_check_interval",DEFAULT_CHECK_INTERVAL_MSEC)/1000;
	retry_interval = check_interval;
	batch_timeout = cfg.getParameterInt("cdr_batch_timeout",DEFAULT_BATCH_TIMEOUT_MSEC)/1000;
	batch_size = cfg.getParameterInt("cdr_batch_size",DEFAULT_BATCH_SIZE);
	failover_to_slave = cfg.getParameterInt("cdr_failover_to_slave",1);

	string cdr_file_dir = "cdr_dir";
	string cdr_file_completed_dir = "cdr_completed_dir";

	failover_requeue = cfg.getParameterInt("failover_requeue",0);

	failover_to_file = cfg.getParameterInt("failover_to_file",1);
	if(failover_to_file){
		if(!cfg.hasParameter(cdr_file_dir)){
			ERROR("missed '%s'' parameter",cdr_file_dir.c_str());
			return -1;
		}
		if(!cfg.hasParameter(cdr_file_completed_dir)){
			ERROR("missed '%s'' parameter",cdr_file_completed_dir.c_str());
			return -1;
		}
		failover_file_dir = cfg.getParameter(cdr_file_dir);
		failover_file_completed_dir = cfg.getParameter(cdr_file_completed_dir);

		//check for permissions
		ofstream t1;
		ostringstream dir_test_file;
		dir_test_file << failover_file_dir << "/test";
		t1.open(dir_test_file.str().c_str(),std::ofstream::out | std::ofstream::trunc);
		if(!t1.is_open()){
			ERROR("can't write test file in '%s' directory",failover_file_dir.c_str());
			return -1;
		}
		remove(dir_test_file.str().c_str());

		ofstream t2;
		ostringstream completed_dir_test_file;
		completed_dir_test_file << failover_file_completed_dir << "/test";
		t2.open(completed_dir_test_file.str().c_str(),std::ofstream::out | std::ofstream::trunc);
		if(!t2.is_open()){
			ERROR("can't write test file in '%s' directory",failover_file_completed_dir.c_str());
			return -1;
		}
		remove(completed_dir_test_file.str().c_str());
	}

	masterdb.cfg2dbcfg(cfg,"mastercdr");
	slavedb.cfg2dbcfg(cfg,"slavecdr");

	return 0;
}
