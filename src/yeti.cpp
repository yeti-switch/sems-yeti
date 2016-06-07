#include "yeti.h"
#include "sdp_filter.h"

#include <string.h>
#include <ctime>
#include <cstdio>

#include "log.h"
#include "AmPlugIn.h"
#include "AmArg.h"
#include "jsonArg.h"
#include "AmSession.h"
#include "AmUtils.h"
#include "AmAudioFile.h"
#include "AmMediaProcessor.h"
#include "SDPFilter.h"
#include "CallLeg.h"
#include "RegisterDialog.h"
#include "Registration.h"
#include "cdr/TrustedHeaders.h"
#include "SBC.h"
struct CallLegCreator;

#define YETI_CFG_PART "signalling"
#define YETI_CFG_DEFAULT_TIMEOUT 5000

#define YETI_DEFAULT_AUDIO_RECORDER_DIR "/var/spool/sems/record"
#define YETI_DEFAULT_LOG_DIR "/var/spool/sems/logdump"

Yeti* Yeti::_instance=0;

Yeti* Yeti::instance() {
	if(!_instance)
		_instance = new Yeti();
	return _instance;
}

Yeti::Yeti() {
	//DBG("Yeti()");
}


Yeti::~Yeti() {
    DBG("~Yeti()");
	Registration::instance()->stop();
	rctl.stop();
    router.stop();
}


static int check_dir_write_permissions(const string &dir)
{
	ofstream st;
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

bool Yeti::read_config(){
	static const char *mandatory_options[] = {
		"node_id",
		"cfg_urls",
		0
	};

	AmConfigReader ycfg;
	if(ycfg.loadFile(AmConfig::ModConfigPath + string(MOD_NAME ".conf"))) {
		ERROR("No configuration for "MOD_NAME" present (%s)\n",
			(AmConfig::ModConfigPath + string(MOD_NAME ".conf")).c_str());
		return false;
	}

	//check mandatory options
	for(const char **opt = mandatory_options; *opt;opt++){
		if(!ycfg.hasParameter(*opt)){
			ERROR("Missed parameter '%s'",*opt);
			return false;
		}
	}

	vector<string> urls = explode(ycfg.getParameter("cfg_urls"),",");
	for(vector<string>::const_iterator url = urls.begin();
		url != urls.end(); ++url)
	{
		string key = "cfg_url_"+*url;
		if(!ycfg.hasParameter(key)){
			ERROR("'%s' declared in cfg_urls but '%s' paremeter is missed",
				  url->c_str(),key.c_str());
			return false;
		}
		string cfg_url = ycfg.getParameter(key);
		DBG("add config url: %s",cfg_url.c_str());
		cfg.add_url(cfg_url.c_str());
	}

	cfg.set_node_id(config.node_id = ycfg.getParameterInt("node_id"));
	cfg.set_cfg_part(YETI_CFG_PART);
	cfg.set_timeout(ycfg.getParameterInt("cfg_timeout",YETI_CFG_DEFAULT_TIMEOUT));

	try {
		DBG("fetching yeti module cfg");
		cfg.load();
	} catch(yeti::cfg::server_exception &e){
		ERROR("can't load yeti config: %d %s",e.code,e.what());
		return false;
	} catch(std::exception &e){
		ERROR("can't load yeti config: %s",e.what());
		return false;
	}

	if(!cfg.hasParameter("pop_id")){
		ERROR("Missed parameter 'pop_id'");
		return false;
	}
	config.pop_id = cfg.getParameterInt("pop_id");

	if(!cfg.hasParameter("routing_schema")){
		ERROR("Missed parameter 'routing_schema'");
		return false;
	}
	config.routing_schema = cfg.getParameter("routing_schema");
	config.use_radius = cfg.getParameterInt("use_radius",0)==1;
	config.early_100_trying = cfg.getParameterInt("early_100_trying",1)==1;

	if(!cfg.hasParameter("msg_logger_dir")){
		ERROR("Missed parameter 'msg_logger_dir'");
		return false;
	}
	config.msg_logger_dir = cfg.getParameter("msg_logger_dir");
	if(check_dir_write_permissions(config.msg_logger_dir))
		return false;

	config.audio_recorder_dir = cfg.getParameter("audio_recorder_dir",YETI_DEFAULT_AUDIO_RECORDER_DIR);
	if(check_dir_write_permissions(config.audio_recorder_dir))
		return false;
	config.audio_recorder_compress = cfg.getParameterInt("audio_recorder_compress",1)==1;

	config.log_dir = cfg.getParameter("log_dir",YETI_DEFAULT_LOG_DIR);
	if(check_dir_write_permissions(config.log_dir))
		return false;

	return true;
}

int Yeti::onLoad() {
	if(!read_config()){
		return -1;
	}

	calls_show_limit = cfg.getParameterInt("calls_show_limit",100);

	self_iface.cc_module = "yeti";
	self_iface.cc_name = "yeti";
	self_iface.cc_values.clear();

	if(TrustedHeaders::instance()->configure(cfg)){
		ERROR("TrustedHeaders configure failed");
		return -1;
	}

	if (router.configure(cfg)){
		ERROR("SqlRouter confgiure failed");
		return -1;
	}

	if(configure_filter(&router)){
		ERROR("ActiveCallsFilter configure failed");
		return -1;
	}

	if(init_radius_module(cfg)){
		ERROR("radius module configure failed");
		return -1;
	}

	if(rctl.configure(cfg)){
		ERROR("ResourceControl configure failed");
		return -1;
	}
	rctl.start();

	if(CodecsGroups::instance()->configure(cfg)){
		ERROR("CodecsGroups configure failed");
		return -1;
	}

	if (CodesTranslator::instance()->configure(cfg)){
		ERROR("CodesTranslator configure failed");
		return -1;
	}

	if(Sensors::instance()->configure(cfg)){
		ERROR("Sensors configure failed");
		return -1;
	}

	if(router.run()){
		ERROR("SqlRouter start failed");
		return -1;
	}

	if(Registration::instance()->configure(cfg)){
		ERROR("Registration agent configure failed");
		return -1;
	}
	Registration::instance()->start();

	start_time = time(NULL);

	init_rpc_cmds();

	return 0;
}

int Yeti::init_radius_module(AmConfigReader& cfg)
{
	AmArg ret;

	if(!config.use_radius){
		return 0;
	}

	AmDynInvokeFactory* radius_client_factory = AmPlugIn::instance()->getFactory4Di("radius_client");
	if(NULL==radius_client_factory){
		ERROR("radius enabled on management node, but radius_client module is not loaded."
			  " please, check your 'load_plugins' option in sems.conf or disable radius usage on management node");
		return 1;
	}
	AmDynInvoke* radius_client = radius_client_factory->getInstance();
	if(NULL==radius_client){
		ERROR("radius_client module factory error");
		return 1;
	}

	radius_client->invoke("init",AmArg(),ret);
	if(0!=ret.asInt()){
		ERROR("can't init radius client module");
		return 1;
	}

	if(init_radius_auth_connections(radius_client)){
		ERROR("can't init radius auth connections");
		return 1;
	}

	if(init_radius_acc_connections(radius_client)){
		ERROR("can't init radius accounting connections");
		return 1;
	}

	radius_client->invoke("start", AmArg(), ret);
	return 0;
}

int Yeti::init_radius_auth_connections(AmDynInvoke* radius_client)
{
	int rc = 1;
	DBG("load radius profiles from db");
	try {
		DbConfig dbc;
		string prefix("master");
		dbc.cfg2dbcfg(cfg,prefix);

		pqxx::connection c(dbc.conn_str());
		c.set_variable("search_path",config.routing_schema+", public");
		pqxx::nontransaction t(c);

		pqxx::result r = t.exec("SELECT * FROM load_radius_profiles()");

		DBG("got %ld radius auth profiles from db",r.size());

		for(pqxx::result::size_type i = 0; i < r.size();++i){
			AmArg args,ret;
			const pqxx::result::tuple &t = r[i];

			args.push(t["id"].as<int>());
			args.push(t["name"].c_str());
			args.push(t["server"].c_str());
			args.push(t["port"].as<int>());
			args.push(t["secret"].c_str());
			args.push(t["reject_on_error"].as<bool>());
			args.push(t["timeout"].as<int>());
			args.push(t["attempts"].as<int>());
			args.push(AmArg());
			json2arg(t["avps"].c_str(),args.back());

			radius_client->invoke("addAuthConnection", args, ret);
			if(0!=ret.asInt()){
				ERROR("can't add radius auth connection for profile %d",
					  t["id"].as<int>());
				throw std::string("can't add radius auth connection");
			}
		}

		rc = 0;
	} catch(const pqxx::pqxx_exception &e){
		ERROR("got database error during radius module configuration: pqxx_exception: %s ",
			  e.base().what());
	} catch(AmDynInvoke::NotImplemented &e){
		ERROR("got AmDynInvoke error during radius module configuration: %s",
			  e.what.c_str());
	} catch(const string &s){
		ERROR("got exception during radius module configuration: %s",
			  s.c_str());
	} catch(...){
		ERROR("got exception during radius module configuration");
	}
	return rc;
}

int Yeti::init_radius_acc_connections(AmDynInvoke* radius_client)
{
	int rc = 1;
	DBG("load radius profiles from db");
	try {
		DbConfig dbc;
		string prefix("master");
		dbc.cfg2dbcfg(cfg,prefix);

		pqxx::connection c(dbc.conn_str());
		c.set_variable("search_path",config.routing_schema+", public");
		pqxx::nontransaction t(c);

		pqxx::result r = t.exec("SELECT * FROM load_radius_accounting_profiles()");

		DBG("got %ld radius accounting profiles from db",r.size());

		for(pqxx::result::size_type i = 0; i < r.size();++i){
			AmArg args,ret;
			const pqxx::result::tuple &t = r[i];

			args.push(t["id"].as<int>());
			args.push(t["name"].c_str());
			args.push(t["server"].c_str());
			args.push(t["port"].as<int>());
			args.push(t["secret"].c_str());
			args.push(t["timeout"].as<int>());
			args.push(t["attempts"].as<int>());

			args.push(AmArg());
			json2arg(t["start_avps"].c_str(),args.back());
			args.push(AmArg());
			json2arg(t["interim_avps"].c_str(),args.back());
			args.push(AmArg());
			json2arg(t["stop_avps"].c_str(),args.back());

			args.push(t["enable_start_accounting"].as<bool>());
			args.push(t["enable_interim_accounting"].as<bool>());
			args.push(t["enable_stop_accounting"].as<bool>());
			args.push(t["interim_accounting_interval"].as<int>());

			radius_client->invoke("addAccConnection", args, ret);
			if(0!=ret.asInt()){
				ERROR("can't add radius acc connection for profile %d",
					  t["id"].as<int>());
				throw std::string("can't add radius acc connection");
			}
		}

		rc = 0;
	} catch(const pqxx::pqxx_exception &e){
		ERROR("got database error during radius module configuration: pqxx_exception: %s ",
			  e.base().what());
	} catch(AmDynInvoke::NotImplemented &e){
		ERROR("got AmDynInvoke error during radius module configuration: %s",
			  e.what.c_str());
	} catch(const string &s){
		ERROR("got exception during radius module configuration: %s",
			  s.c_str());
	} catch(...){
		ERROR("got exception during radius module configuration");
	}
	return rc;
}
