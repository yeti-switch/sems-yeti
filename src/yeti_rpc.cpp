#include "sems.h"
#include "yeti.h"
#include "Registration.h"
#include "codecs_bench.h"
#include "alarms.h"

#include "sip/resolver.h"
#include "sip/transport.h"
#include "AmPlugIn.h"
#include "AmSession.h"

#include <sys/types.h>
#include <signal.h>

#include "AmEventDispatcher.h"
#include "AmAudioFileRecorder.h"

#include "ampi/HttpClientAPI.h"

static const bool RPC_CMD_SUCC = true;

static timeval last_shutdown_time;

typedef void (Yeti::*YetiRpcHandler)(const AmArg& args, AmArg& ret);

#define handler_log() DBG("execute handler: %s(%s)",FUNC_NAME,args.print(args).c_str());

class CdrNotFoundException: public AmSession::Exception {
  public:
	CdrNotFoundException(string local_tag):
		AmSession::Exception(404,"call with local_tag: '"+local_tag+"' is not found") {}
};

struct rpc_entry: public AmObject {
  YetiRpcHandler handler;
  string leaf_descr,func_descr,arg,arg_descr;
  AmArg leaves;

  rpc_entry(string ld):
	  handler(NULL), leaf_descr(ld) {}

  rpc_entry(string ld, YetiRpcHandler h, string fd):
	  leaf_descr(ld), handler(h), func_descr(fd) {}

  rpc_entry(string ld, YetiRpcHandler h, string fd, string a, string ad):
	  leaf_descr(ld), handler(h), func_descr(fd), arg(a), arg_descr(ad) {}

  bool isMethod(){ return handler!=NULL; }
  bool hasLeafs(){ return leaves.getType()==AmArg::Struct; }
  bool hasLeaf(const char *leaf){ return hasLeafs()&&leaves.hasMember(leaf); }
};

void Yeti::init_rpc_cmds(){
#define reg_leaf(parent,leaf,name,descr) \
	e = new rpc_entry(descr);\
	parent[name] = e;\
	AmArg &leaf = e->leaves;

#define reg_method(parent,name,descr,func,func_descr) \
	e = new rpc_entry(descr,&Yeti::func,func_descr);\
	parent[name] = e;

#define reg_leaf_method(parent,leaf,name,descr,func,func_descr) \
	reg_method(parent,name,descr,func,func_descr);\
	AmArg &leaf = e->leaves;

#define reg_method_arg(parent,name,descr,func,func_descr,arg, arg_descr) \
	e = new rpc_entry(descr,&Yeti::func,func_descr,arg, arg_descr);\
	parent[name] = e;

#define reg_leaf_method_arg(parent,leaf,name,descr,func,func_descr,arg, arg_descr) \
	reg_method_arg(parent,name,descr,func,func_descr,arg, arg_descr);\
	AmArg &leaf = e->leaves;

	rpc_entry *e;
	e = new rpc_entry("root");
	rpc_cmds = e->leaves;
	AmArg &root = rpc_cmds;

	timerclear(&last_shutdown_time);

	/* show */
	reg_leaf(root,show,"show","read only queries");

		reg_method(show,"version","show version",showVersion,"");

		reg_leaf(show,show_resource,"resource","resources related functions");

			reg_leaf_method_arg(show_resource,show_resource_state,"state","get resources state from redis",getResourceState,
								"","<type>/-1 <id>/-1","retreive info about certain resources state");

			reg_leaf_method(show_resource_state,show_resource_state_used,"used","show active resources handlers",showResources,"");
			reg_method_arg(show_resource_state_used,"handler","find resource by handler id",showResourceByHandler,"",
						   "<handler_id>","find resource by handler id");
			reg_method_arg(show_resource_state_used,"owner_tag","find resource by onwer local_tag",showResourceByLocalTag,"",
						   "<onwer_local_tag>","find resource by onwer local_tag");
			reg_method_arg(show_resource_state_used,"resource_id","find handlers which manage resources with ceration id",showResourcesById,"",
						   "<resource_id>","find handlers which manage resources with ceration id");


			reg_method(show_resource,"types","show resources types",showResourceTypes,"");

		reg_method(show,"sensors","show active sensors configuration",showSensorsState,"");
		/*reg_leaf(show,show_sensors,"sensors","sensors related functions");
			reg_method(show_sensors,"state","show active sensors configuration",showSensorsState,"");*/

		reg_leaf(show,show_router,"router","active router instance");
			reg_method(show_router,"cache","show callprofile's cache state",ShowCache,"");

			reg_leaf(show_router,show_router_cdrwriter,"cdrwriter","cdrwriter");
				reg_method(show_router_cdrwriter,"opened-files","show opened csv files",showRouterCdrWriterOpenedFiles,"");

		reg_leaf(show,show_media,"media","media processor instance");
			reg_method(show_media,"streams","active media streams info",showMediaStreams,"");

		reg_leaf_method_arg(show,show_calls,"calls","active calls",GetCalls,"show current active calls",
						"<LOCAL-TAG>","retreive call by local_tag");
			reg_method(show_calls,"count","active calls count",GetCallsCount,"");
			reg_method(show_calls,"fields","show available call fields",showCallsFields,"");
			reg_method_arg(show_calls,"filtered","active calls. specify desired fields",GetCallsFields,"",
						"<field1> <field2> ...","active calls. send only certain fields");

		reg_method(show,"configuration","actual settings",GetConfig,"");

		reg_method(show,"stats","runtime statistics",GetStats,"");

		reg_method(show,"interfaces","show network interfaces configuration",showInterfaces,"");

		reg_leaf_method_arg(show,show_sessions,"sessions","show runtime sessions",
							showSessionsInfo,"active sessions",
							"<LOCAL-TAG>","show sessions related to given local_tag");
			reg_method(show_sessions,"count","active sessions count",showSessionsCount,"");

		reg_leaf_method_arg(show,show_registrations,"registrations","uac registrations",GetRegistrations,"show configured uac registrations",
							"<id>","get registration by id");
			reg_method(show_registrations,"count","active registrations count",GetRegistrationsCount,"");

		reg_leaf(show,show_system,"system","system cmds");
			reg_method(show_system,"log-level","loglevels",showSystemLogLevel,"");
			reg_method(show_system,"status","system states",showSystemStatus,"");
			reg_method(show_system,"alarms","system alarms",showSystemAlarms,"");
			reg_method(show_system,"session-limit","actual sessions limit config",showSessions,"");
			reg_method(show_system,"dump-level","dump_level override value",showSystemDumpLevel,"");

		reg_leaf(show,show_radius,"radius","radius module");
			reg_leaf(show_radius,show_radius_auth,"authorization","auth functionality");
				reg_method(show_radius_auth,"profiles","radius profiles configuration",showRadiusAuthProfiles,"");
				reg_method(show_radius_auth,"statistics","radius connections statistic",showRadiusAuthStat,"");
			reg_leaf(show_radius,show_radius_acc,"accounting","accounting functionality");
				reg_method(show_radius_acc,"profiles","radius accounting profiles configuration",showRadiusAccProfiles,"");
				reg_method(show_radius_acc,"statistics","radius connections statistic",showRadiusAccStat,"");
			reg_leaf(show,show_upload,"upload","upload");
				reg_method(show_upload,"destinations","show configured destinations for http_client",showUploadDestinations,"");
				reg_method(show_upload,"stats","show http_client stats",showUploadStats,"");

		reg_leaf(show,show_recorder,"recorder","audio recorder instance");
			reg_method(show_recorder,"stats","show audio recorder processor stats",showRecorderStats,"");

	/* request */
	reg_leaf(root,request,"request","modify commands");

		reg_method(request,"upload","upload file using http_client",requestUpload,"<destination_id> <file_name> <path_to_file>");

		reg_leaf(request,request_sensors,"sensors","sensors");
			reg_method(request_sensors,"reload","reload sensors",requestReloadSensors,"");

		reg_leaf(request,request_router,"router","active router instance");

			reg_leaf(request_router,request_router_cdrwriter,"cdrwriter","CDR writer instance");
				reg_method(request_router_cdrwriter,"close-files","immideatly close failover csv files",closeCdrFiles,"");

			reg_leaf(request_router,request_router_translations,"translations","disconnect/internal_db codes translator");
				reg_method(request_router_translations,"reload","reload translator",reloadTranslations,"");

			reg_leaf(request_router,request_router_codec_groups,"codec-groups","codecs groups configuration");
				reg_method(request_router_codec_groups,"reload","reload codecs-groups",reloadCodecsGroups,"");

			reg_leaf(request_router,request_router_resources,"resources","resources actions configuration");
				reg_method(request_router_resources,"reload","reload resources",reloadResources,"");

			reg_leaf(request_router,request_router_cache,"cache","callprofile's cache");
				reg_method(request_router_cache,"clear","clear cached profiles",ClearCache,"");

		reg_leaf(request,request_registrations,"registrations","uac registrations");
			reg_method(request_registrations,"reload","reload reqistrations preferences",reloadRegistrations,"");
			reg_method_arg(request_registrations,"renew","renew registration",RenewRegistration,
						   "","<ID>","renew registration by id");

		reg_leaf(request,request_stats,"stats","runtime statistics");
			reg_method(request_stats,"clear","clear all counters",ClearStats,"");

		reg_leaf(request,request_call,"call","active calls control");
			reg_method_arg(request_call,"disconnect","drop call",DropCall,
						   "","<LOCAL-TAG>","drop call by local_tag");

		reg_leaf(request,request_media,"media","media processor instance");
			reg_method_arg(request_media,"payloads","loaded codecs",showPayloads,"show supported codecs",
						   "benchmark","compute transcoding cost for each codec");

		reg_leaf(request,request_system,"system","system commands");

			reg_leaf_method(request_system,request_system_shutdown,"shutdown","shutdown switch",
							requestSystemShutdown,"unclean shutdown");
				reg_method(request_system_shutdown,"immediate","don't wait for active calls",
						   requestSystemShutdownImmediate,"");
				reg_method(request_system_shutdown,"graceful","disable new calls, wait till active calls end",
						   requestSystemShutdownGraceful,"");
				reg_method(request_system_shutdown,"cancel","cancel graceful shutdown",
						   requestSystemShutdownCancel,"");

			reg_leaf(request_system,request_system_log,"log","logging facilities control");
				reg_method(request_system_log,"dump","save in-memory ringbuffer log to file",
						   requestSystemLogDump,"");

		reg_leaf(request,request_resource,"resource","resources cache");
			/*reg_method_arg(request_resource,"state","",getResourceState,
						   "","<type> <id>","get current state of resource");*/
			reg_method(request_resource,"invalidate","invalidate all resources",requestResourcesInvalidate,"");

		reg_leaf(request,request_resolver,"resolver","dns resolver instance");
			reg_method(request_resolver,"clear","clear dns cache",requestResolverClear,"");
			reg_method_arg(request_resolver,"get","",requestResolverGet,
						   "","<name>","resolve dns name");

		reg_leaf(request,request_radius,"radius","radius module");
			reg_leaf(request_radius,request_radius_auth,"authorization","authorization");
				reg_leaf(request_radius_auth,request_radius_auth_profiles,"profiles","profiles");
					reg_method(request_radius_auth_profiles,"reload","reload radius profiles",requestRadiusAuthProfilesReload,"");
			reg_leaf(request_radius,request_radius_acc,"accounting","accounting");
				reg_leaf(request_radius_acc,request_radius_acc_profiles,"profiles","profiles");
					reg_method(request_radius_acc_profiles,"reload","reload radius accounting profiles",requestRadiusAccProfilesReload,"");

	/* set */
	reg_leaf(root,lset,"set","set");
		reg_leaf(lset,set_system,"system","system commands");
			reg_leaf(set_system,set_system_log_level,"log-level","logging facilities level");
				reg_method_arg(set_system_log_level,"di_log","",setSystemLogDiLogLevel,
							   "","<log_level>","set new log level");
				reg_method_arg(set_system_log_level,"syslog","",setSystemLogSyslogLevel,
							   "","<log_level>","set new log level");

			reg_method_arg(set_system,"session-limit","",setSessionsLimit,
						   "","<limit> <overload response code> <overload response reason>","set new session limit params");
			reg_leaf(set_system,set_system_dump_level,"dump-level","logging facilities control");
			reg_method(set_system_dump_level,"none","",setSystemDumpLevelNone,"");
			reg_method(set_system_dump_level,"signalling","",setSystemDumpLevelSignalling,"");
			reg_method(set_system_dump_level,"rtp","",setSystemDumpLevelRtp,"");
			reg_method(set_system_dump_level,"full","",setSystemDumpLevelFull,"");

#undef reg_leaf
#undef reg_method
#undef reg_leaf_method
#undef reg_method_arg
#undef reg_leaf_method_arg
}

void Yeti::process_rpc_cmds(const AmArg cmds, const string& method, const AmArg& args, AmArg& ret){
	const char *list_method = "_list";
	//DBG("process_rpc_cmds(%p,%s,...)",&cmds,method.c_str());
	if(method==list_method){
		ret.assertArray();
		switch(cmds.getType()){
			case AmArg::Struct: {
				AmArg::ValueStruct::const_iterator it = cmds.begin();
				for(;it!=cmds.end();++it){
					const AmArg &am_e = it->second;
					rpc_entry *e = reinterpret_cast<rpc_entry *>(am_e.asObject());
					AmArg f;
					f.push(it->first);
					f.push(e->leaf_descr);
					ret.push(f);
				}
			} break;

			case AmArg::AObject: {
				rpc_entry *e = reinterpret_cast<rpc_entry *>(cmds.asObject());
				if(!e->func_descr.empty()&&(!e->arg.empty()||e->hasLeafs())){
					AmArg f;
					f.push("[Enter]");
					f.push(e->func_descr);
					ret.push(f);
				}
				if(!e->arg.empty()){
					AmArg f;
					f.push(e->arg);
					f.push(e->arg_descr);
					ret.push(f);
				}
				if(e->hasLeafs()){
					const AmArg &l = e->leaves;
					AmArg::ValueStruct::const_iterator it = l.begin();
					for(;it!=l.end();++it){
						const AmArg &am_e = it->second;
						rpc_entry *e = reinterpret_cast<rpc_entry *>(am_e.asObject());
						AmArg f;
						f.push(it->first);
						f.push(e->leaf_descr);
						ret.push(f);
					}
				}
			} break;

			default:
				throw AmArg::TypeMismatchException();
		}
		return;
	}

	if(cmds.hasMember(method)){
		const AmArg &l = cmds[method];
		if(l.getType()!=AmArg::AObject)
			throw AmArg::TypeMismatchException();

		rpc_entry *e = reinterpret_cast<rpc_entry *>(l.asObject());
		if(args.size()>0){
			if(e->hasLeaf(args[0].asCStr())){
				AmArg nargs = args,sub_method;
				nargs.pop(sub_method);
				process_rpc_cmds(e->leaves,sub_method.asCStr(),nargs,ret);
				return;
			} else if(args[0]==list_method){
				AmArg nargs = args,sub_method;
				nargs.pop(sub_method);
				process_rpc_cmds(l,sub_method.asCStr(),nargs,ret);
				return;
			}
		}
		if(e->isMethod()){
			if(args.size()&&strcmp(args.back().asCStr(),list_method)==0){
				if(!e->hasLeafs()&&e->arg.empty())
					ret.assertArray();
				return;
			}
			(this->*(e->handler))(args,ret);
			return;
		}
		throw AmDynInvoke::NotImplemented("missed arg");
	}
	throw AmDynInvoke::NotImplemented("no matches with methods tree");
}

void Yeti::invoke(const string& method, const AmArg& args, AmArg& ret)
{
	DBG("Yeti: %s(%s)\n", method.c_str(), AmArg::print(args).c_str());

	if(method == "getLogicInterfaceHandler"){
		SBCLogicInterface *i = (SBCLogicInterface *)this;
		ret[0] = (AmObject *)i;
	} else if(method == "getExtendedInterfaceHandler"){
		ExtendedCCInterface *i = (ExtendedCCInterface *)this;
		ret[0] = (AmObject *)i;
	} else if (method == "dropCall"){
		INFO ("dropCall received via rpc2di");
		DropCall(args,ret);
	} else if (method == "getCall"){
		INFO ("getCall received via rpc2di");
		GetCall(args,ret);
	} else if (method == "getCalls"){
		INFO ("getCalls received via rpc2di");
		GetCalls(args,ret);
	} else if (method == "getCallsCount"){
		INFO ("getCallsCount received via rpc2di");
		GetCallsCount(args,ret);
	} else if (method == "getStats"){
		INFO ("getStats received via rpc2di");
		GetStats(args,ret);
	} else if (method == "clearStats"){
		INFO ("clearStats received via rpc2di");
		ClearStats(args,ret);
	} else if (method == "showCache"){
		INFO ("showCache received via rpc2di");
		ShowCache(args,ret);
	} else if (method == "clearCache"){
		INFO ("clearCache received via rpc2di");
		ClearCache(args,ret);
	} else if (method == "getRegistration"){
		INFO("getRegistration via rpc2di");
		GetRegistration(args,ret);
	} else if (method == "renewRegistration"){
		INFO("renewRegistration via rpc2di");
		RenewRegistration(args,ret);
	} else if (method == "getRegistrations"){
		INFO("getRegistrations via rpc2di");
		GetRegistrations(args,ret);
	} else if (method == "getRegistrationsCount"){
		INFO("getRegistrationsCount via rpc2di");
		GetRegistrationsCount(args,ret);
	} else if (method == "getConfig"){
		INFO ("getConfig received via rpc2di");
		GetConfig(args,ret);
	} else if (method == "showVersion"){
		INFO ("showVersion received via rpc2di");
		showVersion(args, ret);
	} else if(method == "closeCdrFiles"){
		INFO ("closeCdrFiles received via rpc2di");
		closeCdrFiles(args,ret);
	/*} else if(method == "_list"){
		ret.push(AmArg("showVersion"));
		ret.push(AmArg("getConfig"));
		ret.push(AmArg("getStats"));
		ret.push(AmArg("clearStats"));
		ret.push(AmArg("clearCache"));
		ret.push(AmArg("showCache"));
		ret.push(AmArg("dropCall"));
		ret.push(AmArg("getCall"));
		ret.push(AmArg("getCalls"));
		ret.push(AmArg("getCallsCount"));
		ret.push(AmArg("getRegistration"));
		ret.push(AmArg("renewRegistration"));
		ret.push(AmArg("getRegistrations"));
		ret.push(AmArg("getRegistrationsCount"));
		ret.push(AmArg("reload"));
		ret.push(AmArg("closeCdrFiles"));

		ret.push(AmArg("show"));
		ret.push(AmArg("request"));
		//ret.push(AmArg("set"));*/
	} else {
		process_rpc_cmds(rpc_cmds,method,args,ret);
	}/* else {
		throw AmDynInvoke::NotImplemented(method);
	}*/
}

/****************************************
 * 				aux funcs				*
 ****************************************/

bool Yeti::check_event_id(int event_id,AmArg &ret){
	bool succ = false;
	try {
		DbConfig dbc;
		string prefix("master");
		dbc.cfg2dbcfg(cfg,prefix);
		pqxx::connection c(dbc.conn_str());
		c.set_variable("search_path",
					   Yeti::instance()->config.routing_schema+", public");
#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
		pqxx::prepare::declaration d =
#endif
			c.prepare("check_event","SELECT * from check_event($1)");
#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
			d("integer",pqxx::prepare::treat_direct);
#endif
		pqxx::nontransaction t(c);
			pqxx::result r = t.prepared("check_event")(event_id).exec();
		if(r[0][0].as<bool>(false)){
			DBG("event_id checking succ");
			succ = true;
		} else {
			WARN("no appropriate id in database");
			throw AmSession::Exception(503,"no such event_id");
		}
	} catch(pqxx::pqxx_exception &e){
		DBG("e = %s",e.base().what());
		throw AmSession::Exception(500,string("can't check event id in database ")+e.base().what());
	} catch(AmSession::Exception){
		throw;
	} catch(...){
		AmSession::Exception(500,"can't check event id in database");
	}
	return succ;
}

bool Yeti::assert_event_id(const AmArg &args,AmArg &ret){
	if(args.size()){
		int event_id;
		args.assertArrayFmt("s");
		if(!str2int(args[0].asCStr(),event_id)){
			throw AmSession::Exception(500,"invalid event id");
		}
		if(!check_event_id(event_id,ret))
				return false;
	}
	return true;
}

/****************************************
 * 				rpc handlers			*
 ****************************************/

void Yeti::GetCallsCount(const AmArg& args, AmArg& ret) {
	handler_log();
	ret = (long int)cdr_list.get_count();
}

void Yeti::GetCall(const AmArg& args, AmArg& ret) {
	string local_tag;
	handler_log();

	if (!args.size()) {
		throw AmSession::Exception(500,"Parameters error: expected local tag of requested cdr");
	}

	local_tag = args[0].asCStr();
	if(!cdr_list.getCall(local_tag,ret,&router)){
		throw CdrNotFoundException(local_tag);
	}
}

void Yeti::GetCalls(const AmArg& args, AmArg& ret) {
	handler_log();
	if(args.size()){
		string local_tag = args[0].asCStr();
		if(!cdr_list.getCall(local_tag,ret,&router)){
			throw CdrNotFoundException(local_tag);
		}
	} else {
		cdr_list.getCalls(ret,calls_show_limit,&router);
	}
}

void Yeti::GetCallsFields(const AmArg &args, AmArg &ret){
	handler_log();

	if(!args.size()){
		throw AmSession::Exception(500,"you should specify at least one field");
	}

	try {
		cdr_list.getCallsFields(ret,calls_show_limit,&router,args);
	} catch(std::string &s){
		throw AmSession::Exception(500,s);
	}
}

void Yeti::showCallsFields(const AmArg &args, AmArg &ret){
	cdr_list.getFields(ret,&router);
}

void Yeti::GetRegistration(const AmArg& args, AmArg& ret){
	string reg_id_str;
	int reg_id;
	handler_log();
	if (!args.size()) {
		throw AmSession::Exception(500,"Parameters error: expected id of requested registration");
	}

	reg_id_str = args[0].asCStr();
	if(!str2int(reg_id_str,reg_id)){
		throw AmSession::Exception(500,"Non integer value passed as registrations id");
	}

	if(!Registration::instance()->get_registration_info(reg_id,ret)){
		throw AmSession::Exception(404,"Have no registration with such id");
	}
}

void Yeti::RenewRegistration(const AmArg& args, AmArg& ret){
	string reg_id_str;
	int reg_id;
	handler_log();
	if (!args.size()) {
		throw AmSession::Exception(500,"Parameters error: expected id of active registration");
	}

	reg_id_str = args[0].asCStr();
	if(!str2int(reg_id_str,reg_id)){
		throw AmSession::Exception(500,"Non integer value passed as registrations id");
	}

	if(!Registration::instance()->reregister(reg_id)){
		throw AmSession::Exception(404,"Have no registration with such id and in appropriate state");
	}
	ret = RPC_CMD_SUCC;
}

void Yeti::GetRegistrations(const AmArg& args, AmArg& ret){
	handler_log();
	if(args.size()){
		GetRegistration(args,ret);
		return;
	}
	Registration::instance()->list_registrations(ret);
}

void Yeti::GetRegistrationsCount(const AmArg& args, AmArg& ret){
	handler_log();
	ret = Registration::instance()->get_registrations_count();
}

void Yeti::ClearStats(const AmArg& args, AmArg& ret){
	handler_log();
	router.clearStats();
	rctl.clearStats();
	ret = RPC_CMD_SUCC;
}

void Yeti::ClearCache(const AmArg& args, AmArg& ret){
	handler_log();
	router.clearCache();
	ret = RPC_CMD_SUCC;
}

void Yeti::ShowCache(const AmArg& args, AmArg& ret){
	handler_log();
	router.showCache(ret);
}

void Yeti::GetStats(const AmArg& args, AmArg& ret){
	time_t now;
	handler_log();

	/* Yeti stats */
	ret["calls_show_limit"] = (int)calls_show_limit;
	now = time(NULL);
	ret["localtime"] = now;
	ret["uptime"] = difftime(now,start_time);

	/* sql_router stats */
	router.getStats(ret["router"]);

	AmSessionContainer::instance()->getStats(ret["AmSessionContainer"]);

	AmArg &ss = ret["AmSession"];
	ss["SessionNum"] = (int)AmSession::getSessionNum();
	ss["MaxSessionNum"] = (int)AmSession::getMaxSessionNum();
	ss["AvgSessionNum"] = (int)AmSession::getAvgSessionNum();

	AmArg &ts = ret["trans_layer"];
	const trans_stats &tstats = trans_layer::instance()->get_stats();
	ts["rx_replies"] = (long)tstats.get_received_replies();
	ts["tx_replies"] = (long)tstats.get_sent_replies();
	ts["tx_replies_retrans"] = (long)tstats.get_sent_reply_retrans();
	ts["rx_requests"] =(long) tstats.get_received_requests();
	ts["tx_requests"] = (long)tstats.get_sent_requests();
	ts["tx_requests_retrans"] = (long)tstats.get_sent_request_retrans();

	rctl.getStats(ret["resource_control"]);
	CodesTranslator::instance()->getStats(ret["translator"]);
}

void Yeti::GetConfig(const AmArg& args, AmArg& ret) {
	handler_log();

	ret["calls_show_limit"] = calls_show_limit;
	ret["node_id"] = config.node_id;
	ret["pop_id"] = config.pop_id;

	router.getConfig(ret["router"]);

	CodesTranslator::instance()->GetConfig(ret["translator"]);
	rctl.GetConfig(ret["resources_control"]);
	CodecsGroups::instance()->GetConfig(ret["codecs_groups"]);
}

void Yeti::DropCall(const AmArg& args, AmArg& ret){
	SBCControlEvent* evt;
	string local_tag;
	handler_log();

	if (!args.size()){
		throw AmSession::Exception(500,"Parameters error: expected local tag of active call");
	}

	local_tag = args[0].asCStr();

	evt = new SBCControlEvent("teardown");

	if (!AmSessionContainer::instance()->postEvent(local_tag, evt)) {
		/* hack: if cdr not in AmSessionContainer but present in cdr_list then drop it and write cdr */
		cdr_list.lock();
			Cdr *cdr = cdr_list.get_by_local_tag(local_tag);
			if(cdr){
				//don't check for inserted2list. we just got it from here.
				cdr_list.erase_unsafe(local_tag,false);
			}
		cdr_list.unlock();
		if(cdr){
			ERROR("Yeti::DropCall() call %s not in AmSessionContainer but in CdrList. "
				  "remove it from CdrList and write CDR using active router instance",local_tag.c_str());
			router.write_cdr(cdr,true);
			ret = "Dropped from active_calls (no presented in sessions container)";
		} else {
			throw CdrNotFoundException(local_tag);
		}
	} else {
		ret = "Dropped from sessions container";
	}
}

void Yeti::showVersion(const AmArg& args, AmArg& ret) {
	handler_log();
	ret["build"] = YETI_VERSION;
	ret["build_commit"] = YETI_COMMIT;
	ret["compiled_at"] = YETI_BUILD_DATE;
	ret["compiled_by"] = YETI_BUILD_USER;
}

void Yeti::reloadResources(const AmArg& args, AmArg& ret){
	handler_log();
	if(!assert_event_id(args,ret))
		return;
	rctl.configure_db(cfg);
	if(!rctl.reload()){
		throw AmSession::Exception(500,"errors during resources config reload. leave old state");
	}
	ret = RPC_CMD_SUCC;
}

void Yeti::reloadTranslations(const AmArg& args, AmArg& ret){
	handler_log();
	if(!assert_event_id(args,ret))
		return;
	CodesTranslator::instance()->configure_db(cfg);
	if(!CodesTranslator::instance()->reload()){
		throw AmSession::Exception(500,"errors during translations config reload. leave old state");
	}
	ret = RPC_CMD_SUCC;
}

void Yeti::reloadRegistrations(const AmArg& args, AmArg& ret){
	handler_log();
	if(!assert_event_id(args,ret))
		return;
	if(0==Registration::instance()->reload(cfg)){
		ret = RPC_CMD_SUCC;
	} else {
		throw AmSession::Exception(500,"errors during registrations config reload. leave old state");
	}
}

void Yeti::reloadCodecsGroups(const AmArg& args, AmArg& ret){
	handler_log();
	if(!assert_event_id(args,ret))
		return;
	CodecsGroups::instance()->configure_db(cfg);
	if(!CodecsGroups::instance()->reload()){
		throw AmSession::Exception(500,"errors during codecs groups reload. leave old state");
	}
	ret = RPC_CMD_SUCC;
}

void Yeti::requestReloadSensors(const AmArg& args, AmArg& ret){
	handler_log();
	if(!assert_event_id(args,ret))
		return;
	Sensors::instance()->configure_db(cfg);
	if(Sensors::instance()->reload()){
		ret = RPC_CMD_SUCC;
	} else {
		throw AmSession::Exception(500,"errors during sensors reload. leave old state");
	}
}

void Yeti::showSensorsState(const AmArg& args, AmArg& ret){
	handler_log();
	Sensors::instance()->GetConfig(ret);
}


static void SBCCallLeg2AmArg(SBCCallLeg *leg, AmArg &s)
{
	s["a_leg"] = leg->isALeg();
	s["call_status"] = leg->getCallStatusStr();
	s["session_status"] = leg->getProcessingStatusStr();
	s["other_id"] = leg->getOtherId();

	AmSipDialog *dlg = leg->dlg;
	if(dlg){
		s["dlg_status"] = dlg->getStatusStr();
		s["dlg_callid"] = dlg->getCallid();
		s["dlg_ruri"] = dlg->getRemoteUri();
	}

	CallCtx *ctx = getCtx(leg);
	if(ctx){
		s["attempt_num"] = ctx->attempt_num;
		ctx->lock();
		Cdr *cdr = ctx->cdr;
		if(cdr) cdr->info(s);
		ctx->unlock();
	}
}

static void dump_session_info(
	const AmEventDispatcher::QueueEntry &entry,
	void *arg)
{
	AmArg &a = *(AmArg *)arg;
	a.assertStruct();
	SBCCallLeg *leg = dynamic_cast<SBCCallLeg *>(entry.q);
	if(!leg) return;
	SBCCallLeg2AmArg(leg,a);
}

static void dump_sessions_info(
	const string &key,
	const AmEventDispatcher::QueueEntry &entry,
	void *arg)
{
	SBCCallLeg *leg = dynamic_cast<SBCCallLeg *>(entry.q);
	if(!leg) return; //dump only SBCCallLeg entries
	AmArg &ret = *(AmArg *)arg;
	SBCCallLeg2AmArg(leg,ret[key]);
}

void Yeti::showSessionsInfo(const AmArg& args, AmArg& ret){
	handler_log();
	ret.assertStruct();
	if(!args.size()){
		AmEventDispatcher::instance()->iterate(&dump_sessions_info,&ret);
	} else {
		const string local_tag = args[0].asCStr();
		AmArg &session_info = ret[local_tag];
		AmEventDispatcher::instance()->apply(
			local_tag,
			&dump_session_info,
			&session_info);
		if(isArgStruct(session_info) &&
			session_info.hasMember("other_id"))
		{
			const string other_local_tag = session_info["other_id"].asCStr();
			AmArg &other_session_info = ret[other_local_tag];
			AmEventDispatcher::instance()->apply(
				other_local_tag,
				&dump_session_info,
				&other_session_info);

		}
	}
}

void Yeti::showSessionsCount(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	ret = (int)AmSession::getSessionNum();
}

static inline AmDynInvoke* get_radius_interace(){
	AmDynInvokeFactory* radius_client_factory = AmPlugIn::instance()->getFactory4Di("radius_client");
	if(NULL==radius_client_factory){
		throw AmSession::Exception(500,"radius module not loaded");
	}
	AmDynInvoke* radius_client = radius_client_factory->getInstance();
	if(NULL==radius_client){
		throw AmSession::Exception(500,"can't get radius client instance");
	}
	return radius_client;
}

void Yeti::showRadiusAuthProfiles(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	get_radius_interace()->invoke("showAuthConnections",args,ret);
}

void Yeti::showRadiusAccProfiles(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	get_radius_interace()->invoke("showAccConnections",args,ret);
}

void Yeti::showRadiusAuthStat(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	get_radius_interace()->invoke("showAuthStat",args,ret);
}

void Yeti::showRadiusAccStat(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	get_radius_interace()->invoke("showAccStat",args,ret);
}

void Yeti::showRecorderStats(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	AmAudioFileRecorderProcessor::instance()->getStats(ret);
}

void Yeti::showUploadDestinations(const AmArg& args, AmArg& ret){
    handler_log();
    AmDynInvokeFactory* f = AmPlugIn::instance()->getFactory4Di("http_client");
    if(NULL==f){
        throw AmSession::Exception(500,"http_client module not loaded");
    }
    AmDynInvoke* i = f->getInstance();
    if(NULL==i){
        throw AmSession::Exception(500,"can't get http client instance");
    }
    i->invoke("show",args,ret);
}

void Yeti::showUploadStats(const AmArg& args, AmArg& ret){
    handler_log();
    AmDynInvokeFactory* f = AmPlugIn::instance()->getFactory4Di("http_client");
    if(NULL==f){
        throw AmSession::Exception(500,"http_client module not loaded");
    }
    AmDynInvoke* i = f->getInstance();
    if(NULL==i){
        throw AmSession::Exception(500,"can't get http client instance");
    }
    i->invoke("stats",args,ret);
}

void Yeti:: requestUpload(const AmArg& args, AmArg& ret) {
    handler_log();

    args.assertArrayFmt("sss");

    /*int destination_id;
    if(!str2int(args.get(0).asCStr(),destination_id)){
        throw AmSession::Exception(500,"non integer value for destination_id");
    }*/

    if (AmSessionContainer::instance()->postEvent(
        HTTP_EVENT_QUEUE,
        //new HttpUploadEvent(destination_id,args.get(1).asCStr())))
        new HttpUploadEvent(args.get(0).asCStr(),args.get(1).asCStr(),args.get(2).asCStr())))
    {
        ret = "posted to queue";
    } else {
        ret = "failed to post event";
    }
}

void Yeti::requestRadiusAuthProfilesReload(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	AmArg lret;
	AmDynInvoke *r = get_radius_interace();
	DBG("clear radius auth connections");
	r->invoke("clearAuthConnections",AmArg(),lret);
	if(init_radius_auth_connections(r)){
		ERROR("intializing radius auth profiles");
		throw AmSession::Exception(500,"profiles cleared but exception occured during reinit. "
			  "you have no loaded profiles for now. examine logs and check your configuration");
	}
	ret = "auth profiles reloaded";
}

void Yeti::requestRadiusAccProfilesReload(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	AmArg lret;
	AmDynInvoke *r = get_radius_interace();
	DBG("clear radius auth connections");
	r->invoke("clearAccConnections",AmArg(),lret);
	if(init_radius_acc_connections(r)){
		ERROR("intializing radius acc profiles");
		throw AmSession::Exception(500,"profiles cleared but exception occured during reinit. "
			  "you have no loaded profiles for now. examine logs and check your configuration");
	}
	ret = "acc profiles reloaded";
}

void Yeti::closeCdrFiles(const AmArg& args, AmArg& ret){
	handler_log();
	router.closeCdrFiles();
	ret = RPC_CMD_SUCC;
}

void Yeti::showMediaStreams(const AmArg& args, AmArg& ret){
	handler_log();
	AmMediaProcessor::instance()->getInfo(ret);
}

void Yeti::showPayloads(const AmArg& args, AmArg& ret){
	vector<SdpPayload> payloads;
	unsigned char *buf;
	int size = 0;
	handler_log();
	bool compute_cost = args.size() && args[0] == "benchmark";
	string path = args.size()>1 ? args[1].asCStr() : DEFAULT_BECH_FILE_PATH;

	const AmPlugIn* plugin = AmPlugIn::instance();
	plugin->getPayloads(payloads);

	if(compute_cost){
		size = load_testing_source(path,buf);
		compute_cost = size > 0;
	}

	vector<SdpPayload>::const_iterator it = payloads.begin();
	for(;it!=payloads.end();++it){
		const SdpPayload &p = *it;
		ret.push(p.encoding_name,AmArg());
		AmArg &a = ret[p.encoding_name];

		DBG("process codec: %s (%d)",
			p.encoding_name.c_str(),p.payload_type);
		a["payload_type"] = p.payload_type;
		a["clock_rate"] = p.clock_rate;
		if(compute_cost){
			get_codec_cost(p.payload_type,buf,size,a);
		}
	}

	if(compute_cost)
		delete[] buf;
}

void Yeti::showInterfaces(const AmArg& args, AmArg& ret){
	handler_log();

	AmArg &sig = ret["sip"];
	for(int i=0; i<(int)AmConfig::SIP_Ifs.size(); i++) {
		AmConfig::SIP_interface& iface = AmConfig::SIP_Ifs[i];
		AmArg am_iface;
		am_iface["sys_name"] = iface.NetIf;
		am_iface["sys_idx"] = (int)iface.NetIfIdx;
		am_iface["local_ip"] = iface.LocalIP;
		am_iface["local_port"] = (int)iface.LocalPort;
		am_iface["public_ip"] = iface.PublicIP;
		am_iface["use_raw_sockets"] = (iface.SigSockOpts&trsp_socket::use_raw_sockets)!= 0;
		am_iface["force_via_address"] = (iface.SigSockOpts&trsp_socket::force_via_address) != 0;
		am_iface["force_outbound_if"] = (iface.SigSockOpts&trsp_socket::force_outbound_if) != 0;
		sig[iface.name] = am_iface;
	}

	AmArg &sip_map = ret["sip_map"];
	for(multimap<string,unsigned short>::iterator it = AmConfig::LocalSIPIP2If.begin();
		it != AmConfig::LocalSIPIP2If.end(); ++it) {
		AmConfig::SIP_interface& iface = AmConfig::SIP_Ifs[it->second];
		sip_map[it->first] = iface.name.empty() ? "default" : iface.name;
	}

	AmArg &rtp = ret["media"];
	for(int i=0; i<(int)AmConfig::RTP_Ifs.size(); i++) {
		AmConfig::RTP_interface& iface = AmConfig::RTP_Ifs[i];
		AmArg am_iface;
		am_iface["sys_name"] = iface.NetIf;
		am_iface["sys_idx"] = (int)iface.NetIfIdx;
		am_iface["local_ip"] = iface.LocalIP;
		am_iface["public_ip"] = iface.PublicIP;
		am_iface["rtp_low_port"] = iface.RtpLowPort;
		am_iface["rtp_high_port"] = iface.RtpHighPort;
		am_iface["use_raw_sockets"] = (iface.MediaSockOpts&trsp_socket::use_raw_sockets)!= 0;
		string name = iface.name.empty() ? "default" : iface.name;
		rtp[name] = am_iface;
	}
}

void Yeti::showRouterCdrWriterOpenedFiles(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	router.showOpenedFiles(ret);
}

void Yeti::requestSystemLogDump(const AmArg& args, AmArg& ret){
	handler_log();

	//load factory
	AmDynInvokeFactory* di_log = AmPlugIn::instance()->getFactory4Di("di_log");
	if(0==di_log){
		throw AmSession::Exception(404,"di_log module not loaded");
	}

	//generate filename
	struct timeval t;
	gettimeofday(&t,NULL);

	string path = Yeti::config.log_dir + "/";
	path += int2str((unsigned int)t.tv_sec) + "-";
	path += int2hex(get_random());
	path += int2hex(t.tv_sec) + int2hex(t.tv_usec);
	path += int2hex((unsigned int)((unsigned long)pthread_self()));

	AmArg di_log_args;
	di_log_args.push(path);

	di_log->getInstance()->invoke("dumplogtodisk",di_log_args,ret);
}

static void addLoggingFacilityLogLevel(AmArg& ret,const string &facility_name){
	AmLoggingFacility* fac = AmPlugIn::instance()->getFactory4LogFaclty(facility_name);
	if(0==fac)
		return;
	ret[fac->getName()] = fac->getLogLevel();
}

static void setLoggingFacilityLogLevel(const AmArg& args, AmArg& ret,const string &facility_name){
	int log_level;
	if(!args.size()){
		throw AmSession::Exception(500,"missed new log_level");
	}
	args.assertArrayFmt("s");
	if(!str2int(args.get(0).asCStr(),log_level)){
		throw AmSession::Exception(500,"invalid log_level fmt");
	}

	AmLoggingFacility* fac = AmPlugIn::instance()->getFactory4LogFaclty(facility_name);
	if(0==fac){
		throw AmSession::Exception(404,"logging facility not loaded");
	}

	fac->setLogLevel(log_level);

	ret = RPC_CMD_SUCC;
}

void Yeti::showSystemLogLevel(const AmArg& args, AmArg& ret){
	handler_log();
	ret["log_level"] = log_level;
	addLoggingFacilityLogLevel(ret["facilities"],"syslog");
	addLoggingFacilityLogLevel(ret["facilities"],"di_log");
}

void Yeti::setSystemLogSyslogLevel(const AmArg& args, AmArg& ret){
	handler_log();
	setLoggingFacilityLogLevel(args,ret,"syslog");
}

void Yeti::setSystemLogDiLogLevel(const AmArg& args, AmArg& ret){
	handler_log();
	setLoggingFacilityLogLevel(args,ret,"di_log");
}

void Yeti::setSystemDumpLevel(int dump_level){
	INFO("change system dump_level from %s to %s",
		 dump_level2str(AmConfig::DumpLevel),
		 dump_level2str(dump_level));
	AmConfig::DumpLevel = dump_level;
}

void Yeti::setSystemDumpLevelNone(const AmArg& args, AmArg& ret){
	(void)args;
	handler_log();
	setSystemDumpLevel(0);
	ret = RPC_CMD_SUCC;
}

void Yeti::setSystemDumpLevelSignalling(const AmArg& args, AmArg& ret){
	(void)args;
	handler_log();
	setSystemDumpLevel(LOG_SIP_MASK);
	ret = RPC_CMD_SUCC;
}

void Yeti::setSystemDumpLevelRtp(const AmArg& args, AmArg& ret){
	(void)args;
	handler_log();
	setSystemDumpLevel(LOG_RTP_MASK);
	ret = RPC_CMD_SUCC;
}

void Yeti::setSystemDumpLevelFull(const AmArg& args, AmArg& ret){
	(void)args;
	handler_log();
	setSystemDumpLevel(LOG_FULL_MASK);
	ret = RPC_CMD_SUCC;
}

void Yeti::showSystemStatus(const AmArg& args, AmArg& ret){
	handler_log();
	ret["shutdown_mode"] = (bool)AmConfig::ShutdownMode;
	ret["shutdown_request_time"] = !timerisset(&last_shutdown_time) ?
					"nil" : timeval2str(last_shutdown_time);

	ret["version"] = YETI_VERSION;
	ret["calls"] = (long int)cdr_list.get_count();
	ret["sessions"] = (int)AmSession::getSessionNum();
	ret["dump_level"] = dump_level2str(AmConfig::DumpLevel);

	time_t now = time(NULL);
	ret["localtime"] = now;
	ret["uptime"] = difftime(now,start_time);
}

void Yeti::showSystemAlarms(const AmArg& args, AmArg& ret){
	handler_log();
	alarms *a = alarms::instance();
	for(int id = 0; id < alarms::MAX_ALARMS; id++){
		ret.push(AmArg());
		a->get(id).getInfo(ret.back());
	}
}

void Yeti::showSystemDumpLevel(const AmArg& args, AmArg& ret){
	(void)args;
	handler_log();
	ret = dump_level2str(AmConfig::DumpLevel);
}

inline void graceful_suicide(){
	kill(getpid(),SIGINT);
}

inline void immediate_suicide(){
	kill(getpid(),SIGTERM);
}

static void set_system_shutdown(bool shutdown){
	AmConfig::ShutdownMode = shutdown;
	INFO("ShutDownMode changed to %d",AmConfig::ShutdownMode);

	if(AmConfig::ShutdownMode&&!AmSession::getSessionNum()){
		//commit suicide immediatly
		INFO("no active session on graceful shutdown command. exit immediatly");
		graceful_suicide();
	}
}

void Yeti::requestSystemShutdown(const AmArg& args, AmArg& ret){
	handler_log();
	graceful_suicide();
	ret = RPC_CMD_SUCC;
}

void Yeti::requestSystemShutdownImmediate(const AmArg& args, AmArg& ret){
	handler_log();
	immediate_suicide();
	ret = RPC_CMD_SUCC;
}

void Yeti::requestSystemShutdownGraceful(const AmArg& args, AmArg& ret){
	handler_log();
	gettimeofday(&last_shutdown_time,NULL);
	set_system_shutdown(true);
	ret = RPC_CMD_SUCC;
}

void Yeti::requestSystemShutdownCancel(const AmArg& args, AmArg& ret){
	handler_log();
	timerclear(&last_shutdown_time);
	set_system_shutdown(false);
	ret = RPC_CMD_SUCC;
}

void Yeti::getResourceState(const AmArg& args, AmArg& ret){
	handler_log();
	int type, id;

	if(args.size()<2){
		throw AmSession::Exception(500,"specify type and id of resource");
	}
	args.assertArrayFmt("ss");
	if(!str2int(args.get(0).asCStr(),type)){
		throw AmSession::Exception(500,"invalid resource type");
	}
	if(!str2int(args.get(1).asCStr(),id)){
		throw AmSession::Exception(500,"invalid resource id");
	}

	try {
		rctl.getResourceState(type,id,ret);
	} catch(const ResourceCacheException &e){
		throw AmSession::Exception(e.code,e.what);
	}
}

void Yeti::showResources(const AmArg& args, AmArg& ret){
	handler_log();
	rctl.showResources(ret);
}

void Yeti::showResourceByHandler(const AmArg& args, AmArg& ret){
	handler_log();
	if(!args.size()){
		throw AmSession::Exception(500,"specify handler id");
	}
	rctl.showResourceByHandler(args.get(0).asCStr(),ret);
}

void Yeti::showResourceByLocalTag(const AmArg& args, AmArg& ret){
	handler_log();
	if(!args.size()){
		throw AmSession::Exception(500,"specify local_tag");
	}
	rctl.showResourceByLocalTag(args.get(0).asCStr(),ret);
}

void Yeti::showResourcesById(const AmArg& args, AmArg& ret){
	handler_log();

	int id;
	if(!args.size()){
		throw AmSession::Exception(500,"specify resource id");
	}
	if(!str2int(args.get(0).asCStr(),id)){
		throw AmSession::Exception(500,"invalid resource id");
	}
	rctl.showResourcesById(id,ret);
}

void Yeti::showResourceTypes(const AmArg& args, AmArg& ret){
	handler_log();
	rctl.GetConfig(ret,true);
}

void Yeti::requestResourcesInvalidate(const AmArg& args, AmArg& ret){
	handler_log();
	if(rctl.invalidate_resources()){
		ret = RPC_CMD_SUCC;
	} else {
		throw AmSession::Exception(500,"handlers invalidated. but resources initialization failed");
	}
}

void Yeti::showSessions(const AmArg& args, AmArg& ret){
	handler_log();

	ret["limit"] = (long int)AmConfig::SessionLimit;
	ret["limit_error_code"] = (long int)AmConfig::SessionLimitErrCode;
	ret["limit_error_reason"] = AmConfig::SessionLimitErrReason;
}

void Yeti::setSessionsLimit(const AmArg& args, AmArg& ret){
	handler_log();
	if(args.size()<3){
		throw AmSession::Exception(500,"missed parameter");
	}
	args.assertArrayFmt("sss");

	int limit,code;
	if(!str2int(args.get(0).asCStr(),limit)){
		throw AmSession::Exception(500,"non integer value for sessions limit");
	}
	if(!str2int(args.get(1).asCStr(),code)){
		throw AmSession::Exception(500,"non integer value for overload response code");
	}

	AmConfig::SessionLimit = limit;
	AmConfig::SessionLimitErrCode = code;
	AmConfig::SessionLimitErrReason = args.get(2).asCStr();

	ret = RPC_CMD_SUCC;
}


void Yeti::requestResolverClear(const AmArg& args, AmArg& ret){
	handler_log();
	resolver::instance()->clear_cache();
	ret = RPC_CMD_SUCC;
}

void Yeti::requestResolverGet(const AmArg& args, AmArg& ret){
	handler_log();
	if(!args.size()){
		throw AmSession::Exception(500,"missed parameter");
	}
	sockaddr_storage ss;
	dns_handle dh;
	int err = resolver::instance()->resolve_name(args.get(0).asCStr(),&dh,&ss,IPv4);
	if(err == -1){
		throw AmSession::Exception(500,"can't resolve");
	}
	ret["address"] = get_addr_str(&ss).c_str();
	dh.dump(ret["handler"]);
}

