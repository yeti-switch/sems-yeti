#include "sems.h"
#include "yeti.h"
#include "yeti_rpc.h"
#include "Registration.h"
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

#include "SBCCallLeg.h"
#include "RedisConnection.h"
#include "CodecsGroup.h"
#include "Sensors.h"
#include "yeti_version.h"

#include <cstdio>

static const bool RPC_CMD_SUCC = true;

typedef YetiRpc::rpc_handler YetiRpc::*YetiRpcHandler;

#define handler_log() DBG("execute handler: %s(%s)",FUNC_NAME,args.print(args).c_str());

#define CALL_CORE(name) CoreRpc::instance().name(args,ret);

#define DEFINE_CORE_PROXY_METHOD(Name) \
void YetiRpc::Name(const AmArg& args, AmArg& ret) \
{ \
	handler_log(); \
	CALL_CORE(Name); \
}

#define DEFINE_CORE_PROXY_METHOD_ALTER(Name,CoreName) \
void YetiRpc::Name(const AmArg& args, AmArg& ret) \
{ \
	handler_log(); \
	CALL_CORE(CoreName); \
}

struct CallNotFoundException: public AmSession::Exception {
    CallNotFoundException(string local_tag)
      : AmSession::Exception(404,"call with local_tag: '" +
                             local_tag+"' is not found")
    {}
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

void YetiRpc::init_rpc_tree()
{
#define leaf(parent,leaf,name,descr) \
	AmArg &leaf = reg_leaf(parent,name,descr);

#define method(parent,name,descr,func,func_descr) \
	reg_method(parent,name,descr,&YetiRpc::func,func_descr);

#define leaf_method(parent,leaf,name,descr,func,func_descr) \
	AmArg &leaf = reg_method(parent,name,descr,&YetiRpc::func,func_descr);

#define method_arg(parent,name,descr,func,func_descr,arg, arg_descr) \
	reg_method_arg(parent,name,descr,&YetiRpc::func,func_descr, arg, arg_descr);

#define leaf_method_arg(parent,leaf,name,descr,func,func_descr,arg, arg_descr) \
	AmArg &leaf = reg_method_arg(parent,name,descr,&YetiRpc::func,func_descr, arg, arg_descr);

	/* show */
	leaf(root,show,"show","read only queries");

		method(show,"version","show version",showVersion,"");

		leaf(show,show_resource,"resource","resources related functions");

			leaf_method_arg(show_resource,show_resource_state,"state","get resources state from redis",getResourceState,
							"","<type>/-1 <id>/-1","retreive info about certain resources state");

			leaf_method(show_resource_state,show_resource_state_used,"used","show active resources handlers",showResources,"");
			method_arg(show_resource_state_used,"handler","find resource by handler id",showResourceByHandler,"",
					   "<handler_id>","find resource by handler id");
			method_arg(show_resource_state_used,"owner_tag","find resource by onwer local_tag",showResourceByLocalTag,"",
					   "<onwer_local_tag>","find resource by onwer local_tag");
			method_arg(show_resource_state_used,"resource_id","find handlers which manage resources with ceration id",showResourcesById,"",
					   "<resource_id>","find handlers which manage resources with ceration id");


			method(show_resource,"types","show resources types",showResourceTypes,"");

		method(show,"sensors","show active sensors configuration",showSensorsState,"");
		/*leaf(show,show_sensors,"sensors","sensors related functions");
			method(show_sensors,"state","show active sensors configuration",showSensorsState,"");*/

		leaf(show,show_router,"router","active router instance");
			method(show_router,"cache","show callprofile's cache state",ShowCache,"");

			leaf(show_router,show_router_cdrwriter,"cdrwriter","cdrwriter");
				method(show_router_cdrwriter,"opened-files","show opened csv files",showRouterCdrWriterOpenedFiles,"");

		leaf(show,show_media,"media","media processor instance");
			method(show_media,"streams","active media streams info",showMediaStreams,"");

		leaf_method_arg(show,show_calls,"calls","active calls",GetCalls,"show current active calls",
						"<LOCAL-TAG>","retreive call by local_tag");
			method(show_calls,"count","active calls count",GetCallsCount,"");
			method(show_calls,"fields","show available call fields",showCallsFields,"");
			method_arg(show_calls,"filtered","active calls. specify desired fields",GetCallsFields,"",
					   "<field1> <field2> ...","active calls. send only certain fields");

		method(show,"configuration","actual settings",GetConfig,"");

		method(show,"stats","runtime statistics",GetStats,"");

		method(show,"interfaces","show network interfaces configuration",showInterfaces,"");

		leaf(show,show_auth,"auth","auth");
			leaf(show_auth,show_auth_credentials,"credentials","show loaded credentials hash");
				method(show_auth_credentials,"all","show all credentials",showAuthCredentials,"");
				method(show_auth_credentials,"user","filter credentials by user",showAuthCredentialsByUser,"");
				method(show_auth_credentials,"id","filter credentials by id",showAuthCredentialsById,"");

		leaf_method_arg(show,show_sessions,"sessions","show runtime sessions",
						showSessionsInfo,"active sessions",
						"<LOCAL-TAG>","show sessions related to given local_tag");
			method(show_sessions,"count","active sessions count",showSessionsCount,"");

		leaf_method_arg(show,show_registrations,"registrations","uac registrations",GetRegistrations,"show configured uac registrations",
						"<id>","get registration by id");
			method(show_registrations,"count","active registrations count",GetRegistrationsCount,"");

		leaf(show,show_system,"system","system cmds");
			method(show_system,"log-level","loglevels",showSystemLogLevel,"");
			method(show_system,"status","system states",showSystemStatus,"");
			method(show_system,"alarms","system alarms",showSystemAlarms,"");
			method(show_system,"session-limit","actual sessions limit config",showSessions,"");
			method(show_system,"dump-level","dump_level override value",showSystemDumpLevel,"");

		leaf(show,show_radius,"radius","radius module");
			leaf(show_radius,show_radius_auth,"authorization","auth functionality");
				method_arg(show_radius_auth,"profiles","radius profiles configuration",showRadiusAuthProfiles,"",
						   "<id>","show configuration for certain auth profile");
				method_arg(show_radius_auth,"statistics","radius connections statistic",showRadiusAuthStat,"",
						   "<id>","show stats for certain auth profile");
			leaf(show_radius,show_radius_acc,"accounting","accounting functionality");
				method_arg(show_radius_acc,"profiles","radius accounting profiles configuration",showRadiusAccProfiles,"",
						   "<id>","show configuration for certain accounting profile");
				method_arg(show_radius_acc,"statistics","radius connections statistic",showRadiusAccStat,"",
						   "<id>","show stats for certain accounting profile");

		leaf(show,show_upload,"upload","upload");
			method(show_upload,"destinations","show configured destinations for http_client",showUploadDestinations,"");
			method(show_upload,"stats","show http_client stats",showUploadStats,"");

		leaf(show,show_recorder,"recorder","audio recorder instance");
			method(show_recorder,"stats","show audio recorder processor stats",showRecorderStats,"");

		leaf(show,show_cdrwriter,"cdrwriter","cdrwriter");
			method(show_cdrwriter,"retry_queues","show cdrwriter threads retry_queue content",showCdrWriterRetryQueues,"");

		method(show,"aors","show registered AoRs",showAors,"");
		method(show,"keepalive_contexts","show keepalive contexts",showKeepaliveContexts,"");
	/* request */
	leaf(root,request,"request","modify commands");

		method(request,"upload","upload file using http_client",requestUpload,"<destination_id> <file_name> <path_to_file>");

		leaf(request,request_sensors,"sensors","sensors");
			method(request_sensors,"reload","reload sensors",requestReloadSensors,"");

		leaf(request,request_router,"router","active router instance");

			leaf(request_router,request_router_cdrwriter,"cdrwriter","CDR writer instance");
				method(request_router_cdrwriter,"close-files","immideatly close failover csv files",closeCdrFiles,"");

			leaf(request_router,request_router_translations,"translations","disconnect/internal_db codes translator");
				method(request_router_translations,"reload","reload translator",reloadTranslations,"");

			leaf(request_router,request_router_codec_groups,"codec-groups","codecs groups configuration");
				method(request_router_codec_groups,"reload","reload codecs-groups",reloadCodecsGroups,"");

			leaf(request_router,request_router_resources,"resources","resources actions configuration");
				method(request_router_resources,"reload","reload resources",reloadResources,"");

			leaf(request_router,request_router_cache,"cache","callprofile's cache");
				method(request_router_cache,"clear","clear cached profiles",ClearCache,"");

		leaf(request,request_registrations,"registrations","uac registrations");
			method_arg(request_registrations,"reload","reload reqistrations preferences",reloadRegistrations,
					   "","<id>","reload registration with certain id");

		leaf(request,request_stats,"stats","runtime statistics");
			method(request_stats,"clear","clear all counters",ClearStats,"");

		leaf(request,request_call,"call","active calls control");
			method_arg(request_call,"disconnect","drop call",DropCall,
					   "","<LOCAL-TAG>","drop call by local_tag");
			method_arg(request_call,"remove","remove call from container",RemoveCall,
					   "","<LOCAL-TAG>","remove call by local_tag");


		leaf(request,request_media,"media","media processor instance");
			method_arg(request_media,"payloads","loaded codecs",showPayloads,"show supported codecs",
					   "benchmark","compute transcoding cost for each codec");

		leaf(request,request_system,"system","system commands");

			leaf_method(request_system,request_system_shutdown,"shutdown","shutdown switch",
						requestSystemShutdown,"unclean shutdown");
				method(request_system_shutdown,"immediate","don't wait for active calls",
					   requestSystemShutdownImmediate,"");
				method(request_system_shutdown,"graceful","disable new calls, wait till active calls end",
					   requestSystemShutdownGraceful,"");
				method(request_system_shutdown,"cancel","cancel graceful shutdown",
					   requestSystemShutdownCancel,"");

			leaf(request_system,request_system_log,"log","logging facilities control");
				method(request_system_log,"dump","save in-memory ringbuffer log to file",
					   requestSystemLogDump,"");

		leaf(request,request_resource,"resource","resources cache");
			/*method_arg(request_resource,"state","",getResourceState,
						   "","<type> <id>","get current state of resource");*/
			method(request_resource,"invalidate","invalidate all resources",requestResourcesInvalidate,"");
			leaf(request_resource, request_resource_handler,"handler","handler");
				method(request_resource_handler,"invalidate","invalidate specific handler",requestResourcesHandlerInvalidate,"");

		leaf(request,request_resolver,"resolver","dns resolver instance");
			method(request_resolver,"clear","clear dns cache",requestResolverClear,"");
			method_arg(request_resolver,"get","",requestResolverGet,
						   "","<name>","resolve dns name");

		leaf(request,request_radius,"radius","radius module");
			leaf(request_radius,request_radius_auth,"authorization","authorization");
				leaf(request_radius_auth,request_radius_auth_profiles,"profiles","profiles");
					method(request_radius_auth_profiles,"reload","reload radius profiles",requestRadiusAuthProfilesReload,"");
			leaf(request_radius,request_radius_acc,"accounting","accounting");
				leaf(request_radius_acc,request_radius_acc_profiles,"profiles","profiles");
					method(request_radius_acc_profiles,"reload","reload radius accounting profiles",requestRadiusAccProfilesReload,"");

		leaf(request,request_auth,"auth","auth");
			leaf(request_auth,request_auth_credentials,"credentials","credentials");
				method(request_auth_credentials,"reload","reload auth credentials hash",requestAuthCredentialsReload,"");

		leaf(request,request_cdrwriter,"cdrwriter","cdrwriter");
			method(request_cdrwriter,"pause","pause CDRs processing",requestCdrWriterPause,"");
			method(request_cdrwriter,"resume","resume CDRs processing",requestCdrWriterResume,"");
	/* set */
	leaf(root,lset,"set","set");
		leaf(lset,set_system,"system","system commands");
			leaf(set_system,set_system_log_level,"log-level","logging facilities level");
				method_arg(set_system_log_level,"di_log","",setSystemLogDiLogLevel,
						   "","<log_level>","set new log level");
				method_arg(set_system_log_level,"syslog","",setSystemLogSyslogLevel,
						   "","<log_level>","set new log level");

			method_arg(set_system,"session-limit","",setSessionsLimit,
					   "","<limit> <overload response code> <overload response reason>","set new session limit params");
			leaf(set_system,set_system_dump_level,"dump-level","logging facilities control");
			method(set_system_dump_level,"none","",setSystemDumpLevelNone,"");
			method(set_system_dump_level,"signalling","",setSystemDumpLevelSignalling,"");
			method(set_system_dump_level,"rtp","",setSystemDumpLevelRtp,"");
			method(set_system_dump_level,"full","",setSystemDumpLevelFull,"");

		leaf(lset,set_cdrwriter,"cdrwriter","cdrwriter");
			method(set_cdrwriter,"retry_interval","set cdrwriter retry_interval",setCdrWriterRetryInterval,"");

#undef leaf
#undef method
#undef leaf_method
#undef method_arg
#undef leaf_method_arg
}

void YetiRpc::process_rpc_cmds(const AmArg cmds, const string& method, const AmArg& args, AmArg& ret){
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

void YetiRpc::invoke(const string& method, const AmArg& args, AmArg& ret)
{
	DBG("Yeti: %s(%s)\n", method.c_str(), AmArg::print(args).c_str());

	if (method == "dropCall"){
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
		RpcTreeHandler::invoke(method,args,ret);
		//process_rpc_cmds(rpc_cmds,method,args,ret);
	}/* else {
		throw AmDynInvoke::NotImplemented(method);
	}*/
}

/****************************************
 * 				aux funcs				*
 ****************************************/

bool YetiRpc::check_event_id(int event_id,AmArg &ret){
	bool succ = false;
	try {
		DbConfig dbc;
		string prefix("master");
		dbc.cfg2dbcfg(cfg,prefix);
		pqxx::connection c(dbc.conn_str());
		c.set_variable("search_path",
					   config.routing_schema+", public");
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

bool YetiRpc::assert_event_id(const AmArg &args,AmArg &ret){
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

void YetiRpc::GetCallsCount(const AmArg& args, AmArg& ret) {
	handler_log();
	ret = cdr_list.getCallsCount();
}

void YetiRpc::GetCall(const AmArg& args, AmArg& ret) {
	string local_tag;
	handler_log();

	if (!args.size()) {
		throw AmSession::Exception(500,"Parameters error: expected local tag of requested cdr");
	}

	local_tag = args[0].asCStr();
	if(!cdr_list.getCall(local_tag,ret,&router)){
		throw CallNotFoundException(local_tag);
	}
}

void YetiRpc::GetCalls(const AmArg& args, AmArg& ret) {
	handler_log();
	if(args.size()) {
		string local_tag = args[0].asCStr();
		if(!cdr_list.getCall(local_tag,ret,&router))
			throw CallNotFoundException(local_tag);
	} else {
		cdr_list.getCalls(ret,calls_show_limit,&router);
	}
}

void YetiRpc::GetCallsFields(const AmArg &args, AmArg &ret){
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

void YetiRpc::showCallsFields(const AmArg &args, AmArg &ret){
	cdr_list.getFields(ret,&router);
}

void YetiRpc::GetRegistration(const AmArg& args, AmArg& ret){
	handler_log();

	AmDynInvokeFactory* di_f = AmPlugIn::instance()->getFactory4Di("registrar_client");
	if (di_f == NULL) {
		ERROR("unable to get a registrar_client");
		throw AmSession::Exception(500,"unable to get a registrar_client");
	}

	AmDynInvoke* registrar_client_i = di_f->getInstance();
	if (registrar_client_i==NULL) {
		ERROR("unable to get registrar client invoke instance");
		throw AmSession::Exception(500,"unable to get registrar client invoke instance");
	}

	registrar_client_i->invoke("showRegistrationById", args, ret);
}

void YetiRpc::GetRegistrations(const AmArg& args, AmArg& ret){
	handler_log();
	if(args.size()){
		GetRegistration(args,ret);
		return;
	}
	Registration::instance()->list_registrations(ret);
}

void YetiRpc::GetRegistrationsCount(const AmArg& args, AmArg& ret){
	handler_log();

	(void)args;

	AmDynInvokeFactory* di_f = AmPlugIn::instance()->getFactory4Di("registrar_client");
	if (di_f == NULL) {
		ERROR("unable to get a registrar_client");
		throw AmSession::Exception(500,"unable to get a registrar_client");
	}

	AmDynInvoke* registrar_client_i = di_f->getInstance();
	if (registrar_client_i==NULL) {
		throw AmSession::Exception(500,"unable to get registrar client invoke instance");
	}

	registrar_client_i->invoke("getRegistrationsCount", AmArg(), ret);
}

void YetiRpc::ClearStats(const AmArg& args, AmArg& ret){
	handler_log();
	router.clearStats();
	rctl.clearStats();
	ret = RPC_CMD_SUCC;
}

void YetiRpc::ClearCache(const AmArg& args, AmArg& ret){
	handler_log();
	router.clearCache();
	ret = RPC_CMD_SUCC;
}

void YetiRpc::ShowCache(const AmArg& args, AmArg& ret){
	handler_log();
	router.showCache(ret);
}

void YetiRpc::GetStats(const AmArg& args, AmArg& ret){
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

void YetiRpc::GetConfig(const AmArg& args, AmArg& ret) {
	handler_log();

	ret["calls_show_limit"] = calls_show_limit;
	ret["node_id"] = AmConfig.node_id;
	ret["pop_id"] = config.pop_id;

	router.getConfig(ret["router"]);

	CodesTranslator::instance()->GetConfig(ret["translator"]);
	rctl.GetConfig(ret["resources_control"]);
	CodecsGroups::instance()->GetConfig(ret["codecs_groups"]);
}

void YetiRpc::DropCall(const AmArg& args, AmArg& ret){
	string local_tag;
	handler_log();

	if (!args.size()){
		throw AmSession::Exception(500,"Parameters error: expected local tag of active call");
	}

	local_tag = args[0].asCStr();

	if (!AmSessionContainer::instance()->postEvent(
		local_tag,
		new SBCControlEvent("teardown")))
	{
		throw CallNotFoundException(local_tag);
	}
	ret = "Dropped from sessions container";
}

void YetiRpc::RemoveCall(const AmArg& args, AmArg& ret){
	string local_tag;
	handler_log();

	if (!args.size()){
		throw AmSession::Exception(500,"Parameters error: expected local tag of active call");
	}

	local_tag = args[0].asCStr();

	string ret_reason;

	if (AmSessionContainer::instance()->postEvent(
		local_tag,
		new SBCControlEvent("teardown")))
	{
		ret_reason = "Call found in sessions container. teardown command sent";
	}

	if(cdr_list.remove_by_local_tag(local_tag)) {
		ret_reason += ". Removed from active calls container";
	} else {
		ret_reason += ". Failed to remove from active calls container";
	}

	ret = ret_reason;
}

void YetiRpc::showVersion(const AmArg& args, AmArg& ret) {
	handler_log();
	ret["build"] = YETI_VERSION;
	ret["build_commit"] = YETI_COMMIT;
	ret["compiled_at"] = YETI_BUILD_DATE;
	ret["compiled_by"] = YETI_BUILD_USER;
	ret["core_build"] = get_sems_version();
	CALL_CORE(showVersion);
}

void YetiRpc::reloadResources(const AmArg& args, AmArg& ret){
	handler_log();
	if(!assert_event_id(args,ret))
		return;
	rctl.configure_db(cfg);
	if(!rctl.reload()){
		throw AmSession::Exception(500,"errors during resources config reload. leave old state");
	}
	ret = RPC_CMD_SUCC;
}

void YetiRpc::reloadTranslations(const AmArg& args, AmArg& ret){
	handler_log();
	if(!assert_event_id(args,ret))
		return;
	CodesTranslator::instance()->configure_db(cfg);
	if(!CodesTranslator::instance()->reload()){
		throw AmSession::Exception(500,"errors during translations config reload. leave old state");
	}
	ret = RPC_CMD_SUCC;
}

void YetiRpc::reloadRegistrations(const AmArg& args, AmArg& ret){
	handler_log();
	/*if(!assert_event_id(args,ret))
		return;*/

	if(args.size()){
		if(0==Registration::instance()->reload_registration(cfg,args)){
			ret = RPC_CMD_SUCC;
		} else {
			throw AmSession::Exception(500,"errors during registration config reload. check state");
		}
		return;
	}

	if(0==Registration::instance()->reload(cfg)){
		ret = RPC_CMD_SUCC;
	} else {
		throw AmSession::Exception(500,"errors during registrations config reload. check state");
	}
}

void YetiRpc::reloadCodecsGroups(const AmArg& args, AmArg& ret){
	handler_log();
	if(!assert_event_id(args,ret))
		return;
	CodecsGroups::instance()->configure_db(cfg);
	if(!CodecsGroups::instance()->reload()){
		throw AmSession::Exception(500,"errors during codecs groups reload. leave old state");
	}
	ret = RPC_CMD_SUCC;
}

void YetiRpc::requestReloadSensors(const AmArg& args, AmArg& ret){
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

void YetiRpc::showSensorsState(const AmArg& args, AmArg& ret){
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

	CallCtx *ctx = leg->getCallCtx();
	if(ctx){
		s["attempt_num"] = ctx->attempt_num;
		ctx->lock();
		if(Cdr *cdr = ctx->cdr) cdr->info(s);
		if(SqlCallProfile *profile = ctx->getCurrentProfile()) profile->info(s);
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

void YetiRpc::showSessionsInfo(const AmArg& args, AmArg& ret){
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

void YetiRpc::showRadiusAuthProfiles(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	get_radius_interace()->invoke("showAuthConnections",args,ret);
}

void YetiRpc::showRadiusAccProfiles(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	get_radius_interace()->invoke("showAccConnections",args,ret);
}

void YetiRpc::showRadiusAuthStat(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	get_radius_interace()->invoke("showAuthStat",args,ret);
}

void YetiRpc::showRadiusAccStat(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	get_radius_interace()->invoke("showAccStat",args,ret);
}

void YetiRpc::requestRadiusAuthProfilesReload(const AmArg& args, AmArg& ret){
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

void YetiRpc::requestRadiusAccProfilesReload(const AmArg& args, AmArg& ret){
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

void YetiRpc::closeCdrFiles(const AmArg& args, AmArg& ret){
	handler_log();
	router.closeCdrFiles();
	ret = RPC_CMD_SUCC;
}

void YetiRpc::showRouterCdrWriterOpenedFiles(const AmArg& args, AmArg& ret){
	handler_log();
	(void)args;
	router.showOpenedFiles(ret);
}

void YetiRpc::showSystemStatus(const AmArg& args, AmArg& ret){
	handler_log();
	ret["version"] = YETI_VERSION;
	ret["calls"] = cdr_list.getCallsCount();
	CALL_CORE(showStatus);
}

void YetiRpc::showSystemAlarms(const AmArg& args, AmArg& ret){
	handler_log();
	alarms *a = alarms::instance();
	for(int id = 0; id < alarms::MAX_ALARMS; id++){
		ret.push(AmArg());
		a->get(id).getInfo(ret.back());
	}
}

void YetiRpc::getResourceState(const AmArg& args, AmArg& ret){
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

void YetiRpc::showResources(const AmArg& args, AmArg& ret){
	handler_log();
	rctl.showResources(ret);
}

void YetiRpc::showResourceByHandler(const AmArg& args, AmArg& ret){
	handler_log();
	if(!args.size()){
		throw AmSession::Exception(500,"specify handler id");
	}
	rctl.showResourceByHandler(args.get(0).asCStr(),ret);
}

void YetiRpc::showResourceByLocalTag(const AmArg& args, AmArg& ret){
	handler_log();
	if(!args.size()){
		throw AmSession::Exception(500,"specify local_tag");
	}
	rctl.showResourceByLocalTag(args.get(0).asCStr(),ret);
}

void YetiRpc::showResourcesById(const AmArg& args, AmArg& ret){
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

void YetiRpc::showResourceTypes(const AmArg& args, AmArg& ret){
	handler_log();
	rctl.GetConfig(ret,true);
}

void YetiRpc::requestResourcesInvalidate(const AmArg& args, AmArg& ret){
	handler_log();
	if(rctl.invalidate_resources()){
		ret = RPC_CMD_SUCC;
	} else {
		throw AmSession::Exception(500,"handlers invalidated. but resources initialization failed");
	}
}

void YetiRpc::requestResourcesHandlerInvalidate(const AmArg& args, AmArg& ret)
{
	handler_log();
	args.assertArrayFmt("s");
	rctl.put(args.get(0).asCStr());
	ret = RPC_CMD_SUCC;
}

void YetiRpc::showAuthCredentials(const AmArg&, AmArg& ret)
{
	router.auth_info(ret);
}

void YetiRpc::showAuthCredentialsByUser(const AmArg& args, AmArg& ret)
{
	args.assertArrayFmt("s");
	router.auth_info_by_user(args.get(0).asCStr(),ret);
}

void YetiRpc::showAuthCredentialsById(const AmArg& args, AmArg& ret)
{
	int id;
	args.assertArrayFmt("s");

	if(!str2int(args.get(0).asCStr(),id))
		throw AmSession::Exception(500,"invalid id");

	router.auth_info_by_id(id,ret);
}

void YetiRpc::requestAuthCredentialsReload(const AmArg&, AmArg& ret)
{
	router.db_reload_credentials(ret);
}

void YetiRpc::requestCdrWriterPause(const AmArg&, AmArg& ret)
{
	router.setCdrWriterPaused(true);
	ret = RPC_CMD_SUCC;
}

void YetiRpc::requestCdrWriterResume(const AmArg&, AmArg& ret)
{
	router.setCdrWriterPaused(false);
	ret = RPC_CMD_SUCC;
}

void YetiRpc::setCdrWriterRetryInterval(const AmArg& args, AmArg& ret)
{
	if(!args.size() || !isArgCStr(args[0]))
		throw AmSession::Exception(500, "required interval value");
	int interval;
	if(!str2int(args[0].asCStr(),interval))
		throw AmSession::Exception(500, "failed to cast str2int");
	if(interval < 0)
		throw AmSession::Exception(500, "wrong interval value. must be positive integer");

	router.setRetryInterval(interval);

	ret = RPC_CMD_SUCC;
}

void YetiRpc::showCdrWriterRetryQueues(const AmArg&, AmArg& ret)
{
	router.showRetryQueues(ret);
}


DEFINE_CORE_PROXY_METHOD(showMediaStreams);
DEFINE_CORE_PROXY_METHOD(showSessionsCount);
DEFINE_CORE_PROXY_METHOD(showRecorderStats);
DEFINE_CORE_PROXY_METHOD(showPayloads);
DEFINE_CORE_PROXY_METHOD(showInterfaces);

DEFINE_CORE_PROXY_METHOD(setSessionsLimit);

DEFINE_CORE_PROXY_METHOD(requestResolverClear);
DEFINE_CORE_PROXY_METHOD(requestResolverGet);

DEFINE_CORE_PROXY_METHOD_ALTER(showUploadDestinations,showHttpDestinations);
DEFINE_CORE_PROXY_METHOD_ALTER(showUploadStats,showHttpStats);
DEFINE_CORE_PROXY_METHOD_ALTER(showSystemLogLevel,showLogLevel);
DEFINE_CORE_PROXY_METHOD_ALTER(showSystemDumpLevel,showDumpLevel);
DEFINE_CORE_PROXY_METHOD_ALTER(showSessions,showSessionsLimit);

DEFINE_CORE_PROXY_METHOD_ALTER(setSystemLogSyslogLevel,setLogSyslogLevel);
DEFINE_CORE_PROXY_METHOD_ALTER(setSystemLogDiLogLevel,setLogDiLogLevel);
DEFINE_CORE_PROXY_METHOD_ALTER(setSystemDumpLevelNone,setDumpLevelNone);
DEFINE_CORE_PROXY_METHOD_ALTER(setSystemDumpLevelSignalling,setDumpLevelSignalling);
DEFINE_CORE_PROXY_METHOD_ALTER(setSystemDumpLevelRtp,setDumpLevelRtp);
DEFINE_CORE_PROXY_METHOD_ALTER(setSystemDumpLevelFull,setDumpLevelFull);

DEFINE_CORE_PROXY_METHOD_ALTER(requestUpload,requestHttpUpload);
DEFINE_CORE_PROXY_METHOD_ALTER(requestSystemLogDump,requestLogDump);
DEFINE_CORE_PROXY_METHOD_ALTER(requestSystemShutdown,requestShutdownNormal);
DEFINE_CORE_PROXY_METHOD_ALTER(requestSystemShutdownImmediate,requestShutdownImmediate);
DEFINE_CORE_PROXY_METHOD_ALTER(requestSystemShutdownGraceful,requestShutdownGraceful);
DEFINE_CORE_PROXY_METHOD_ALTER(requestSystemShutdownCancel,requestShutdownCancel);

bool YetiRpc::aor_lookup_reply::parse(const RedisReplyEvent &e)
{
	return false;
}

void YetiRpc::showAors(const AmArg& arg, AmArg& ret)
{
	size_t i,j;

	RegistrarRedisConnection::RpcAorLookupCtx ctx;

	Yeti::instance().registrar_redis.rpc_resolve_aors_blocking(arg, ctx);

	if(RedisReplyEvent::SuccessReply!=ctx.result) {
		throw AmSession::Exception(500, AmArg::print(ctx.data));
	}

	if(!isArgArray(ctx.data) || ctx.data.size()%2!=0)
		throw AmSession::Exception(500, "unexpected redis reply");

	ret.assertArray();

	for(i = 0; i < ctx.data.size(); i+=2) {
		AmArg &id_arg = ctx.data[i];
		if(!isArgLongLong(id_arg)) {
			ERROR("unexpected auth_id type. skip entry");
			continue;
		}

		AmArg &aor_data_arg = ctx.data[i+1];
		if(!isArgArray(aor_data_arg)) {
				ERROR("unexpected aor_data_arg layout. skip entry");
				continue;
		}

		for(j = 0; j < aor_data_arg.size(); j++) {
			AmArg &aor_entry_arg = aor_data_arg[j];
			if(!isArgArray(aor_entry_arg) || aor_entry_arg.size() != 6) {
				ERROR("unexpected aor_entry_arg layout. skip entry");
				continue;
			}

			ret.push(AmArg());
			AmArg &r = ret.back();
			r["auth_id"] = id_arg;
			r["contact"]  = aor_entry_arg[0];
			r["expires"]  = aor_entry_arg[1];
			r["node_id"]  = aor_entry_arg[2];
			r["interface_id"]  = aor_entry_arg[3];
			r["user_agent"]  = aor_entry_arg[4];
			r["path"]  = aor_entry_arg[5];
		}
	}
}

void YetiRpc::showKeepaliveContexts(const AmArg& arg, AmArg& ret)
{
	registrar_redis.dumpKeepAliveContexts(ret);
}
