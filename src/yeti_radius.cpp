#include "yeti_radius.h"

//#include "AmPlugIn.h"
#include "AmApi.h"
#include "jsonArg.h"

int YetiRadius::init_radius_module(AmConfigReader& cfg)
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

int YetiRadius::init_radius_auth_connections(AmDynInvoke* radius_client)
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

		for(pqxx::row_size_type i = 0; i < r.size();++i){
			AmArg args,ret;
			const pqxx::row &t = r[i];

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

int YetiRadius::init_radius_acc_connections(AmDynInvoke* radius_client)
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

		for(pqxx::row_size_type i = 0; i < r.size();++i){
			AmArg args,ret;
			const pqxx::row &t = r[i];

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
