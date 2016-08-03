#include "Registration.h"
#include "AmSipRegistration.h"
#include "ampi/SIPRegistrarClientAPI.h"
#include <pqxx/pqxx>
#include "yeti.h"

#define CHECK_INTERVAL_DEFAULT 5000

Registration* Registration::_instance=0;

Registration* Registration::instance(){
	if(!_instance)
		_instance = new Registration();
	return _instance;
}

Registration::Registration() { }

Registration::~Registration(){ }

void Registration::configure_db(AmConfigReader &cfg){
	string prefix("master");
	dbc.cfg2dbcfg(cfg,prefix);
}

int Registration::load_registrations(){
	int ret = 1;

	AmDynInvokeFactory* di_f = AmPlugIn::instance()->getFactory4Di("registrar_client");
	if (di_f == NULL) {
		ERROR("unable to get a registrar_client");
		return ret;
	}

	AmDynInvoke* registrar_client_i = di_f->getInstance();
	if (registrar_client_i==NULL) {
		ERROR("unable to get registrar client invoke instance");
		return ret;
	}

	try {
		pqxx::result r;
		Yeti::global_config &gc = Yeti::instance().config;

		pqxx::connection c(dbc.conn_str());
		c.set_variable("search_path",gc.routing_schema+", public");

		pqxx::work t(c);
		c.prepare("load_reg","SELECT * from load_registrations_out($1,$2)")
#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
			("integer")("integer")
#endif
		;
		r = t.prepared("load_reg")(gc.pop_id)(gc.node_id).exec();
		for(pqxx::result::size_type i = 0; i < r.size();++i){
			const pqxx::result::tuple &row = r[i];
			if(!create_registration(r[i],registrar_client_i)) {
				ERROR("registration create error");
				break;
			}
		}

		t.commit();
		c.disconnect();

		ret = 0;
	} catch(const pqxx::pqxx_exception &e){
		ERROR("pqxx_exception: %s ",e.base().what());
	}
	return ret;
}

int Registration::configure(AmConfigReader &cfg){

	db_schema = Yeti::instance().config.routing_schema;
	configure_db(cfg);

	if(load_registrations()){
		ERROR("can't load registrations");
		return -1;
	}

	return 0;
}

int Registration::reload(AmConfigReader &cfg){
	DBG("Registration::reload()");
	//remove old registrations
	clean_registrations();
	//add new
	return configure(cfg);
}

bool Registration::create_registration(const pqxx::result::tuple &r, AmDynInvoke* registrar_client_i)
{
	AmArg di_args, reg_handle;
	di_args.push(r["o_id"].c_str());
	di_args.push(r["o_domain"].c_str());
	di_args.push(r["o_user"].c_str());
	di_args.push(r["o_display_name"].c_str());	// display name
	di_args.push(r["o_auth_user"].c_str());		// auth_user
	di_args.push(r["o_auth_password"].c_str());	// pwd
	di_args.push("");
	di_args.push(r["o_proxy"].c_str());
	di_args.push(r["o_contact"].c_str());
	di_args.push(r["o_expire"].as<int>(0));

	registrar_client_i->invoke("createRegistration", di_args, reg_handle);
	string handle = reg_handle.asCStr();
	if(handle.empty()) {
		ERROR("createRegistration invokation failed");
		return false;
	}

	DBG("created registration with handle %s",handle.c_str());
	return true;
}

void Registration::list_registrations(AmArg &ret)
{
	AmDynInvokeFactory* di_f = AmPlugIn::instance()->getFactory4Di("registrar_client");
	if (di_f == NULL) {
		ERROR("unable to get a registrar_client");
		return;
	}

	AmDynInvoke* registrar_client_i = di_f->getInstance();
	if (registrar_client_i==NULL) {
		ERROR("unable to get registrar client invoke instance");
		return;
	}

	ret.assertArray();
	registrar_client_i->invoke("listRegistrations", AmArg(), ret);

	//add node_id and pop_id to the each element of array  to keep compatibility
	const Yeti::global_config &c = Yeti::instance().config;
	for(int i = 0;i < ret.size(); i++) {
		AmArg &a = ret[i];
		a["node_id"] = c.node_id;
		a["pop_id"] = c.pop_id;
	}
}

void Registration::clean_registrations()
{
	AmArg ret, tmp;

	AmDynInvokeFactory* di_f = AmPlugIn::instance()->getFactory4Di("registrar_client");
	if (di_f == NULL) {
		ERROR("unable to get a registrar_client");
		return;
	}

	AmDynInvoke* registrar_client_i = di_f->getInstance();
	if (registrar_client_i==NULL) {
		ERROR("unable to get registrar client invoke instance");
		return;
	}

	ret.assertArray();
	registrar_client_i->invoke("listRegistrations", AmArg(), ret);

	for(int i = 0;i < ret.size(); i++) {
		AmArg arg;
		arg.push(ret[i]["handle"]);
		registrar_client_i->invoke("removeRegistration", arg, tmp);
	}
}

