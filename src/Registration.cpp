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
#define push_str(key) \
	di_args.push(r[#key].c_str());

#define push_int_safe(key,default_value) \
	try { \
		di_args.push(r[#key].as<int>(default_value)); \
	} catch(...) { \
		di_args.push(default_value); \
	}

	AmArg di_args, ret;

	push_str(o_id);
	push_str(o_domain);
	push_str(o_user);
	push_str(o_display_name);
	push_str(o_auth_user);
	push_str(o_auth_password);
	di_args.push(""); //sess_link
	push_str(o_proxy);
	push_str(o_contact);
	push_int_safe(o_expire,0);
	push_int_safe(o_force_expires_interval,0);
	push_int_safe(o_retry_delay,DEFAULT_REGISTER_RETRY_DELAY);
	push_int_safe(o_max_attempts,REGISTER_ATTEMPTS_UNLIMITED);

	registrar_client_i->invoke("createRegistration", di_args, ret);
	DBG("created registration with handle %s",ret[0].asCStr());
	return true;
#undef push_str
#undef push_int_safe
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

int Registration::reload_registration(AmConfigReader &cfg, const AmArg &args)
{
	AmArg tmp;
	string reg_id(args.get(0).asCStr());

	AmDynInvokeFactory* di_f = AmPlugIn::instance()->getFactory4Di("registrar_client");
	if (di_f == NULL) {
		ERROR("unable to get a registrar_client");
		return -1;
	}

	AmDynInvoke* registrar_client_i = di_f->getInstance();
	if (registrar_client_i==NULL) {
		ERROR("unable to get registrar client invoke instance");
		return -1;
	}

	//remove old registration suppressing not existence exceptions
	try {
		registrar_client_i->invoke("removeRegistrationById", args, tmp);
	} catch(AmSession::Exception &e) {
		DBG("exception on removeRegistrationById(%s): %d %s. continue anyway",
			reg_id.c_str(),e.code,e.reason.c_str());
	}

	//load all registrations and try to create the one with specified id
	try {
		string reg_id(args.get(0).asCStr());
		pqxx::result r;
		Yeti::global_config &gc = Yeti::instance().config;

		pqxx::connection c(dbc.conn_str());
		c.set_variable("search_path",gc.routing_schema+", public");

		pqxx::work t(c);
		c.prepare("load_reg","SELECT * from load_registrations_out($1,$2,$3)")
#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
			("integer")("integer")("integer")
#endif
		;
		r = t.prepared("load_reg")(gc.pop_id)(gc.node_id)(reg_id).exec();

		t.commit();
		c.disconnect();

		if(r.size()==0) {
			DBG("empty response from DB for registration with id %s",
				reg_id.c_str());
			return 0;
		}

		const pqxx::result::tuple &row = *r.begin();

		DBG("got response from DB for registration with id %s. add it to registrar_client",
			reg_id.c_str());

		if(!create_registration(row,registrar_client_i))
			ERROR("registration create error");

	} catch(const pqxx::pqxx_exception &e){
		ERROR("pqxx_exception: %s ",e.base().what());
		return -1;
	}

	return 0;
}

