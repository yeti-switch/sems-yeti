#include "Registration.h"
#include "sip/parse_via.h"
#include "AmSipRegistration.h"
#include "ampi/SIPRegistrarClientAPI.h"
#include <pqxx/pqxx>
#include "yeti.h"

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
		auto &gc = Yeti::instance().config;

		pqxx::connection c(dbc.conn_str());
		c.set_variable("search_path",gc.routing_schema+", public");

		pqxx::work t(c);
		c.prepare("load_reg","SELECT * from load_registrations_out($1,$2)")
#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
			("integer")("integer")
#endif
		;
		r = t.exec_prepared("load_reg", gc.pop_id, AmConfig.node_id);
		for(pqxx::row_size_type i = 0; i < r.size();++i){
			const pqxx::row &row = r[i];
			//for(const auto &f: row) DBG("reg[%d] %s: %s",i,f.name(),f.c_str());
			if(!create_registration(row,registrar_client_i)) {
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

bool Registration::create_registration(const pqxx::row &r, AmDynInvoke* registrar_client_i)
{
	AmArg args, ret;

	args.push(AmArg());
	AmArg &ri = args.back();

	static std::vector< std::tuple<const char *, const char *> > str_fields({
		{"id", "o_id"},
		{"domain", "o_domain"},
		{"user", "o_user"},
		{"name", "o_display_name"},
		{"auth_username", "o_auth_user"},
		{"auth_password", "o_auth_password"},
		{"proxy", "o_proxy"},
		{"contact", "o_contact"},
		{"sip_interface_name", "o_sip_interface_name"}
	});
	for(const auto &t: str_fields) {
		try {
			ri[std::get<0>(t)] = r[std::get<1>(t)].c_str();
		} catch(pqxx::pqxx_exception &e) {
			DBG("pqxx exception for tuple (%s,%s): %s",
				std::get<0>(t), std::get<1>(t),
				e.base().what());
		}
	}

	static std::vector< std::tuple<const char *, const char *, int> > int_fields({
		{"expires_interval", "o_expire", 0},
		{"retry_delay", "o_retry_delay", DEFAULT_REGISTER_RETRY_DELAY},
		{"max_attempts", "o_max_attempts", REGISTER_ATTEMPTS_UNLIMITED},
		{"transport_protocol_id", "o_transport_protocol_id", sip_transport::UDP},
		{"proxy_transport_protocol_id", "o_proxy_transport_protocol_id", sip_transport::UDP},
		{"scheme_id", "o_scheme_id", sip_uri::SIP}
	});
	for(const auto &t: int_fields) {
		try {
			ri[std::get<0>(t)] = r[std::get<1>(t)].as<int>(std::get<2>(t));
		} catch(pqxx::pqxx_exception &e) {
			DBG("exception on tuple: %s %s %d. use default value: %s",
				std::get<0>(t), std::get<1>(t), std::get<2>(t),
				e.base().what());
			ri[std::get<0>(t)] = std::get<2>(t);
		}
	}

	static std::vector< std::tuple<const char *, const char *, bool> > bool_fields({
		{"force_expires_interval", "o_force_expire", false},
	});
	for(const auto &t: bool_fields) {
		try {
			ri[std::get<0>(t)] = static_cast<int>(r[std::get<1>(t)].as<bool>(std::get<2>(t)));
		} catch(pqxx::pqxx_exception &e) {
			DBG("exception on tuple: %s %s %d. use default value: %s",
				std::get<0>(t), std::get<1>(t), std::get<2>(t),
				e.base().what());
			ri[std::get<0>(t)] = static_cast<int>(std::get<2>(t));
		}
	}

	registrar_client_i->invoke("createRegistration", args, ret);

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
	const auto &c = Yeti::instance().config;
	for(int i = 0;i < ret.size(); i++) {
		AmArg &a = ret[i];
		a["node_id"] = AmConfig.node_id;
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
		auto &gc = Yeti::instance().config;

		pqxx::connection c(dbc.conn_str());
		c.set_variable("search_path",gc.routing_schema+", public");

		pqxx::work t(c);
		c.prepare("load_reg","SELECT * from load_registrations_out($1,$2,$3)")
#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
			("integer")("integer")("integer")
#endif
		;
		r = t.exec_prepared("load_reg", gc.pop_id, AmConfig.node_id, reg_id);

		t.commit();
		c.disconnect();

		if(r.size()==0) {
			DBG("empty response from DB for registration with id %s",
				reg_id.c_str());
			return 0;
		}

		const pqxx::row &row = *r.begin();

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

