#include "Registration.h"
#include "sip/parse_via.h"
#include "AmSipRegistration.h"
#include "ampi/SIPRegistrarClientAPI.h"
#include "yeti.h"
#include "db/DbHelpers.h"

Registration* Registration::_instance=0;

Registration* Registration::instance(){
	if(!_instance)
		_instance = new Registration();
	return _instance;
}

void Registration::dispose() {
	if(_instance)
		delete _instance;
}

Registration::Registration()
  : registrar_client_i(nullptr)
{
	AmDynInvokeFactory* di_f = AmPlugIn::instance()->getFactory4Di("registrar_client");
	if (di_f == nullptr) {
		ERROR("unable to get a registrar_client");
		return;
	}

	registrar_client_i = di_f->getInstance();
	if (registrar_client_i == nullptr) {
		ERROR("unable to get registrar client invoke instance");
		return;
	}
}

Registration::~Registration()
{ }

void Registration::load_registrations(const AmArg &data)
{
	if(!registrar_client_i) {
		ERROR("unable to get registar_client module api");
		return;
	}

	RegistrationsContainer db_registrations;
	if(isArgArray(data)) {
		for(size_t i = 0; i < data.size(); i++) {
			if(!read_registration(data[i],db_registrations)) {
				ERROR("registration read error");
				continue;
			}
		}
	}

	/*for(const auto &r : db_registrations) {
		BG("db registration %s:%s",
			r.first.data(), AmArg::print(r.second).data());
	}
	for(const auto &r : registrations) {
		DBG("local registration %s:%s",
			r.first.data(), AmArg::print(r.second).data());
	}*/

	//process removed and updated
	for(const auto &r : registrations) {
		auto it = db_registrations.find(r.first);
		if(it != db_registrations.end()) {
			if(is_reg_updated(r.second, it->second)) {
				//changed in db. update
				DBG("update registration. id:%s", r.first.data());
				remove_registration(r.first);
				add_registration(it->second);
			}
			//keep untouched
		} else {
			//present locally. removed from DB
			DBG("remove registration. id:%s", r.first.data());
			remove_registration(r.first);
		}
	}

	//process new
	for(const auto &r : db_registrations) {
		if(!registrations.count(r.first)) {
			DBG("add registration. id:%s", r.first.data());
			add_registration(r.second);
		}
	}

	registrations.swap(db_registrations);
}

int Registration::configure(AmConfigReader &)
{
	return 0;
}

bool Registration::read_registration(const AmArg &r, RegistrationsContainer &regs)
{
	string id = DbAmArg_hash_get_str_any(r, "o_id");
	AmArg &ri = regs.try_emplace(id).first->second;

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
		ri[std::get<0>(t)] = DbAmArg_hash_get_str_any(r, std::get<1>(t));
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
		ri[std::get<0>(t)]= DbAmArg_hash_get_int(
			r, std::get<1>(t), std::get<2>(t));
	}

	static std::vector< std::tuple<const char *, const char *, bool> > bool_fields({
		{"force_expires_interval", "o_force_expire", false},
	});
	for(const auto &t: bool_fields) {
		ri[std::get<0>(t)] = (int)DbAmArg_hash_get_bool(
			r, std::get<1>(t), std::get<2>(t));
	}

	return true;
}

bool Registration::is_reg_updated(const AmArg &local_reg, const AmArg &db_reg)
{
	for(const auto &r : local_reg) {
		if(r.second != db_reg[r.first]) {
			return true;
		}
	}
	return false;
}

void Registration::add_registration(const AmArg &r)
{
	AmArg arg, ret;
	arg.push(r);
	registrar_client_i->invoke("createRegistration", arg, ret);
}

void Registration::remove_registration(const string &reg_id)
{
	AmArg arg, ret;
	arg.push(reg_id);
	registrar_client_i->invoke("removeRegistrationById", arg, ret);
}

void Registration::list_registrations(AmArg &ret)
{
	ret.assertArray();

	if(!registrar_client_i)
		return;

	registrar_client_i->invoke("listRegistrations", AmArg(), ret);

	//add node_id and pop_id to the each element of array  to keep compatibility
	const auto &c = Yeti::instance().config;
	for(size_t i = 0;i < ret.size(); i++) {
		AmArg &a = ret[i];
		a["node_id"] = AmConfig.node_id;
		a["pop_id"] = c.pop_id;
	}
}
