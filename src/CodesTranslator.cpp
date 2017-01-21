#include "CodesTranslator.h"
#include "yeti.h"
#include "sip/defs.h"
#include <pqxx/pqxx>

#include "AmSession.h"

CodesTranslator* CodesTranslator::_instance=0;


InternalException::InternalException(unsigned int code):
	icode(code)
{
	CodesTranslator::instance()->translate_db_code(
		icode,
		internal_code,internal_reason,
		response_code,response_reason
	);
}

CodesTranslator::CodesTranslator(){
	stat.clear();
}

CodesTranslator::~CodesTranslator(){
}

CodesTranslator* CodesTranslator::instance()
{
	if(!_instance)
		_instance = new CodesTranslator();
	return _instance;
}

int CodesTranslator::configure(AmConfigReader &cfg){
	db_schema = Yeti::instance().config.routing_schema;
	configure_db(cfg);
	if(load_translations_config()){
		ERROR("can't load resources config");
		return -1;
	}

	return 0;
}

void CodesTranslator::configure_db(AmConfigReader &cfg){
	string prefix("master");
	dbc.cfg2dbcfg(cfg,prefix);
}

bool CodesTranslator::reload(){
	if(load_translations_config()){
		return false;
	}
	return true;
}

int CodesTranslator::load_translations_config(){
	int ret = 1;

	map<int,pref> _code2pref;
	map<int,trans> _code2trans;
	map<unsigned int,icode> _icode2resp;
	map<unsigned int,override> _overrides;

	try {
		pqxx::result r;
		pqxx::connection c(dbc.conn_str());
		c.set_variable("search_path",db_schema+", public");
			pqxx::work t(c);
			//code2pref
			r = t.exec("SELECT * from load_disconnect_code_rerouting()");
			for(pqxx::result::size_type i = 0; i < r.size();++i){
				const pqxx::result::tuple &row = r[i];
				int code = row["received_code"].as<int>(0);
				pref p(row["stop_rerouting"].as<bool>(true));

				_code2pref.insert(pair<int,pref>(code,p));
				DBG("ResponsePref:     %d -> stop_hunting: %d",
					code,p.is_stop_hunting);
			}

			//code2trans
			r = t.exec("SELECT * from load_disconnect_code_rewrite()");
			for(pqxx::result::size_type i = 0; i < r.size();++i){
				const pqxx::result::tuple &row = r[i];
				int code =	row["o_code"].as<int>(0);
				string rewrited_reason = row["o_rewrited_reason"].c_str();
				if(rewrited_reason.empty()){
					rewrited_reason = row["o_reason"].c_str();
				}
				trans t(	row["o_pass_reason_to_originator"].as<bool>(false),
							row["o_rewrited_code"].as<int>(code),
							rewrited_reason);

				_code2trans.insert(pair<int,trans>(code,t));
				DBG("ResponseTrans:     %d -> %d:'%s' pass_reason: %d",
					code,t.rewrite_code,t.rewrite_reason.c_str(),t.pass_reason_to_originator);
			}

			//icode2resp
			r = t.exec("SELECT * from load_disconnect_code_refuse()");
			for(pqxx::result::size_type i = 0; i < r.size();++i){
				const pqxx::result::tuple &row = r[i];
				unsigned int code =	row["o_id"].as<int>(0);

				int internal_code = row["o_code"].as<int>(0);
				string internal_reason = row["o_reason"].c_str();
				int response_code = row["o_rewrited_code"].is_null()?
									internal_code:row["o_rewrited_code"].as<int>();
				string response_reason = row["o_rewrited_reason"].c_str();
				if(response_reason.empty()) //no difference between null and empty string for us
					response_reason = internal_reason;

				icode ic(internal_code,internal_reason,
						response_code,response_reason,
						row["o_store_cdr"].as<bool>(true),
						row["o_silently_drop"].as<bool>(false));
				_icode2resp.insert(pair<unsigned int,icode>(code,ic));

				DBG("DbTrans:     %d -> <%d:'%s'>, <%d:'%s'>",code,
					internal_code,internal_reason.c_str(),
					response_code,response_reason.c_str());
			}

			//code2pref overrides
			r = t.exec("SELECT * from load_disconnect_code_rerouting_overrides()");
			for(pqxx::result::size_type i = 0; i < r.size();++i){
				map<unsigned int,override>::iterator it;
				const pqxx::result::tuple &row = r[i];
				int override_id = row["policy_id"].as<int>();

				int code = row["received_code"].as<int>(0);
				pref p(row["stop_rerouting"].as<bool>(true));

				pair<map<unsigned int,override>::iterator,bool> pit = _overrides.insert(pair<unsigned int,override>(override_id,override()));
				it = pit.first;
				it->second.code2prefs.insert(pair<int,pref>(code,p));

				DBG("Override %d ResponsePref:     %d -> stop_hunting: %d",
					override_id,code,p.is_stop_hunting);
			}

			//code2trans overrides
			r = t.exec("SELECT * from load_disconnect_code_rewrite_overrides()");
			for(pqxx::result::size_type i = 0; i < r.size();++i){
				map<unsigned int,override>::iterator it;
				const pqxx::result::tuple &row = r[i];
				int override_id = row["o_policy_id"].as<int>();

				int code =	row["o_code"].as<int>(0);
				string rewrited_reason = row["o_rewrited_reason"].c_str();
				if(rewrited_reason.empty()){
					rewrited_reason = row["o_reason"].c_str();
				}
				trans t(	row["o_pass_reason_to_originator"].as<bool>(false),
							row["o_rewrited_code"].as<int>(code),
							rewrited_reason);

				pair<map<unsigned int,override>::iterator,bool> pit = _overrides.insert(pair<unsigned int,override>(override_id,override()));
				it = pit.first;
				it->second.code2trans.insert(pair<int,trans>(code,t));

				DBG("Override %d ResponseTrans:     %d -> %d:'%s' pass_reason: %d",
					override_id,code,t.rewrite_code,t.rewrite_reason.c_str(),t.pass_reason_to_originator);
			}

		t.commit();
		c.disconnect();

		INFO("translations are loaded successfully. apply changes");

		code2pref_mutex.lock();
		code2trans_mutex.lock();
		icode2resp_mutex.lock();
		overrides_mutex.lock();

		code2pref.swap(_code2pref);
		code2trans.swap(_code2trans);
		icode2resp.swap(_icode2resp);
		overrides.swap(_overrides);

		code2pref_mutex.unlock();
		code2trans_mutex.unlock();
		icode2resp_mutex.unlock();
		overrides_mutex.unlock();

		ret = 0;
	} catch(const pqxx::pqxx_exception &e){
		ERROR("pqxx_exception: %s ",e.base().what());
	} catch(...){
		ERROR("unexpected exception");
	}

	return ret;
}

void CodesTranslator::rewrite_response(unsigned int code,const string &reason,
				  unsigned int &out_code,string &out_reason,
				  int override_id){


	if(override_id!=0){
		overrides_mutex.lock();
		map<unsigned int,override>::const_iterator oit = overrides.find(override_id);
		if(oit!=overrides.end()){
			map<int,trans>::const_iterator tit = oit->second.code2trans.find(code);
			if(tit!=oit->second.code2trans.end()){
				const trans &t = tit->second;
				string treason = reason;
				out_code = t.rewrite_code;
				out_reason = t.pass_reason_to_originator?treason:t.rewrite_reason;
				overrides_mutex.unlock();
				DBG("translated %d:'%s' -> %d:'%s' with override<%d>",
					code,treason.c_str(),
					out_code,out_reason.c_str(),
					override_id);
				return;
			} else {
				DBG("override<%d> has no translation for code '%d'. use global config",
					override_id,code);
			}
		} else {
			DBG("unknown override<%d>. use global config",
				override_id);
		}
		overrides_mutex.unlock();
	}

	code2trans_mutex.lock();
	map<int,trans>::const_iterator it = code2trans.find(code);
	if(it!=code2trans.end()){
		const trans &t = it->second;
		string treason = reason;
		out_code = t.rewrite_code;
		out_reason = t.pass_reason_to_originator?treason:t.rewrite_reason;
		DBG("translated %d:'%s' -> %d:'%s'",
			code,treason.c_str(),
			out_code,out_reason.c_str());
	} else {
		stat.unknown_response_codes++;
		DBG("no translation for response with code '%d'. leave it 'as is'",code);
		out_code = code;
		out_reason = reason;
	}
	code2trans_mutex.unlock();
}

bool CodesTranslator::stop_hunting(unsigned int code,int override_id){
	bool ret = true;

	if(override_id!=0){
		overrides_mutex.lock();
		map<unsigned int,override>::const_iterator oit = overrides.find(override_id);
		if(oit!=overrides.end()){
			map<int,pref>::const_iterator tit = oit->second.code2prefs.find(code);
			if(tit!=oit->second.code2prefs.end()){
				ret = tit->second.is_stop_hunting;
				overrides_mutex.unlock();
				DBG("stop_hunting = %d for code '%d' with override<%d>",
					ret,code,override_id);
				return ret;
			} else {
				DBG("override<%d> has no translation for code '%d'. use global config",
					override_id,code);
			}
		} else {
			DBG("unknown override<%d>. use global config",
				override_id);
		}
		overrides_mutex.unlock();
	}

	code2pref_mutex.lock();
	map<int,pref>::const_iterator it = code2pref.find(code);
	if(it!=code2pref.end()){
		ret = it->second.is_stop_hunting;
		DBG("stop_hunting = %d for code '%d'",ret,code);
	} else {
		stat.missed_response_configs++;
		DBG("no preference for code '%d', so simply stop hunting",code);
	}
	code2pref_mutex.unlock();
	return ret;
}

bool CodesTranslator::translate_db_code(unsigned int code,
						 unsigned int &internal_code,
						 string &internal_reason,
						 unsigned int &response_code,
						 string &response_reason,
						 int override_id)
{
	bool write_cdr = true;

	icode2resp_mutex.lock();
	map<unsigned int,icode>::const_iterator it = icode2resp.find(code);
	if(it!=icode2resp.end()){
		DBG("found translation for db code '%d'",code);
		const icode &c = it->second;
		internal_code = c.internal_code;
		internal_reason = c.internal_reason;
		if(c.silently_drop
			&& !Yeti::instance().config.early_100_trying)
		{
			response_code = NO_REPLY_DISCONNECT_CODE;
			response_reason = "";
		} else {
			response_code = c.response_code;
			response_reason = c.response_reason;
		}
		write_cdr = c.store_cdr;
		DBG("translation result: internal = <%d:'%s'>, response = <%d:'%s'>, silently_drop = %d, store_cdr = %d",
			internal_code,internal_reason.c_str(),
			response_code,response_reason.c_str(),
			c.silently_drop,c.store_cdr);
	} else {
		stat.unknown_internal_codes++;
		DBG("no translation for db code '%d'. reply with 500",code);
		internal_code = response_code = 500;
		internal_reason = "Internal code "+int2str(code);
		response_reason = SIP_REPLY_SERVER_INTERNAL_ERROR;
	}
	icode2resp_mutex.unlock();
	return write_cdr;
}

void CodesTranslator::GetConfig(AmArg& ret){
	AmArg u;

	ret["config_db"] = dbc.conn_str();
	ret["db_schema"] = db_schema;
	code2pref_mutex.lock();
	{
		map<int,pref>::const_iterator it = code2pref.begin();
		for(;it!=code2pref.end();++it){
			AmArg p;
			p["is_stop_hunting"] = it->second.is_stop_hunting;
			u.push(int2str(it->first),p);
		}
	}
	code2pref_mutex.unlock();
	ret.push("hunting",u);

	u.clear();
	code2trans_mutex.lock();
	{
		map<int,trans>::const_iterator it = code2trans.begin();
		for(;it!=code2trans.end();++it){
			AmArg p;
			const trans &t = it->second;
			p["rewrite_code"] = t.rewrite_code;
			p["rewrite_reason"] = t.rewrite_reason;
			p["pass_reason_to_originator"] = t.pass_reason_to_originator;
			u.push(int2str(it->first),p);
		}
	}
	code2trans_mutex.unlock();
	ret.push("response_translations",u);

	u.clear();
	icode2resp_mutex.lock();
	{
		map<unsigned int,icode>::const_iterator it =  icode2resp.begin();
		for(;it!= icode2resp.end();++it){
			AmArg p;
			const icode &c = it->second;
			p["internal_code"] = c.internal_code;
			p["internal_reason"] = c.internal_reason;
			p["response_code"] = c.response_code;
			p["response_reason"] = c.response_reason;
			u.push(int2str(it->first),p);
		}
	}
	icode2resp_mutex.unlock();
	ret.push("internal_translations",u);

	u.clear();
	overrides_mutex.lock();
	{
		map<unsigned int,override>::const_iterator oit = overrides.begin();
		for(;oit!=overrides.end();++oit){
			AmArg am_override,am_response_translations,am_hunting;

			map<int,trans>::const_iterator tit = oit->second.code2trans.begin();
			for(;tit!=oit->second.code2trans.end();++tit){
				AmArg p;
				const trans &t = tit->second;
				p["rewrite_code"] = t.rewrite_code;
				p["rewrite_reason"] = t.rewrite_reason;
				p["pass_reason_to_originator"] = t.pass_reason_to_originator;
				am_response_translations.push(int2str(tit->first),p);
			}
			am_override.push("response_translations",am_response_translations);

			map<int,pref>::const_iterator pit = oit->second.code2prefs.begin();
			for(;pit!=oit->second.code2prefs.end();++pit){
				AmArg p;
				p["is_stop_hunting"] = pit->second.is_stop_hunting;
				am_hunting.push(int2str(pit->first),p);
			}
			am_override.push("hunting",am_hunting);
			u.push(int2str(oit->first),am_override);
		}
	}
	overrides_mutex.unlock();
	ret.push("overrides_translations",u);
}

void CodesTranslator::clearStats(){
	stat.clear();
}

void CodesTranslator::getStats(AmArg &ret){
	stat.get(ret);
}

