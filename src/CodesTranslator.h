#ifndef CODESTRANSLATOR_H
#define CODESTRANSLATOR_H

#include "AmConfigReader.h"
#include "AmThread.h"
#include "AmArg.h"
#include <map>
#include "db/DbConfig.h"

//fail codes for TS
#define	FC_PARSE_FROM_FAILED		114
#define	FC_PARSE_TO_FAILED			115
#define	FC_PARSE_CONTACT_FAILED		116
#define FC_NOT_PREPARED				117
#define FC_DB_EMPTY_RESPONSE		118
#define FC_READ_FROM_TUPLE_FAILED	119
#define FC_EVALUATION_FAILED		120
#define FC_GET_ACTIVE_CONNECTION	121
#define FC_DB_BROKEN_EXCEPTION		122
#define FC_DB_CONVERSION_EXCEPTION	123
#define FC_DB_BASE_EXCEPTION		124

#define DC_RTP_TIMEOUT				125
#define DC_NO_ACK					126
#define DC_NO_PRACK					127
#define DC_SESSION_TIMEOUT			128
#define DC_INTERNAL_ERROR			129
#define DC_TRANSACTION_TIMEOUT		130

#define SC_NOT_REGISTERED			131

#define FC_CG_GROUP_NOT_FOUND       140
#define FC_CODECS_NOT_MATCHED       141
#define FC_NO_SUITABLE_MEDIA        142
#define FC_INVALID_MEDIA_TRANSPORT  143

#define DC_REINVITE_ERROR_REPLY     150

#define DC_REPLY_SDP_GENERIC_EXCEPTION	1500
#define DC_REPLY_SDP_PARSING_FAILED		1501
#define DC_REPLY_SDP_EMPTY_ANSWER		1502
#define DC_REPLY_SDP_STREAMS_COUNT		1503
#define DC_REPLY_SDP_STREAMS_TYPES		1504
#define DC_RINGING_TIMEOUT				1505

#define DC_RESOURCE_CACHE_ERROR			1600
#define DC_RESOURCE_UNKNOWN_TYPE		1601

using namespace std;

struct InternalException {
	unsigned int icode, internal_code, response_code;
	string internal_reason, response_reason;
	InternalException(unsigned int code, int override_id);
};

class CodesTranslator {
	static CodesTranslator* _instance;

	/*! actions preferences */
	struct pref {
		bool is_stop_hunting;
		pref(bool stop_hunting)
		  : is_stop_hunting(stop_hunting)
		{}
		void getInfo(AmArg &ret) const;
	};
	using Code2PrefContainer = map<unsigned int,pref>;
	using Code2PrefOverridesContainer = map<unsigned int,Code2PrefContainer>;

	Code2PrefContainer code2pref;
	Code2PrefOverridesContainer code2prefs_overrides;
	AmMutex code2pref_mutex;

	/*! response translation preferences */
	struct trans {
		bool pass_reason_to_originator;
		int rewrite_code;
		string rewrite_reason;
		trans(bool p,int c,string r):
			pass_reason_to_originator(p),
			rewrite_code(c),
			rewrite_reason(r)
		{}
		void getInfo(AmArg &ret) const;
	};
	using Code2TransContainer = map<unsigned int,trans>;
	using Code2TransOverridesContainer = map<unsigned int,Code2TransContainer>;

	Code2TransContainer code2trans;
	Code2TransOverridesContainer code2trans_overrides;
	AmMutex code2trans_mutex;

	/*! internal codes translator */
	struct icode {
		int internal_code,response_code;
		string internal_reason,response_reason;
		bool store_cdr,silently_drop;
		icode(int ic,string ir,int rc, string rr,bool sc,bool sd):
			internal_code(ic),response_code(rc),
			internal_reason(ir), response_reason(rr),
			store_cdr(sc),
			silently_drop(sd)
		{}
		void getInfo(AmArg &ret) const;
	};
	using Icode2RespContainer = map<unsigned int,icode>;
	using Icode2RespOverridesContainer = map<unsigned int,Icode2RespContainer>;

	Icode2RespContainer icode2resp;
	Icode2RespOverridesContainer icode2resp_overrides;
	AmMutex icode2resp_mutex;

	struct {
		unsigned int unknown_response_codes;
		unsigned int missed_response_configs;
		unsigned int unknown_internal_codes;
		void clear(){
			unknown_response_codes = 0;
			missed_response_configs = 0;
			unknown_internal_codes = 0;
		}
		void get(AmArg &arg){
			arg["unknown_code_resolves"] = (long)unknown_response_codes;
			arg["missed_response_configs"] = (long)missed_response_configs;
			arg["unknown_internal_codes"] = (long)unknown_internal_codes;
		}
	} stat;

	bool apply_internal_code_translation(
		const icode &c,
		unsigned int &internal_code,
		string &internal_reason,
		unsigned int &response_code,
		string &response_reason);

  public:
	CodesTranslator();
	~CodesTranslator();
	static CodesTranslator* instance();
	static void dispose();

	int configure(AmConfigReader &cfg);

	void load_disconnect_code_rerouting(const AmArg &data);
	void load_disconnect_code_rewrite(const AmArg &data);
	void load_disconnect_code_refuse(const AmArg &data);

	void load_disconnect_code_refuse_overrides(const AmArg &data);
	void load_disconnect_code_rerouting_overrides(const AmArg &data);
	void load_disconnect_code_rewrite_overrides(const AmArg &data);


	void rewrite_response(unsigned int code,const string &reason,
						  unsigned int &out_code,string &out_reason,
						  int override_id = 0);
	bool stop_hunting(unsigned int code,int override_id = 0);
	bool translate_db_code(unsigned int icode,
								 unsigned int &internal_code,
								 string &internal_reason,
								 unsigned int &response_code,
								 string &response_reason,
								int override_id = 0);

	void GetConfig(AmArg& ret);
	void clearStats();
	void getStats(AmArg &ret);
};

#endif // CODESTRANSLATOR_H
