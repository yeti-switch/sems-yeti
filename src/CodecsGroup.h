#ifndef CODECSGROUP_H
#define CODECSGROUP_H

#include <AmArg.h>
#include <AmSdp.h>

#include "HeaderFilter.h"
#include "db/DbConfig.h"
#include "CodesTranslator.h"

#include <string>
#include <vector>
#include <map>
using namespace std;

#define NO_DYN_PAYLOAD -1

struct CodecsGroupException : public InternalException {
	CodecsGroupException(unsigned int code,unsigned int codecs_group);
};

class CodecsGroupEntry {
	vector<SdpPayload> codecs_payloads;
  public:
	CodecsGroupEntry();
	~CodecsGroupEntry(){}
	bool add_codec(string codec,string sdp_params, int dyn_payload_id);
	vector<SdpPayload> &get_payloads() { return codecs_payloads; }
	void getConfig(AmArg &ret) const;
};

class CodecsGroups {
	static CodecsGroups* _instance;
	AmMutex _lock;

	DbConfig dbc;
	string db_schema;
	map<unsigned int,CodecsGroupEntry> m;

  public:
	CodecsGroups(){}
	~CodecsGroups(){}
	static CodecsGroups* instance(){
		if(!_instance)
			_instance = new CodecsGroups();
		return _instance;
	}
	static void dispose() { if(_instance) delete _instance; }

	int configure(AmConfigReader &cfg);
	void configure_db(AmConfigReader &cfg);
	int load_codecs_groups();
	bool reload();

	void get(int group_id,CodecsGroupEntry &e) {
		_lock.lock();
		map<unsigned int,CodecsGroupEntry>::iterator i = m.find(group_id);
		if(i==m.end()){
			_lock.unlock();
			ERROR("can't find codecs group %d",group_id);
			throw CodecsGroupException(FC_CG_GROUP_NOT_FOUND,group_id);
		}
		e = i->second;
		_lock.unlock();
	}

	bool insert(map<unsigned int,CodecsGroupEntry> &dst, unsigned int group_id, string codec,string sdp_params,int dyn_payload_id = NO_DYN_PAYLOAD) {
		return dst[group_id].add_codec(codec,sdp_params,dyn_payload_id);
	}

	void clear(){ m.clear(); }
	unsigned int size() { return m.size(); }

	void GetConfig(AmArg& ret);
};

#endif // CODECSGROUP_H
