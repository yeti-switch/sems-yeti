#include "CdrList.h"
#include "log.h"
#include "../yeti.h"

CdrList::CdrList(unsigned long buckets):MurmurHash<string,string,Cdr>(buckets){
	//DBG("CdrList()");
}

CdrList::~CdrList(){
	//DBG("~CdrList()");
}

uint64_t CdrList::hash_lookup_key(const string *key){
	//!got segfault due to invalid key->size() value. do not trust it
	//return hashfn(key->c_str(),key->size());
	const char *s = key->c_str();
	return hashfn(s,strlen(s));
}

bool CdrList::cmp_lookup_key(const string *k1,const string *k2){
	return *k1 == *k2;
}

void CdrList::init_key(string **dest,const string *src){
	*dest = new string;
	(*dest)->assign(*src);
}

void CdrList::free_key(string *key){
	delete key;
}

int CdrList::insert(Cdr *cdr){
	int err = 1;
	if(cdr){
		DBG("%s() local_tag = %s",FUNC_NAME,cdr->local_tag.c_str());
		cdr->lock();
			if(!cdr->inserted2list && MurmurHash::insert(&cdr->local_tag,cdr,true,true)){
				err = 0;
				cdr->inserted2list = true;
			} else {
				ERROR("attempt to double insert cdr with local_tag '%s' into active calls list. integrity threat",
					  cdr->local_tag.c_str());
				log_stacktrace(L_ERR);
			}
		cdr->unlock();
	} else {
		ERROR("%s() cdr = NULL",FUNC_NAME);
		log_stacktrace(L_ERR);
	}
	return err;
}

void CdrList::erase_unsafe(const string &local_tag, bool locked){
	erase_lookup_key(&local_tag, locked);
}

int CdrList::erase(Cdr *cdr){
	int err = 1;
	if(cdr){
		//DBG("%s() local_tag = %s",FUNC_NAME,cdr->local_tag.c_str());
		cdr->lock();
			if(cdr->inserted2list){
				//erase_lookup_key(&cdr->local_tag);
				erase_unsafe(cdr->local_tag);
				err = 0;
			} else {
				//ERROR("attempt to erase not inserted cdr local_tag = %s",cdr->local_tag.c_str());
				//log_stacktrace(L_ERR);
			}
		cdr->unlock();
	} else {
		//ERROR("CdrList::%s() cdr = NULL",FUNC_NAME);
		//log_stacktrace(L_ERR);
	}
	return err;
}

Cdr *CdrList::get_by_local_tag(string local_tag){
	return at_data(&local_tag,false);
}

int CdrList::getCall(const string &local_tag,AmArg &call,const SqlRouter *router){
	Cdr *cdr;
	int ret = 0;
	lock();
	if((cdr = get_by_local_tag(local_tag))){
		Yeti::global_config &gc = Yeti::instance()->config;
		const get_calls_ctx ctx(gc.node_id,gc.pop_id,router);
		cdr2arg<Unfiltered>(call,cdr,ctx);
		ret = 1;
	}
	unlock();
	return ret;
}

void CdrList::getCalls(AmArg &calls,int limit,const SqlRouter *router){
	entry *e;
	int i = limit;
	Yeti::global_config &gc = Yeti::instance()->config;

	const get_calls_ctx ctx(gc.node_id,gc.pop_id,router);

	calls.assertArray();

	PROF_START(calls_serialization);
	lock();
		e = first;
		while(e&&i--){
			calls.push(AmArg());
			cdr2arg<Unfiltered>(calls.back(),e->data,ctx);
			e = e->list_next;
		}
	unlock();
	PROF_END(calls_serialization);
	PROF_PRINT("active calls serialization",calls_serialization);
}

void CdrList::getCallsFields(AmArg &calls,int limit,const SqlRouter *router, const AmArg &params){
	entry *e;

	calls.assertArray();
	int i = limit;
	Yeti::global_config &gc = Yeti::instance()->config;

	cmp_rules filter_rules;
	vector<string> fields;

	parse_fields(filter_rules, params, fields);

	validate_fields(fields,router);

	const get_calls_ctx ctx(gc.node_id,gc.pop_id,router,&fields);

	PROF_START(calls_serialization);
	lock();
		e = first;
		while(e&&i--){
			Cdr *cdr = e->data;
			if(apply_filter_rules(cdr,filter_rules)){
				calls.push(AmArg());
				cdr2arg<Filtered>(calls.back(),e->data,ctx);
			}
			e = e->list_next;
		}
	unlock();
	PROF_END(calls_serialization);
	PROF_PRINT("active calls serialization",calls_serialization);
}

void CdrList::getFields(AmArg &ret,SqlRouter *r){
	ret.assertStruct();

	for(const static_call_field *f = static_call_fields; f->name; f++){
		AmArg &a = ret[f->name];
		a["type"] = f->type;
		a["is_dynamic"] = false;
	}

	const DynFieldsT &router_dyn_fields = r->getDynFields();
	for(DynFieldsT::const_iterator it = router_dyn_fields.begin();
			it!=router_dyn_fields.end();++it)
	{
		AmArg &a = ret[it->name];
		a["type"] = it->type_name;
		a["is_dynamic"] = true;
	}
}

void CdrList::validate_fields(const vector<string> &wanted_fields, const SqlRouter *router){
	bool ret = true;
	AmArg failed_fields;
	const DynFieldsT &df = router->getDynFields();
	for(vector<string>::const_iterator i = wanted_fields.begin();
			i!=wanted_fields.end();++i){
		const string &f = *i;
		int k = static_call_fields_count-1;
		for(;k>=0;k--){
			if(f==static_call_fields[k].name)
				break;
		}
		if(k<0){
			//not present in static fields. search in dynamic
			DynFieldsT::const_iterator it = df.begin();
			for(;it!=df.end();++it)
				if(f==it->name)
					break;
			if(it==df.end()){ //not found in dynamic fields too
				ret = false;
				failed_fields.push(f);
			}
		}
	}
	if(!ret){
		throw std::string(string("passed one or more unknown fields:")+AmArg::print(failed_fields));
	}
}

