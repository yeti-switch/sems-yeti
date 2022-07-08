#include "CdrFilter.h"

#include <map>
#include <algorithm>
#include <sstream>

const static_call_field static_call_fields[] = {
	{ "node_id", "integer", c_field_unsupported },
	{ "pop_id", "integer", c_field_unsupported },
	{ "local_time", "timestamp", c_field_unsupported },
	{ "cdr_born_time", "timestamp", c_field_unsupported },
	{ "start_time", "timestamp", c_field_unsupported },
	{ "connect_time", "timestamp", c_field_connect_time },
	{ "end_time", "timestamp", c_field_unsupported },
	{ "duration", "double", c_field_duration },
	{ "attempt_num", "integer", c_field_attempt_num },
	{ "resources", "string", c_field_unsupported },
	{ "active_resources", "string", c_field_unsupported },
	{ "active_resources_json", "string", c_field_unsupported },
	{ "legB_remote_port", "integer", c_field_unsupported },
	{ "legB_local_port", "integer", c_field_unsupported },
	{ "legA_remote_port", "integer", c_field_unsupported },
	{ "legA_local_port", "integer", c_field_unsupported },
	{ "legB_remote_ip", "string", c_field_unsupported },
	{ "legB_local_ip", "string", c_field_unsupported },
	{ "legA_remote_ip", "string", c_field_unsupported },
	{ "legA_local_ip", "string", c_field_unsupported },
	{ "orig_call_id", "string", c_field_unsupported },
	{ "term_call_id", "string", c_field_unsupported },
	{ "local_tag", "string", c_field_unsupported },
	{ "global_tag", "string", c_field_unsupported },
	{ "time_limit", "integer", c_field_unsupported },
	{ "dump_level_id", "integer", c_field_unsupported },
	{ "audio_record_enabled", "integer", c_field_unsupported },
	{ "versions", "json", c_field_unsupported },
	{ nullptr, nullptr, c_field_unsupported }
};
const unsigned int static_call_fields_count = 28;

/* maps to accelerate rules parsing.
 * inited in int configure_filter(const SqlRouter *router) */

static map<string,cmp_field_t> field_name2field_type;
typedef map<string,cmp_field_t>::const_iterator field_name2field_type_iterator;

static map<string,cmp_type_t> field_name2type;
typedef map<string,cmp_type_t>::const_iterator field_name2type_iterator;

static map<string,cmp_cond_t> cond_name2type;
typedef map<string,cmp_cond_t>::const_iterator cond_name2type_iterator;


//resolve sql types into internal type id
static cmp_type_t get_type_by_name(const string &type_name){
	if(type_name=="integer"
	   || type_name=="smallint"
	   || type_name=="boolean")
	{
		return c_type_int;
	} else if(type_name=="bigint") {
		return c_type_long_long_int;
	} else if(type_name=="string"
			  || type_name=="varchar"
			  || type_name=="json"
			  || type_name=="inet"
			  || type_name=="numeric"
			  || type_name=="smallint[]")
	{
		return c_type_string;
	} else if(type_name=="timestamp"){
		return c_type_timestamp;
	} else if(type_name=="double"){
		return c_type_double;
	}
	throw std::string("unsupported field type '"+type_name+"'");
}

/* type2name conversions
 * must comply to enums in header
 */

static const char *name_unknown = "unknown";

static const char *cmp_type_names[] = {
	"int",
	"long long int",
	"string",
	"timestamp",
	"double"
};
static const char *get_cmp_type_name(cmp_type_t type){
	if(type>=c_type_max || type < 0){
		return name_unknown;
	}
	return cmp_type_names[type];
}

static const char *cmp_field_names[] = {
	"unsupported",
	"DYNAMIC",
	"duration",
	"connect_time",
	"attempt_num"
};
static const char *get_cmp_field_name(cmp_field_t field){
	if(field>=c_field_max || field < 0){
		return name_unknown;
	}
	return cmp_field_names[field];
}

static const char *cmp_cond_names[] = {
	"=",
	"!=",
	">",
	"<",
	">=",
	"<="
};
static const char *get_cmp_cond_name(cmp_cond_t cond){
	if(cond>=c_cond_max || cond < 0){
		return name_unknown;
	}
	return cmp_cond_names[cond];
}

/************************
 *		comparators		*
 ************************/

//generic comparators

#define COMPARATOR_NAME(type,field,sop) cmp_ ## type ## _ ## field ## _ ## sop

#define GENERIC_STATIC_COMPARATOR(field,type,op,sop) \
	static bool COMPARATOR_NAME(type,field,sop)(const Cdr *cdr,type value){ \
		DBG("called %s for Cdr[%p]",FUNC_NAME,cdr);\
		return cdr->field op value; \
	}

#define TIMESTAMP_STATIC_COMPARATOR(field,type,op,sop) \
	static bool COMPARATOR_NAME(type,field,sop)(const Cdr *cdr,const timeval &value){ \
		DBG("called %s for Cdr[%p]",FUNC_NAME,cdr);\
		if(!cdr->field.tv_sec){ \
			DBG("CDR timestamp field "#field" is not initialized. return false"); \
			return false; \
		} \
		return cdr->field.tv_sec op value.tv_sec; \
	}

#define ACTIVE_COMPARATOR(field,type,op,sop) GENERIC_STATIC_COMPARATOR(field,type,op,sop)

#define EQ_STATIC_COMPARATOR(field,type) ACTIVE_COMPARATOR(field,type,==,eq)
#define NEQ_STATIC_COMPARATOR(field,type) ACTIVE_COMPARATOR(field,type,!=,neq)
#define GT_STATIC_COMPARATOR(field,type) ACTIVE_COMPARATOR(field,type,>,gt)
#define LT_STATIC_COMPARATOR(field,type) ACTIVE_COMPARATOR(field,type,<,lt)
#define GTE_STATIC_COMPARATOR(field,type) ACTIVE_COMPARATOR(field,type,>=,gte)
#define LTE_STATIC_COMPARATOR(field,type) ACTIVE_COMPARATOR(field,type,<=,lte)

#define DEFINE_STATIC_FIELD_COMPARATORS(field,type) \
	EQ_STATIC_COMPARATOR(field,type) \
	NEQ_STATIC_COMPARATOR(field,type) \
	GT_STATIC_COMPARATOR(field,type) \
	LT_STATIC_COMPARATOR(field,type) \
	GTE_STATIC_COMPARATOR(field,type) \
	LTE_STATIC_COMPARATOR(field,type)


DEFINE_STATIC_FIELD_COMPARATORS(attempt_num,int)

#undef ACTIVE_COMPARATOR
#define ACTIVE_COMPARATOR(field,type,op,sop) TIMESTAMP_STATIC_COMPARATOR(field,type,op,sop)

DEFINE_STATIC_FIELD_COMPARATORS(connect_time,timestamp)

/* comparators for dynamic fields */

#define DEF_ALL_OPS(MACRO_NAME) \
	MACRO_NAME(==,eq) \
	MACRO_NAME(!=,neq) \
	MACRO_NAME(>,gt) \
	MACRO_NAME(<,lt) \
	MACRO_NAME(>=,gte) \
	MACRO_NAME(<=,lte)

#define DYN_COMPARATOR_NAME(type,op) cmp_dyn_ ## type ## _function_ ## op

#define DEF_DYN_CMP_INT_FUNC(op,opname) \
static bool cmp_dyn_int_function_ ##opname(const Cdr *cdr, \
										 const string& field_name, \
										 int value) \
{ \
	if(!cdr->dyn_fields.hasMember(field_name)){ \
		ERROR("can't find dynamic field %s in %s",field_name.c_str(),FUNC_NAME); \
		return false; \
	} \
	AmArg &a = cdr->dyn_fields[field_name]; \
	if(a.getType()!=AmArg::Int){ \
		ERROR("invalid type for field %s in %s",field_name.c_str(),FUNC_NAME); \
		return false; \
	} \
	return a.asInt() op value; \
}
DEF_ALL_OPS(DEF_DYN_CMP_INT_FUNC)

#define DEF_DYN_CMP_LONG_LONG_INT_FUNC(op,opname) \
static bool cmp_dyn_long_long_int_function_ ##opname(const Cdr *cdr, \
										 const string& field_name, \
										 long_long_int value) \
{ \
	if(!cdr->dyn_fields.hasMember(field_name)){ \
		ERROR("can't find dynamic field %s in %s",field_name.c_str(),FUNC_NAME); \
		return false; \
	} \
	AmArg &a = cdr->dyn_fields[field_name]; \
	if(isArgInt(a)) { \
		return a.asLong() op value; \
	} else if(isArgLongLong(a)) { \
		return a.asLongLong() op value; \
	} \
	ERROR("invalid type for field %s in %s",field_name.c_str(),FUNC_NAME); \
	return false; \
}
DEF_ALL_OPS(DEF_DYN_CMP_LONG_LONG_INT_FUNC)

#define DEF_DYN_CMP_STRING_FUNC(op,opname) \
static bool cmp_dyn_string_function_ ##opname(const Cdr *cdr, \
										 const string& field_name, \
										 const string& value) \
{ \
	if(!cdr->dyn_fields.hasMember(field_name)){ \
		ERROR("can't find dynamic field %s in %s",field_name.c_str(),FUNC_NAME); \
		return false; \
	} \
	AmArg &a = cdr->dyn_fields[field_name]; \
	if(a.getType()!=AmArg::CStr){ \
		ERROR("invalid type for field '%s' in %s",field_name.c_str(),FUNC_NAME); \
		return false; \
	} \
	return value op a.asCStr(); \
}

DEF_DYN_CMP_STRING_FUNC(==,eq)
DEF_DYN_CMP_STRING_FUNC(!=,neq)

/* macro definitions for static field case declaration in functor constructor */

#define CMP_FIELD_PTR_CASE(type,name,op) \
	case c_cond_ ## op: fptr_ ## type = &COMPARATOR_NAME(type,name,op); break;

#define CMP_FIELD_TYPE_CASES(type,name) \
	switch(cmp_cond){ \
		CMP_FIELD_PTR_CASE(type,name,eq) \
		CMP_FIELD_PTR_CASE(type,name,neq) \
		CMP_FIELD_PTR_CASE(type,name,gt) \
		CMP_FIELD_PTR_CASE(type,name,lt) \
		CMP_FIELD_PTR_CASE(type,name,gte) \
		CMP_FIELD_PTR_CASE(type,name,lte) \
		default: \
			throw string(string("condition ")+get_cmp_cond_name(cmp_cond)+ \
						" for field "+get_cmp_field_name(cmp_field) + " is not implemented"); \
	} \

#define CMP_FIELD_CASE(type,name) \
	case c_field_ ## name: \
	CMP_FIELD_TYPE_CASES(type,name) \
	break

/* macro definitions for dynamic fields case declaration in functor constructor */

#define DYN_FIELD_PTR_CASE(type,op) \
	case c_cond_ ## op: fptr_dyn_ ## type = &DYN_COMPARATOR_NAME(type,op); break;

#define DYN_FIELD_CASE(type) \
	switch(cmp_cond){ \
	DYN_FIELD_PTR_CASE(type,eq) \
	DYN_FIELD_PTR_CASE(type,neq) \
	DYN_FIELD_PTR_CASE(type,gt) \
	DYN_FIELD_PTR_CASE(type,lt) \
	DYN_FIELD_PTR_CASE(type,gte) \
	DYN_FIELD_PTR_CASE(type,lte) \
	default: \
		throw string(string("condition ")+get_cmp_cond_name(cmp_cond)+ \
					" for dynamic field "+dyn_field_name + " is not implemented"); \
	} \

/* functor constructors */

//static fields with type int
cmp_functor::cmp_functor(int value, cmp_field_t cmp_field, cmp_cond_t cmp_cond)
	: cmp_type(c_type_int), cmp_field(cmp_field), cmp_cond(cmp_cond),
	  v_int(value)
{
	switch(cmp_field){
	//CMP_FIELD_CASE(int,time_limit);
	CMP_FIELD_CASE(int,attempt_num);
	default:
		throw string(string("unknown field: ")+int2str(cmp_field));
	}
	DBG("created functor %s",info().c_str());
}

static cmp_cond_t condition_directons_invert[] = {
	c_cond_eq,
	c_cond_neq,
	c_cond_lt,
	c_cond_gt,
	c_cond_lte,
	c_cond_gte,
};
static inline cmp_cond_t invert_condition_direction(cmp_cond_t condition){
	return condition_directons_invert[condition];
}

//static fields with type double
cmp_functor::cmp_functor(double value, cmp_field_t cmp_field_in, cmp_cond_t cmp_cond_in)
	: cmp_type(c_type_double), cmp_field(cmp_field_in), cmp_cond(cmp_cond_in),
	  v_double(value)
{
	switch(cmp_field){
	case c_field_duration:
		//DBG("requested functor for pseudo-field 'duration'. replace it with asjusted connect_time comparsion implicit");
		timeval now;
		gettimeofday(&now,NULL);
		//adjust parameter, change functor type and condition direction on the fly
		v_time.tv_sec = now.tv_sec-v_double;
		cmp_cond = invert_condition_direction(cmp_cond);
		cmp_field = c_field_connect_time;
		cmp_type = c_type_timestamp;
		CMP_FIELD_TYPE_CASES(timestamp,connect_time)
	break;
	default:
		throw string(string("unknown field: ")+int2str(cmp_field));
	}
	DBG("created functor %s",info().c_str());
}

//static fields with type timestamp
cmp_functor::cmp_functor(const timeval &value, cmp_field_t cmp_field, cmp_cond_t cmp_cond)
	: cmp_type(c_type_timestamp), cmp_field(cmp_field), cmp_cond(cmp_cond),
	  v_time(value)
{
	switch(cmp_field){
	CMP_FIELD_CASE(timestamp,connect_time);
	default:
		throw string(string("unknown field: ")+int2str(cmp_field));
	}
	DBG("created functor %s",info().c_str());
}

//dynamic fields with type int
cmp_functor::cmp_functor(int value,const string &field_name,cmp_cond_t cmp_cond)
	: cmp_type(c_type_int), cmp_field(c_field_dynamic), cmp_cond(cmp_cond),
	  v_int(value), dyn_field_name(field_name)
{
	DYN_FIELD_CASE(int)
	DBG("created functor %s",info().c_str());
}

//dynamic fields with type bigint (long long int)
cmp_functor::cmp_functor(long long int value,const string &field_name,cmp_cond_t cmp_cond)
	: cmp_type(c_type_long_long_int), cmp_field(c_field_dynamic), cmp_cond(cmp_cond),
	  v_long_long_int(value), dyn_field_name(field_name)
{
	DYN_FIELD_CASE(long_long_int)
	DBG("created functor %s",info().c_str());
}


//dynamic fields with type string
cmp_functor::cmp_functor(const string &value,const string &field_name,cmp_cond_t cmp_cond)
	: cmp_type(c_type_string), cmp_field(c_field_dynamic), cmp_cond(cmp_cond),
	  v_string(value), dyn_field_name(field_name)
{
	switch(cmp_cond){
	DYN_FIELD_PTR_CASE(string,eq)
	DYN_FIELD_PTR_CASE(string,neq)
	default:
		throw string(string("condition ")+get_cmp_cond_name(cmp_cond)+
							" for dynamic field "+dyn_field_name + " is not implemented"); \
	}
	DBG("created functor %s",info().c_str());
}

//match function
bool cmp_functor::operator()(const Cdr *cdr) const {
	if(cmp_field==c_field_dynamic){
		switch(cmp_type){
		case c_type_int:
			return (*fptr_dyn_int)(cdr,dyn_field_name,v_int);
			break;
		case c_type_long_long_int:
			return (*fptr_dyn_long_long_int)(cdr,dyn_field_name,v_long_long_int);
			break;
		case c_type_string:
			return (*fptr_dyn_string)(cdr,dyn_field_name,v_string);
			break;
		default:
			;
		}
	} else {
		switch(cmp_type){
		case c_type_int:
			return (*fptr_int)(cdr,v_int);
			break;
		case c_type_double:
			return (*fptr_double)(cdr,v_double);
			break;
		case c_type_timestamp:
			return (*fptr_timestamp)(cdr,v_time);
			break;
		default:
			;
		}
	}
	ERROR("wrong initialized cmp_functor: %s",info().c_str());
	return false;
}

string cmp_functor::info() const {
	stringstream info;

	info << std::dec <<  this << ":" << get_cmp_type_name(cmp_type) << " ";

	if(cmp_field!=c_field_dynamic) info << get_cmp_field_name(cmp_field) << " ";
	else info << dyn_field_name << "(dynamic) ";

	info << get_cmp_cond_name(cmp_cond) << " ";

	switch(cmp_type){
	case c_type_int: info << v_int; break;
	case c_type_long_long_int: info << v_long_long_int; break;
	case c_type_timestamp:
		info << v_time.tv_sec << " (" << timeval2str(v_time) << ")";
		break;
	case c_type_double: info << v_double; break;
	case c_type_string: info << v_string; break;
	default:
		info << "?";
	}
	return info.str();
}

bool apply_filter_rules(const Cdr *cdr,const cmp_rules &rules){
	bool matched = true;
	for(cmp_rules_it it = rules.begin(); it!=rules.end(); ++it){
		if(!(*it)(cdr)) {
			DBG("[%s] NOT MATCHED against functor: %s",
				cdr->local_tag.c_str(),
				it->info().c_str());
			matched = false;
			break;
		} else {
			DBG("[%s] MATCHED against functor: %s",
				cdr->local_tag.c_str(),
				it->info().c_str());
		}
	}
	return matched;
}

/* helper to parse rule string
 * in: ptr to string and it length
 * out: ptr to the beginning of operator and his len in op_len
 *      will return NULL ptr on errors */
const char *get_operator_pos(const char *s,int len,int &op_len){
	if(len < 3) {
		ERROR("input rule string is too short");
		return NULL;
	}
	for(int i = 0;i<len;i++){
		switch(s[i]){
		case '=': //definitely =
			if(i>=len-1){
				ERROR("no characters after operator '='");
				return NULL;
			}
			op_len = 1;
			return s+i; //return =
			break;
		case '!': //possible !=
			if(i>=len-2){
				ERROR("no characters after operator which starts with '!'");
				return NULL;
			}
			if(s[i+1]=='='){
				op_len = 2;
				return s+i; //return !=
			}
			ERROR("uknown operator which starts with '!'");
			return NULL;
			break;
		case '<': //possible > or >=
		case '>': //possible > or >=
			if(i>=len-1){
				ERROR("no characters after operator which starts with '>' or '<'");
				return NULL;
			}
			if(s[i+1]=='='){ //definitely >= or <=
				if(i>=len-2){
					ERROR("no characters after operator '>=' or '<='");
					return NULL;
				}
				op_len = 2;
				return s+i; //return >= or <=
			}
			op_len = 1;
			return s+i; //return > or <
			break;
		}
	}
	ERROR("can't recognize any operator in string: %s",s);
	return NULL;
}

//function acts as factory for functors from parsed field, operator and value
void insert_rule(cmp_rules &rules,
				 const string &field,
				 const string &op,
				 const string &value)
{
	field_name2type_iterator field_type_it = field_name2type.find(field);
	if(field_type_it==field_name2type.end()){
		throw string("unknown field "+field+" in WHERE clause");
	}
	cmp_type_t field_type = field_type_it->second;

	cmp_field_t field_name_type = c_field_dynamic;
	field_name2field_type_iterator field_name_type_it =
			field_name2field_type.find(field);
	if(field_name_type_it!=field_name2field_type.end()){
		//it's static field
		field_name_type = field_name_type_it->second;
	}
	if(field_name_type==c_field_unsupported){
		throw string("field "+field+" is known but unsupported");
	}

	cond_name2type_iterator cond_type_it = cond_name2type.find(op);
	if(cond_type_it==cond_name2type.end()){
		throw string("unsupported operator "+op);
	}
	cmp_cond_t cond_type = cond_type_it->second;

	switch(field_type){
	case c_type_timestamp: {
		double v_double;
		if(0==sscanf(value.c_str(),"%lf",&v_double)){
			throw string(string("can't cast '")+value+"' to double");
		}
		timeval v_timestamp = {0,0};
		v_timestamp.tv_sec = v_double; //warn: precision reduced down to seconds
		if(field_name_type==c_field_dynamic) throw string(string("not supported dynamic field type: ")+get_cmp_type_name(field_type));
		else rules.push_back(cmp_functor(v_timestamp,field_name_type,cond_type));
	} break;
	case c_type_int: {
		int v_int;
		if(!str2int(value,v_int)){
			throw string(string("can't cast '")+value+"' to integer");
		}
		if(field_name_type==c_field_dynamic) rules.push_back(cmp_functor(v_int,field,cond_type));
		else rules.push_back(cmp_functor(v_int,field_name_type,cond_type));
	} break;
	case c_type_long_long_int: {
		long long int v_long_long_int;
		if(!str2longlong(value,v_long_long_int)){
			throw string(string("can't cast '")+value+"' to long long integer");
		}
		if(field_name_type==c_field_dynamic) rules.push_back(cmp_functor((long long int)v_long_long_int,field,cond_type));
		else throw string(string("not supported static field type: ")+get_cmp_type_name(field_type));
	} break;
	case c_type_double: {
		double v_double;
		if(0==sscanf(value.c_str(),"%lf",&v_double)){
			throw string(string("can't cast '")+value+"' to double");
		}
		if(field_name_type==c_field_dynamic) throw string(string("not supported dynamic field type: ")+get_cmp_type_name(field_type));
		else rules.push_back(cmp_functor(v_double,field_name_type,cond_type));
	} break;
	case c_type_string: {
		if(field_name_type==c_field_dynamic) rules.push_back(cmp_functor(value,field,cond_type));
		else throw string(string("not supported static field type: ")+get_cmp_type_name(field_type));
	} break;
	default:
		throw string(string("not supported field type: ")+get_cmp_type_name(field_type));
	}
}

void parse_fields(cmp_rules &rules, const AmArg &params, vector<string> &fields){
	int state = 0;

	for(unsigned int i = 0; i< params.size(); i++){
		if(!isArgCStr(params.get(i))){
			throw std::string("unexpected input");
		}
		string entry = params.get(i).asCStr();
		switch(state){
		case 0: //default state. output fields names
			if(entry=="WHERE"){
				if(i==0){
					throw std::string("found WHERE in wrong place");
				}
				state = 1;
			} else {
				DBG("parse entry: %s",entry.c_str());
				fields.push_back(entry);
			}
		break;
		case 1: {//state after WHERE keyword. rules
			int op_len;
			const char *s = entry.c_str();
			DBG("parse filter rule: %s",s);
			const char *op = get_operator_pos(s,entry.length(),op_len);
			if(!op)
				throw std::string(string("can't parse rule: ")+entry);
			insert_rule(rules,
						string(s,op-s),		//field
						string(op,op_len),	//operator
						string(op+op_len));	//value
		} break;
		}
	}

	if(state && rules.empty()){
		throw std::string("no rules defined after WHERE");
	}
}

int configure_filter(const SqlRouter *router){
	field_name2type.clear();
	//static fields
	for(unsigned int k = 0; k < static_call_fields_count; k++){
		const static_call_field &f = static_call_fields[k];
		try {
			field_name2type.insert(
						std::pair<string,cmp_type_t>(
							f.name,
							get_type_by_name(f.type)
						));
			field_name2field_type.insert(
						std::pair<string,cmp_field_t>(
							f.name,
							f.name_type
						));
		} catch(std::string &s){
			ERROR("can't process static field %s: %s",
				  f.name,s.c_str());
			return 1;
		}
	}

	//dynamic fields
	const DynFieldsT &df = router->getDynFields();
	for(DynFieldsT_const_iterator it = df.begin();
		it!=df.end(); ++it)
	{
		try {
			field_name2type.insert(
						std::pair<string,cmp_type_t>(
							it->name,
							get_type_by_name(it->type_name)
					));
		} catch(std::string &s){
			ERROR("can't process dynamic field %s: %s",
				  it->name.c_str(),s.c_str());
			return 1;
		}
	}

	/*for(map<string,cmp_type_t>::const_iterator i = field_name2type.begin();
		i!=field_name2type.end(); ++i){
		DBG("field_name2type[%s]: %d (%s)",
			i->first.c_str(),i->second,get_cmp_type_name(i->second));
	}*/

	//conditions
	for(int i = 0; i < c_cond_max;i++){
		cond_name2type.insert(
					std::pair<string,cmp_cond_t>(
						cmp_cond_names[i],
						(cmp_cond_t)i
					));
	}

	return 0;

}

