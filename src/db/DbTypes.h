#ifndef _DBTYPES_
#define _DBTYPES_

#include <log.h>
#include <AmArg.h>

#include <map>
#include <list>
#include <string>

#include <pqxx/result>

#define GETPROFILE_STATIC_FIELDS_COUNT 21
#define WRITECDR_STATIC_FIELDS_COUNT 47

struct static_field {
    const char *name;
    const char *type;   //field SQL type
};

extern const static_field cdr_static_fields[];
extern const static_field profile_static_fields[];

using namespace std;

#define assign_str(field,sql_field)\
	field =  t[sql_field].c_str();

#define assign_str_safe(field,sql_field,failover_value)\
	try { assign_str(field,sql_field); }\
	catch(...) {\
		ERROR("field '%s' not exist in db response",sql_field);\
		field = failover_value;\
	}

#define assign_type(field,sql_field,default_value,type)\
	field = t[sql_field].as<type>(default_value);

#define assign_type_safe(field,sql_field,default_value,type,failover_value)\
	try { assign_type(field,sql_field,default_value,type);\
	} catch(...) {\
		ERROR("field '%s' not exist in db response",sql_field);\
		field = failover_value;\
	}

#define assign_type_safe_silent(field,sql_field,default_value,type,failover_value)\
	try { assign_type(field,sql_field,default_value,type);\
	} catch(...) {\
		field = failover_value;\
	}

#define assign_bool(field,sql_field,default_value)\
	assign_type(field,sql_field,default_value,bool);

#define assign_bool_safe(field,sql_field,default_value,failover_value)\
	assign_type_safe(field,sql_field,default_value,bool,failover_value);

#define assign_bool_str(field,sql_field,default_value)\
	do {\
		bool field_tmp_bool;\
		assign_bool(field_tmp_bool,sql_field,default_value);\
		field = field_tmp_bool ? "yes" : "no";\
	} while(0)

#define assign_bool_str_safe(field,sql_field,default_value,failover_value)\
	do {\
		bool field_tmp_bool;\
		assign_bool_safe(field_tmp_bool,sql_field,default_value,failover_value);\
		field = field_tmp_bool ? "yes" : "no";\
	} while(0)

#define assign_int(field,sql_field,default_value)\
	assign_type(field,sql_field,default_value,int);

#define assign_int_safe(field,sql_field,default_value,failover_value)\
	assign_type_safe(field,sql_field,default_value,int,failover_value);

#define assign_int_safe_silent(field,sql_field,default_value,failover_value)\
	assign_type_safe_silent(field,sql_field,default_value,int,failover_value);

#define assign_bool_safe_silent(field,sql_field,default_value,failover_value)\
	assign_type_safe_silent(field,sql_field,default_value,bool,failover_value);


#define conditional_assign(field,condition,else_val,op,sql_field,default_value,failover_value)\
	if(condition) {\
		op(field,sql_field,default_value,failover_value);\
	} else { \
		field = else_val;\
	}

#define conditional_assign_int_safe(field,condition,else_val,sql_field,default_value,failover_value)\
	conditional_assign(field,condition,else_val,assign_int_safe,sql_field,default_value,failover_value)

typedef vector<string> PreparedQueryArgs;
typedef PreparedQueryArgs::iterator PreparedQueryArgs_iterator;

typedef map<string, pair<string,PreparedQueryArgs> > PreparedQueriesT;
typedef PreparedQueriesT::iterator PreparedQueriesT_iterator;

struct DynField {
	string name;
	string type_name;
	enum type {
		VARCHAR,
		INTEGER,
		BIGINT,
		BOOL,
		INET,
	} type_id;
	DynField(string field_name, string field_type):
		name(field_name), type_name(field_type)
	{
		if(type_name=="varchar"){
			type_id = VARCHAR;
		} else if(type_name=="integer" || type_name=="smallint"){
			type_id = INTEGER;
		} else if(type_name=="bigint"){
			type_id = BIGINT;
		} else if(type_name=="boolean"){
			type_id = BOOL;
		} else if(type_name=="inet"){
			type_id = INET;
		} else {
			WARN("unhandled sql type '%s' for field '%s'. consider it as varchar",
				 type_name.c_str(),name.c_str());
			type_id = VARCHAR;
		}
	}

	void tuple2AmArg(const pqxx::row &t, AmArg &ret) const {
		if(t[name].is_null()){
			ret = AmArg();
			return;
		}
		switch(type_id){
			case VARCHAR: assign_str(ret,name); break;
			case INTEGER: assign_type(ret,name,,int); break;
			case BIGINT: assign_type(ret,name,,long long); break;
			case BOOL: assign_bool(ret,name,); break;
			case INET: assign_str(ret,name); break;
		}
	}
};
typedef list<DynField> DynFieldsT;
typedef DynFieldsT::iterator DynFieldsT_iterator;
typedef DynFieldsT::const_iterator DynFieldsT_const_iterator;
class dyn_name_is_eq {
	string field_name;
  public:
	dyn_name_is_eq(string field_name): field_name(field_name) {}
	bool operator()(const DynField &f) { return f.name==field_name; }
};

#endif
