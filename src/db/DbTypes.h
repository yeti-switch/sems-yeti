#ifndef _DBTYPES_
#define _DBTYPES_

#include <log.h>
#include <AmArg.h>

#include <map>
#include <list>
#include <string>

#define GETPROFILE_STATIC_FIELDS_COUNT 21
#define WRITECDR_STATIC_FIELDS_COUNT 47

struct static_field {
    const char *name;
    const char *type;   //field SQL type
};

extern const static_field cdr_static_fields[];
extern const static_field profile_static_fields[];

using namespace std;

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
};

typedef list<DynField> DynFieldsT;
typedef DynFieldsT::iterator DynFieldsT_iterator;
typedef DynFieldsT::const_iterator DynFieldsT_const_iterator;
class dyn_name_is_eq
{
    string field_name;
  public:
    dyn_name_is_eq(string field_name): field_name(field_name) {}
    bool operator()(const DynField &f) { return f.name==field_name; }
};

#endif
