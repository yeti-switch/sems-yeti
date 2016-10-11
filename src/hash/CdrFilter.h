#ifndef CDR_FILTER_H
#define CDR_FILTER_H

#include "../cdr/Cdr.h"
#include "../SqlRouter.h"

#include <list>
using std::list;

/* condition internal type. see  CdrFilter.cpp:get_type_by_name()*/
enum cmp_type_t {
	c_type_int = 0,
	c_type_long_long_int,
	c_type_string,
	c_type_timestamp,
	c_type_double,
	c_type_max,
};

/* types to make distinction between static fields */
enum cmp_field_t {
	c_field_unsupported = 0,
	c_field_dynamic,
	c_field_duration,
	c_field_connect_time,
	c_field_attempt_num,
	c_field_max
};

/* internal types for each comparsion operator */
enum cmp_cond_t {
	c_cond_eq = 0,
	c_cond_neq,
	c_cond_gt,
	c_cond_lt,
	c_cond_gte,
	c_cond_lte,
	c_cond_max
};

typedef struct {
	const char *name;		//human-readable name
	const char *type;		//SQL type
	cmp_field_t name_type;	//assigned internal type
} static_call_field;

extern const static_call_field static_call_fields[];
extern const unsigned int static_call_fields_count;


/* types definitions for static fields comparsion functions */

#define STATIC_CMP_FUNCTION_PTR(type) cmp_ ## type ## _function_ptr
#define DEF_STATIC_CMP_FUNCTION(type,value_type) \
typedef bool cmp_ ## type ## _function(const Cdr *cdr, value_type value);\
typedef cmp_ ## type ## _function *cmp_ ## type ## _function_ptr;

DEF_STATIC_CMP_FUNCTION(int,int)
DEF_STATIC_CMP_FUNCTION(double,double)
DEF_STATIC_CMP_FUNCTION(timestamp,const timeval &)

#define DYNAMIC_CMP_FUNCTION_PTR(type) cmp_dyn_ ## type ## _function_ptr
#define DEF_DYNAMIC_CMP_FUNCTION(type, val_type) \
typedef bool cmp_dyn_ ## type ## _function(const Cdr *cdr, const string& field_name, val_type value); \
typedef cmp_dyn_ ## type ## _function *cmp_dyn_ ## type ## _function_ptr;

DEF_DYNAMIC_CMP_FUNCTION(int,int)
DEF_DYNAMIC_CMP_FUNCTION(string,const string &)

typedef long long int long_long_int;
DEF_DYNAMIC_CMP_FUNCTION(long_long_int,long_long_int)

/* functor is used to memorize comparsion parameters for further use */
class cmp_functor {
	/* functor parameters */

	cmp_type_t cmp_type;
	cmp_field_t cmp_field;
	cmp_cond_t cmp_cond;

	string dyn_field_name;

	/* pointers to the appropriate comparsion function */

	STATIC_CMP_FUNCTION_PTR(int) fptr_int;
	STATIC_CMP_FUNCTION_PTR(double) fptr_double;
	STATIC_CMP_FUNCTION_PTR(timestamp) fptr_timestamp;

	DYNAMIC_CMP_FUNCTION_PTR(int) fptr_dyn_int;
	DYNAMIC_CMP_FUNCTION_PTR(long_long_int) fptr_dyn_long_long_int;
	DYNAMIC_CMP_FUNCTION_PTR(string) fptr_dyn_string;

	/* value holders */
	int v_int;
	long_long_int v_long_long_int;
	double v_double;
	timeval v_time;
	string v_string;

  public:
	/* constructors for static fields */
	cmp_functor(int value, cmp_field_t cmp_field, cmp_cond_t cmp_cond);
	cmp_functor(double value, cmp_field_t cmp_field, cmp_cond_t cmp_cond);
	cmp_functor(const timeval &value, cmp_field_t cmp_field, cmp_cond_t cmp_cond);

	/* constructor for dynamic fields */
	cmp_functor(int value,const string &field_name, cmp_cond_t cmp_cond);
	cmp_functor(long long int value,const string &field_name, cmp_cond_t cmp_cond);
	cmp_functor(const string &value,const string &field_name, cmp_cond_t cmp_cond);


	/* check for matching with given Cdr */
	bool operator()(const Cdr *cdr) const;

	/* short self-info */
	string info() const;
};

/* types definitions of functors list */
typedef list<cmp_functor> cmp_rules;
typedef cmp_rules::const_iterator cmp_rules_it;

/* walk over functors from list and run each of them for given Cdr
 * return true if all rules matched and false otherwise */
bool apply_filter_rules(const Cdr *cdr,const cmp_rules &rules);

/* parse one rule and append rules list with created functor */
void parse_fields(cmp_rules &rules, const AmArg &params, vector<string> &fields);

/* prepare structures for fast parsing */
int configure_filter(const SqlRouter *router);


#endif // CDR_FILTER_H
