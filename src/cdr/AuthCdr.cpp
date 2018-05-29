#include "AuthCdr.h"

static string auth_sql_statement_name("writeauth");

pqxx::prepare::invocation AuthCdr::get_invocation(cdr_transaction &tnx)
{
    return tnx.prepared(auth_sql_statement_name);
}

void AuthCdr::invoc(
    pqxx::prepare::invocation &invoc,
    AmArg &invocated_values,
    const DynFieldsT &df,
    bool serialize_dynamic_fields)
{ }

void AuthCdr::write_debug(AmArg &fields_values, const DynFieldsT &df)
{ }

void AuthCdr::to_csv_stream(ofstream &s, const DynFieldsT &df)
{ }
