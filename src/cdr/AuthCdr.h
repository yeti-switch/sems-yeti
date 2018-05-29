#pragma once

#include "CdrBase.h"

class AuthCdr
  : public CdrBase
{
    AuthCdr()
      : CdrBase(CdrBase::Auth)
    {}

    pqxx::prepare::invocation get_invocation(cdr_transaction &tnx) override;
    void invoc(
        pqxx::prepare::invocation &invoc,
        AmArg &invocated_values,
        const DynFieldsT &df,
        bool serialize_dynamic_fields) override;
    void write_debug(AmArg &fields_values, const DynFieldsT &df) override;
    void to_csv_stream(ofstream &s, const DynFieldsT &df) override;
};
