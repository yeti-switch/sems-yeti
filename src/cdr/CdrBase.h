#pragma once

#include <pqxx/pqxx>

#include "../SqlCallProfile.h"
#include "AmThread.h"

using cdr_transaction = pqxx::work;

class CdrBase
{
  public:
    enum cdr_type {
        Call = 0,
        Auth
    };

  private:
    cdr_type type;

  public:
    bool suppress;
    struct timeval cdr_born_time;

    CdrBase() = delete;
    CdrBase(cdr_type type);

    cdr_type getType() { return type; }

    virtual pqxx::prepare::invocation get_invocation(cdr_transaction &tnx) = 0;

    virtual void invoc(
        pqxx::prepare::invocation &invoc,
        const DynFieldsT &df,
        bool serialize_dynamic_fields) = 0;
    virtual void to_csv_stream(ofstream &s, const DynFieldsT &df) = 0;
    virtual void info(AmArg &s) = 0;

    virtual ~CdrBase() { }
};
