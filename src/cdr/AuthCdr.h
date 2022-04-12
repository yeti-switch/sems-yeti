#pragma once

#include "CdrBase.h"
#include "../UsedHeaderField.h"
#include "../Auth.h"

#include <vector>

extern const string auth_sql_statement_name;
extern const std::vector<static_field> auth_log_static_fields;

class AuthCdr
  : public CdrBase
#ifdef OBJECTS_COUNTER
  , ObjCounter(AuthCdr)
#endif
{
    timeval request_time;
    int transport_proto_id;
    string remote_ip;
    unsigned short remote_port;
    string local_ip;
    unsigned short local_port;
    string method;
    string r_uri;
    string from_uri;
    string to_uri;
    string orig_call_id;

    bool success;
    int code;
    string reason;
    string internal_reason;
    string nonce;
    string response;
    string username;
    string realm;
    Auth::auth_id_type auth_id;

    vector<string> dynamic_fields;

  public:
    AuthCdr(const AmSipRequest& req,
            const vector<UsedHeaderField> &hdrs_to_parse,
            bool success,
            int code,
            const string &reason,
            const string &internal_reason,
            Auth::auth_id_type auth_id);

    pqxx::prepare::invocation get_invocation(cdr_transaction &tnx) override;
    void invoc(
        pqxx::prepare::invocation &i,
        const DynFieldsT &) override;
    void to_csv_stream(ofstream &s, const DynFieldsT &df) override;
    void info(AmArg &s) override;
};
