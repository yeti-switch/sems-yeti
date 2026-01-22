#pragma once

#include "CdrBase.h"
#include "ampi/PostgreSqlAPI.h"
#include "../UsedHeaderField.h"
#include "../Auth.h"

#include <vector>

extern const string              auth_log_statement_name;
extern std::vector<static_field> auth_log_static_fields;

class AuthCdr : public CdrBase
#ifdef OBJECTS_COUNTER
    ,
                ObjCounter(AuthCdr)
#endif
{
    timeval        request_time;
    int            transport_proto_id;
    string         remote_ip;
    unsigned short remote_port;
    string         local_ip;
    unsigned short local_port;
    string         method;
    string         r_uri;
    string         from_uri;
    string         to_uri;
    string         orig_call_id;

    bool               success;
    int                code;
    string             reason;
    string             internal_reason;
    int                auth_error_id;
    string             nonce;
    string             response;
    string             username;
    string             realm;
    Auth::auth_id_type auth_id;
    AmArg              aleg_headers_amarg;

  public:
    AuthCdr(const AmSipRequest &req, bool success, int code, const string &reason, const string &internal_reason,
            int _auth_error_id, Auth::auth_id_type auth_id);

    void apply_params(QueryInfo & query_info) const;
    void info(AmArg & s) override;

    const string &getOrigCallId() const
    {
        return orig_call_id;
    }
};
