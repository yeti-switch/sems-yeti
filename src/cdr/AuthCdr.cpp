#include "AuthCdr.h"
#include "sip/defs.h"
#include "AmUtils.h"
#include "AmSipMsg.h"

#include <vector>
#include "../yeti.h"
#include "jsonArg.h"

const string auth_log_statement_name("writeauth");

const std::vector<static_field> auth_log_static_fields = {
    {          "is_master",  "boolean" },
    {            "node_id",  "integer" },
    {             "pop_id",  "integer" },
    {       "request_time",   "double" },
    { "transport_proto_id", "smallint" },
    {          "remote_ip",     "inet" },
    {        "remote_port",  "integer" },
    {           "local_ip",     "inet" },
    {         "local_port",  "integer" },
    {           "username",  "varchar" },
    {              "realm",  "varchar" },
    {             "method",  "varchar" },
    {               "ruri",  "varchar" },
    {           "from_uri",  "varchar" },
    {             "to_uri",  "varchar" },
    {       "orig_call_id",  "varchar" },
    {            "success",  "boolean" },
    {               "code", "smallint" },
    {             "reason",  "varchar" },
    {    "internal_reason",  "varchar" },
    {              "nonce",  "varchar" },
    {           "response",  "varchar" },
    {            "auth_id",  "integer" },
    { "i_aleg_cdr_headers",     "json" }
};

inline string find_attribute(const string &name, const string &header)
{
    size_t pos1 = header.find(name);

    while (true) {
        if (pos1 == string::npos)
            return "";

        if (!pos1 || header[pos1 - 1] == ',' || header[pos1 - 1] == ' ')
            break;

        pos1 = header.find(name, pos1 + 1);
    }

    pos1 += name.length();
    pos1 = header.find_first_not_of(" =\"", pos1);
    if (pos1 != string::npos) {
        size_t pos2 = header.find_first_of(",\"", pos1);
        if (pos2 != string::npos) {
            return header.substr(pos1, pos2 - pos1);
        } else {
            return header.substr(pos1); // end of hdr
        }
    }

    return "";
}

AuthCdr::AuthCdr(const AmSipRequest &req, bool _success, int _code, const string &_reason,
                 const string &_internal_reason, Auth::auth_id_type _auth_id)
    : CdrBase(CdrBase::Auth)
    ,
    // fields from SIP request
    request_time(req.recv_timestamp)
    , transport_proto_id(req.transport_id)
    , remote_ip(req.remote_ip)
    , remote_port(req.remote_port)
    , local_ip(req.local_ip)
    , local_port(req.local_port)
    , method(req.method)
    , r_uri(req.r_uri)
    , from_uri(req.from)
    , to_uri(req.to)
    , orig_call_id(req.callid)
    ,
    // auth-related fields
    success(_success)
    , code(_code)
    , reason(_reason)
    , internal_reason(_internal_reason)
    , auth_id(_auth_id)
    , aleg_headers_amarg(Yeti::instance().config.aleg_cdr_headers.serialize_headers(req.hdrs))
{
    string auth_hdr = getHeader(req.hdrs, SIP_HDR_AUTHORIZATION);
    if (auth_hdr.empty())
        return;
    nonce    = find_attribute("nonce", auth_hdr);
    response = find_attribute("response", auth_hdr);

    username = find_attribute("username", auth_hdr);

    realm = find_attribute("realm", auth_hdr);
}

void AuthCdr::apply_params(QueryInfo &query_info) const
{
#define invoc(field_value) query_info.addParam(field_value);

#define invoc_typed(type, field_value) query_info.addTypedParam(type, field_value);

#define invoc_null() query_info.addParam(AmArg());

#define invoc_cond(field_value, condition)                                                                             \
    if (condition) {                                                                                                   \
        invoc(field_value);                                                                                            \
    } else {                                                                                                           \
        invoc_null();                                                                                                  \
    }

#define invoc_str_no_empty(field_value)                                                                                \
    if (!field_value.empty()) {                                                                                        \
        invoc(field_value);                                                                                            \
    } else {                                                                                                           \
        invoc_null();                                                                                                  \
    }

#define invoc_cond_typed(type, field_value, condition)                                                                 \
    if (condition) {                                                                                                   \
        invoc_typed(type, field_value);                                                                                \
    } else {                                                                                                           \
        invoc_null();                                                                                                  \
    }

    invoc(true); // is_master
    invoc(AmConfig.node_id);
    invoc(Yeti::instance().config.pop_id);

    invoc(timeval2double(request_time));
    invoc_typed("smallint", transport_proto_id);
    invoc_str_no_empty(remote_ip);
    invoc(remote_port);
    invoc_str_no_empty(local_ip) invoc(local_port);
    invoc_cond(username, !username.empty());
    invoc_cond(realm, !realm.empty());
    invoc(method);
    invoc(r_uri);
    invoc(from_uri);
    invoc(to_uri);
    invoc(orig_call_id);

    invoc(success);
    invoc_typed("smallint", code);
    invoc(reason);
    invoc(internal_reason);
    invoc_cond(nonce, !nonce.empty());
    invoc_cond(response, !response.empty());
    invoc_cond(auth_id, auth_id > 0);

    invoc_cond(arg2json(aleg_headers_amarg), isArgStruct(aleg_headers_amarg) && aleg_headers_amarg.size());

#undef invoc_cond_typed
#undef invoc_cond
#undef invoc_null
#undef invoc_typed
#undef invoc
}

void AuthCdr::info(AmArg &s)
{
    s["request_time"] = timeval2str(request_time);
    s["remote_ip"]    = remote_ip;
    s["remote_port"]  = remote_port;
    s["r_uri"]        = r_uri;
    s["method"]       = method;
}
