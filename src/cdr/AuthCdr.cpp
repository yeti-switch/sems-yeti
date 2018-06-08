#include "AuthCdr.h"
#include "sip/defs.h"
#include "AmUtils.h"
#include "AmSipMsg.h"

#include <vector>

string const auth_sql_statement_name("writeauth");

const std::vector<static_field> auth_log_static_fields = {
    { "is_master", "boolean" },
    { "node_id", "integer" },
    { "pop_id", "integer" },
    { "transport_proto_id", "integer" },
    { "remote_ip", "varchar" },
    { "remote_ip", "varchar" },
    { "remote_port", "integer" },
    { "local_ip", "varchar" },
    { "local_port", "integer" },
    { "method", "varchar" },
    { "ruri", "varchar" },
    { "from_uri", "varchar" },
    { "to_uri", "varchar" },
    { "orig_call_id", "varchar" },
    { "success" ,"boolean" },
    { "code", "smallint" },
    { "reason", "varchar" },
    { "internal_reason", "varchar" },
    { "nonce", "varchar" },
    { "response", "varchar" },
    { "auth_id" ,"integer" }
};

inline string find_attribute(const string& name, const string& header) {
    size_t pos1 = header.find(name);

    while (true) {
        if (pos1 == string::npos)
            return "";

        if (!pos1 || header[pos1-1] == ',' || header[pos1-1] == ' ')
            break;

        pos1 = header.find(name, pos1+1);
    }

    pos1+=name.length();
    pos1 = header.find_first_not_of(" =\"", pos1);
    if (pos1 != string::npos) {
        size_t pos2 = header.find_first_of(",\"", pos1);
        if (pos2 != string::npos) {
            return header.substr(pos1, pos2-pos1);
        } else {
            return header.substr(pos1); // end of hdr
        }
    }

    return "";
}

AuthCdr::AuthCdr(
    const AmSipRequest& req,
    const vector<UsedHeaderField> &hdrs_to_parse,
    bool success,
    int code,
    const string &reason,
    const string &internal_reason,
    Auth::auth_id_type auth_id)
  : CdrBase(CdrBase::Auth),
    //fields from SIP request
    request_time(req.recv_timestamp),
    transport_proto_id(req.transport_id),
    remote_ip(req.remote_ip),
    remote_port(req.remote_port),
    local_ip(req.local_ip),
    local_port(req.local_port),
    method(req.method),
    r_uri(req.r_uri),
    from_uri(req.from),
    to_uri(req.to),
    orig_call_id(req.callid),
    //auth-related fields
    success(success),
    code(code),
    reason(reason),
    internal_reason(internal_reason),
    auth_id(auth_id)
{
    for(const auto &h: hdrs_to_parse) {
        dynamic_fields.emplace_back();
        h.getValue(req,dynamic_fields.back());
    }

    string auth_hdr =  getHeader(req.hdrs, SIP_HDR_AUTHORIZATION);
    if(auth_hdr.empty())
        return;
    nonce =  find_attribute("nonce", auth_hdr);
    response =  find_attribute("response", auth_hdr);
    username = find_attribute("username", auth_hdr);
}

pqxx::prepare::invocation AuthCdr::get_invocation(cdr_transaction &tnx)
{
    return tnx.prepared(auth_sql_statement_name);
}

void AuthCdr::invoc(
    pqxx::prepare::invocation &i,
    const DynFieldsT &,
    bool)
{
    i(timeval2double(request_time));
    i(transport_proto_id);
    i(remote_ip)(remote_port);
    i(local_ip)(local_port);
    i(method);
    i(r_uri)(from_uri)(to_uri);
    i(orig_call_id);

    i(success);
    i(code)(reason);
    i(internal_reason);
    if(nonce.empty()) i(); else i(nonce);
    if(response.empty()) i(); else i(response);
    //if(username.empty()) i(); else i(username);
    if(auth_id <= 0) i(); else i(auth_id);

    for(const auto &f : dynamic_fields)
        if(f.empty()) i(); else i(f);
}

void AuthCdr::to_csv_stream(ofstream &s, const DynFieldsT &df)
{ }
