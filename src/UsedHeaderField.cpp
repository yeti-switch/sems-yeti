#include "UsedHeaderField.h"

#include "AmUtils.h"
#include "db/DbHelpers.h"
#include "sip/parse_common.h"
#include "sip/parse_uri.h"
#include "sip/defs.h"
#include "jsonArg.h"

#include <botan/base64.h>

using std::string;

static bool getInternalHeader(const AmSipRequest &req,const string &name, string &hdr)
{
    switch(name[0]) {
    case 'F':
        if(name==SIP_HDR_FROM) hdr = req.from;
        break;
    case 'T':
        if(name==SIP_HDR_TO) hdr = req.to;
        break;
    case 'C':
        if(name==SIP_HDR_CONTACT) hdr = req.contact;
        break;
    default:
        return false;
    }
    return true;
}

void UsedHeaderField::applyFormat(const string &format)
{
    multiple_headers = false;

    if(format.empty()){
        type = Raw;
        return;
    }
    if(format.starts_with("uri_user")) {
        type = Uri;
        part = uri_user;
    } else if(format.starts_with("uri_json")) {
        type = Uri;
        part = uri_json;
    } else if(format.starts_with("uri_domain")) {
        type = Uri;
        part = uri_domain;
    } else if(format.starts_with("uri_port")) {
        type = Uri;
        part = uri_port;
    } else if(format.starts_with("uri_param")) {
        if(param.empty()) {
            WARN("empty mandatory param for fromat '%s' for header field '%s'. use Raw",
                 format.c_str(),name.c_str());
            type = Raw;
        } else {
            type = Uri;
            part = uri_param;
        }
    } else {
        WARN("unknown format '%s' for header field '%s'. use Raw",
            format.c_str(),name.c_str());
        type = Raw;
    }

    if(format.ends_with("_array"))
        multiple_headers = true;
}

bool UsedHeaderField::process_uri(const sip_uri &uri, string &ret) const
{
    if(!ret.empty()) ret += ',';

    switch(part) {
    case uri_user:
        ret += c2stlstr(uri.user);
        return true;
    case uri_domain:
        ret += c2stlstr(uri.host);
        return true;
    case uri_port:
        ret += int2str(uri.port);
        return true;
    case uri_param: {
        for(list<sip_avp*>::const_iterator i = uri.params.begin();
             i!=uri.params.end();++i)
        {
            const cstring &s = (*i)->name;
            if(param.length()==s.len &&
                strncmp(s.s,param.c_str(),s.len)==0)
            {
                ret += c2stlstr((*i)->value);
                return true;
            }
        }
        DBG("uri option '%s' not found in header '%s'",
            param.c_str(),name.c_str());
        return false;
    }
    default:
        ERROR("unknown part type for header '%s'",
              name.c_str());
        return false;
    } //switch(part)
}

void UsedHeaderField::serialize_nameaddr(const sip_nameaddr &na, AmArg &ret) const
{
    switch(na.uri.scheme) {
    case sip_uri::SIP:
    case sip_uri::SIPS:
        ret["s"] = na.uri.scheme == sip_uri::SIP ? "sip" : "sips";

        ret["n"] = na.name.len ? c2stlstr(na.name) : AmArg();

        ret["p"] = na.uri.port;
        ret["u"] = na.uri.user.len ? c2stlstr(na.uri.user) : AmArg();
        ret["h"] = na.uri.host.len ? c2stlstr(na.uri.host) : AmArg();
        break;
    case sip_uri::TEL:
        ret["s"] = "tel";
        ret["t"] = na.uri.user.len ? c2stlstr(na.uri.user) : AmArg();
        break;
    case sip_uri::UNKNOWN:
        ret["s"] = "unknown";
        return;
    }

    if(!na.uri.params.empty()) {
        AmArg &params = ret["up"];
        for(const auto &p: na.uri.params) {
            params[c2stlstr(p->name)] = p->value.len ? c2stlstr(p->value) : string();
        }
    }

    if(!na.uri.hdrs.empty()) {
        AmArg &params = ret["uh"];
        for(const auto &p: na.uri.hdrs) {
            params[c2stlstr(p->name)] = p->value.len ? c2stlstr(p->value) : string();
        }
    }

    if(!na.params.empty()) {
        AmArg &params = ret["np"];
        for(const auto &p: na.params) {
            params[c2stlstr(p->name)] = p->value.len ? c2stlstr(p->value) : string();
        }
    }
}

UsedHeaderField::UsedHeaderField(const string &hdr_name)
{
    name = hdr_name;
    type = Raw;
}

UsedHeaderField::UsedHeaderField(const AmArg &a)
{
    name = DbAmArg_hash_get_str(a,"varname");
    param = DbAmArg_hash_get_str(a,"varparam");
    sql_type_name = DbAmArg_hash_get_str(a,"vartype");
    applyFormat(DbAmArg_hash_get_str(a,"varformat"));
}

std::optional<AmArg> UsedHeaderField::getValue(const AmSipRequest &req) const
{
    string hdr;
    sip_nameaddr na;
    list<cstring> na_list;
    sip_uri uri;

    AmArg amarg_ret;
    string string_ret;

    if(!getInternalHeader(req,name,hdr))
        hdr = getHeader(req.hdrs,name);

    if(hdr.empty()) {
        DBG("no header '%s' in SipRequest",name.c_str());
        return std::nullopt;
    }

    switch(type) {
    case Raw:
        string_ret = hdr;
        break;
    case Uri:
        if(parse_nameaddr_list(na_list, hdr.c_str(),hdr.length()) < 0) {
            ERROR("wrong nameaddr list '%s' in header '%s'",
                  hdr.c_str(),name.c_str());
            return std::nullopt;
        }
        DBG("got %zd nameaddr entries. multiple_headers:%d",
            na_list.size(), multiple_headers);

        for(const auto &na_str : na_list) {
            const char *s = na_str.s;

            if(multiple_headers) {
                na.name.clear();
                na.params.clear();
                na.uri.host.clear();
                na.uri.port = 0;
                na.uri.params.clear();
                na.uri.uri_params.clear();
                na.uri.hdrs.clear();
            }

            if(parse_nameaddr_uri(&na, &s, na_str.len) < 0) {
                ERROR("invalid nameaddr '%.*s' in header '%s'. skip value",
                      na_str.len, na_str.s, name.c_str());

                if(multiple_headers) continue;
                return std::nullopt;
            }

            if(part == uri_json) {
                amarg_ret.push(AmArg());
                serialize_nameaddr(na, amarg_ret.back());
            } else {
                if(!process_uri(na.uri, string_ret)) {
                    if(multiple_headers) continue;
                    return std::nullopt;
                }
            }

            if(!multiple_headers) break;
        }
        break;
    default:
        ERROR("unknown value type for header '%s'",
              name.c_str());
        return std::nullopt;
    } //switch(type)

    if(!isArgUndef(amarg_ret)) {
        DBG("%s[%s:%s:%s] processed. got serialized value",
            name.c_str(), type2str(),part2str(), param.c_str());
        return amarg_ret;
    }

    if(string_ret.empty()) {
        DBG("%s[%s:%s:%s] processed. got empty value. return null",
            name.c_str(), type2str(),part2str(),param.c_str());
        return std::nullopt;
    }

    DBG("%s[%s:%s:%s] processed. got '%s'",
        name.c_str(), type2str(),part2str(),param.c_str(), string_ret.c_str());

    return string_ret;
}

void UsedHeaderField::getInfo(AmArg &arg) const
{
    arg["name"] = name;
    arg["type"] = type2str();
    if(type!=Raw) {
        arg["part"] = part2str();
        if(part==uri_param){
            arg["param"] = param;
        }
    }
    arg["multiple_headers"] = multiple_headers;
}

const char* UsedHeaderField::type2str() const
{
    switch(type){
    case Raw: return "Raw";
    case Uri: return "Uri";
    default: return "Unknown";
    }
}

const char* UsedHeaderField::part2str() const
{
    if(type==Raw)
        return "*";
    switch(part){
    case uri_user: return "uri_user";
    case uri_domain: return "uri_domain";
    case uri_port: return "uri_port";
    case uri_param: return "uri_param";
    case uri_json: return "uri_json";
    default: return "unknown";
    }
}

