#include "UsedHeaderField.h"

#include "AmUtils.h"
#include "sip/parse_common.h"
#include "sip/parse_nameaddr.h"
#include "sip/parse_uri.h"
#include "sip/defs.h"

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

UsedHeaderField::UsedHeaderField(const string &hdr_name)
{
    name = hdr_name;
    type = Raw;
}

UsedHeaderField::UsedHeaderField(const pqxx::row &t)
{
    readFromTuple(t);
}

void UsedHeaderField::readFromTuple(const pqxx::row &t)
{
    string format;

    name = t["varname"].c_str();
    param = t["varparam"].c_str();
    hashkey = t["varhashkey"].as<bool>(false);
    format = t["varformat"].c_str();

    multiple_headers = false;

    if(format.empty()){
        type = Raw;
        return;
    }
    if(format.starts_with("uri_user")) {
        type = Uri;
        part = uri_user;
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

bool UsedHeaderField::getValue(const AmSipRequest &req,string &val) const
{
    string hdr;
    sip_nameaddr na;
    list<cstring> na_list;

    if(!getInternalHeader(req,name,hdr))
        hdr = getHeader(req.hdrs,name);

    if(hdr.empty()) {
        DBG("no header '%s' in SipRequest",name.c_str());
        return false;
    }

    switch(type) {
    case Raw:
        val = hdr;
        goto succ;
    case Uri:
        if(parse_nameaddr_list(na_list, hdr.c_str(),hdr.length()) < 0) {
            ERROR("wrong nameaddr list '%s' in header '%s'",
                  hdr.c_str(),name.c_str());
            return false;
        }
        DBG("got %zd nameaddr entries. multiple_headers:%d",
            na_list.size(), multiple_headers);

        for(const auto &na_str : na_list) {
            const char *s = na_str.s;

            if(multiple_headers) {
                na.params.clear();
                na.uri.params.clear();
                na.uri.uri_params.clear();
                na.uri.hdrs.clear();
            }

            if(parse_nameaddr_uri(&na, &s, na_str.len) < 0) {
                ERROR("invalid nameaddr '%.*s' in header '%s'. skip value",
                      na_str.len, na_str.s, name.c_str());

                if(multiple_headers) continue;
                return false;
            }

            if(!process_uri(na.uri, val)) {
                if(multiple_headers) continue;
                return false;
            }

            if(!multiple_headers) break;
        }
        break;
    default:
        ERROR("unknown value type for header '%s'",
              name.c_str());
        return false;
    } //switch(type)

succ:
    if(val.empty()) {
        DBG("%s[%s:%s:%s] processed. got empty value. return null",
            name.c_str(), type2str(),part2str(),param.c_str());
        return false;
    }
    if(fixup_utf8_inplace(val)) {
        WARN("value for %s[%s:%s:%s]"
             "contained at least one invalid utf8 sequence. wrong bytes erased",
             name.c_str(), type2str(),part2str(),param.c_str());
    }
    DBG("%s[%s:%s:%s] processed. got '%s'",
        name.c_str(), type2str(),part2str(),param.c_str(), val.c_str());
    return true;
}

void UsedHeaderField::getInfo(AmArg &arg) const
{
    string s;
    arg["name"] = name;
    arg["hashkey"] = hashkey;
    arg["type"] = type2str();
    if(type!=Raw) {
        arg["part"] = part2str();
        if(part==uri_param){
            arg["param"] = param;
        }
    }
    arg["multiple_headers"] = true;
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
    default: return "unknown";
    }
}

