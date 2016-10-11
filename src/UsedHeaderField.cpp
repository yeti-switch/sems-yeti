#include "UsedHeaderField.h"

#include "AmUtils.h"
#include "sip/parse_common.h"
#include "sip/parse_nameaddr.h"
#include "sip/parse_uri.h"
#include "sip/defs.h"

using std::string;

static bool getInternalHeader(const AmSipRequest &req,const string &name, string &hdr){
	switch(name[0]){
	case 'F':
		if(name==SIP_HDR_FROM) hdr = req.from;
		break;
	case 'T':
		if(name==SIP_HDR_TO) hdr = req.to;
		break;
	case 'C':
		if(name==SIP_HDR_CONTACT) hdr = req.contact;
	default:
		return false;
	}
	return true;
}

UsedHeaderField::UsedHeaderField(const string &hdr_name){
    name = hdr_name;
    type = Raw;
}

UsedHeaderField::UsedHeaderField(const pqxx::result::tuple &t){
    readFromTuple(t);
}

void UsedHeaderField::readFromTuple(const pqxx::result::tuple &t){
    string format;

    name = t["varname"].c_str();
	param = t["varparam"].c_str();
    hashkey = t["varhashkey"].as<bool>(false);
    format = t["varformat"].c_str();

    if(format.empty()){
        type = Raw;
        return;
    }

    if(format=="uri_user"){
        type = Uri;
        part = uri_user;
    } else if(format=="uri_domain"){
        type = Uri;
        part = uri_domain;
    } else if(format=="uri_port"){
        type = Uri;
        part = uri_port;
	} else if(format=="uri_param"){
		if(param.empty()){
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
}

bool UsedHeaderField::getValue(const AmSipRequest &req,string &val) const {
    string hdr;
    const char *sptr;
    sip_nameaddr na;
    sip_uri uri;

	if(!getInternalHeader(req,name,hdr)){
		hdr = getHeader(req.hdrs,name);
	}

    if(hdr.empty()){
		DBG("no header '%s' in SipRequest",name.c_str());
        return false;
    }
    switch(type){

        case Raw:
            val = hdr;
            goto succ;
        break;

        case Uri:
            sptr = hdr.c_str();
            if(parse_nameaddr(&na,&sptr,hdr.length()) < 0 ||
               parse_uri(&uri,na.addr.s,na.addr.len) < 0)
            {
				ERROR("invalid uri '%s' in header '%s'",
					hdr.c_str(),name.c_str());
                return false;
            }
			/*DBG("uri.params = %li",uri.params.size());
			for(list<sip_avp*>::const_iterator i = uri.params.begin();
					i!=uri.params.end();++i){
				const sip_avp &a = **i;
				DBG("uri_param: %.*s = %.*s",
					a.name.len,a.name.s,
					a.value.len,a.value.s);
			}
			DBG("uri.hdrs = %li",uri.hdrs.size());
			for(list<sip_avp*>::const_iterator i = uri.hdrs.begin();
					i!=uri.hdrs.end();++i){
				const sip_avp &a = **i;
				DBG("uri_hdr: %.*s = %.*s",
					a.name.len,a.name.s,
					a.value.len,a.value.s);
			}*/
            switch(part){
                case uri_user:
                    val = c2stlstr(uri.user);
                    goto succ;
                case uri_domain:
                    val = c2stlstr(uri.host);
                    goto succ;
                case uri_port:
                    val = int2str(uri.port);
                    goto succ;
				case uri_param: {
					for(list<sip_avp*>::const_iterator i = uri.params.begin();
							i!=uri.params.end();++i){
						const cstring &s = (*i)->name;
						if(param.length()==s.len &&
								strncmp(s.s,param.c_str(),s.len)==0){
							val = c2stlstr((*i)->value);
							goto succ;
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
            }
        break;

        default:
		ERROR("unknown value type for header '%s'",
                  name.c_str());
            return false;
    }
    return false;
succ:
	if(val.empty()){
		DBG("'%s':%s:%s:'%s' processed. got empty value. return null",
			name.c_str(),
			type2str(),part2str(),param.c_str());
		return false;
	}
	DBG("'%s':%s:%s:'%s' processed. got '%s'",
		name.c_str(),
		type2str(),part2str(),param.c_str(),
		val.c_str());
    return true;
}

void UsedHeaderField::getInfo(AmArg &arg) const{
    string s;
    arg["name"] = name;
    arg["hashkey"] = hashkey;
    arg["type"] = type2str();
	if(type!=Raw){
        arg["part"] = part2str();
		if(part==uri_param){
			arg["param"] = param;
		}
	}
}

const char* UsedHeaderField::type2str() const {
    switch(type){
        case Raw: return "Raw";
        case Uri: return "Uri";
        default: return "Unknown";
    }
}

const char* UsedHeaderField::part2str() const {
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

