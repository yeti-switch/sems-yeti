/*
 * Copyright (C) 2010 Stefan Sayer
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * For a license to use the SEMS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * SEMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ParamReplacer.h"
#include "sip/parse_next_hop.h"
#include "sip/parse_common.h"

#include "log.h"
#include "AmSipHeaders.h"
#include "AmUtils.h"
#include "sip/parse_uri.h"
#include "sip/parse_header.h"
#include "sip/parse_route.h"
#include "SBC.h" // for RegexMapper SBCFactory::regex_mappings
#include <algorithm>
#include <stdlib.h>

/*
 * reimplements AmBasicSipDialog::getOutboundIf() to provide
 * ability for replaces related to outbound interface
 */
int getOutboundInterface(const string &next_hop,
                         const string &outbound_proxy,bool force_outbound_proxy,
                         const string &route,
                         const string &ruri)
{

    if(AmConfig.sip_ifs.size() == 1) {
        return 0;
    }

    // Destination priority:
    // 1. next_hop
    // 2. outbound_proxy (if 1st req or force_outbound_proxy)
    // 3. first route
    // 4. remote URI

    string dest_uri;
    string dest_ip;
    string local_ip;
    multimap<string,unsigned short>::iterator if_it;

    list<sip_destination> ip_list;
    if(!next_hop.empty() &&
       !parse_next_hop(stl2cstr(next_hop),ip_list) &&
       !ip_list.empty())
    {
        dest_ip = c2stlstr(ip_list.front().host);
    } else if(!outbound_proxy.empty() && force_outbound_proxy) {
      dest_uri = outbound_proxy;
    } else if(!route.empty()) {
        // parse first route
        sip_header fr;
        fr.value = stl2cstr(route);
        sip_uri* route_uri = get_first_route_uri(&fr);
        if(!route_uri){
            ERROR("Could not parse route route='%s'",route.c_str());
            goto error;
        }

        dest_ip = c2stlstr(route_uri->host);
    } else {
        dest_uri = ruri;
    }

    if(dest_uri.empty() && dest_ip.empty()) {
        ERROR("No destination found");
        goto error;
    }

    if(!dest_uri.empty()) {
        sip_uri d_uri;
        if(parse_uri(&d_uri,dest_uri.c_str(),dest_uri.length()) < 0) {
            ERROR("Could not parse destination URI dest_uri='%s'",dest_uri.c_str());
            goto error;
        }
        dest_ip = c2stlstr(d_uri.host);
    }

    if(get_local_addr_for_dest(dest_ip,local_ip,IPv4_only) < 0) {
        ERROR("No local address for dest '%s'",dest_ip.c_str());
        goto error;
    }

    if_it = AmConfig.local_sip_ip2if.find(local_ip);
    if(if_it == AmConfig.local_sip_ip2if.end()) {
        ERROR("Could not find a local interface for resolved local IP local_ip='%s'",
              local_ip.c_str());
        goto error;
    }

    return if_it->second;

   error:
    WARN("Error while computing outbound interface: default interface will be used instead.");
    return 0;
}

int replaceParsedParam(const string& s, size_t p,
			const AmUriParser& parsed, string& res) {
  int skip_chars=1;
  switch (s[p+1]) {
  case 'u': { // URI
    res+=parsed.uri_user+"@"+parsed.uri_host;
    if (!parsed.uri_port.empty())
      res+=":"+parsed.uri_port;
  } break;
  case 'U': res+=parsed.uri_user; break; // User
  case 'd': { // domain
    res+=parsed.uri_host;
    if (!parsed.uri_port.empty())
      res+=":"+parsed.uri_port;
  } break;
  case 'h': res+=parsed.uri_host; break; // host
  case 'p': res+=parsed.uri_port; break; // port
  case 'H': res+=parsed.uri_headers; break; // Headers
  case 'P': { // Params
    if((s.length() > p+3) && (s[p+2] == '(')) {
      size_t skip_p = p+3;
      for (;skip_p<s.length() && s[skip_p] != ')';skip_p++) { }
      if (skip_p==s.length()) {
	WARN("Error parsing $%cP() param replacement (unclosed brackets)\n",s[p]);
	break;
      }
      string param_name = s.substr(p+3,skip_p-p-3);
      if(param_name.empty()) {
	res+=parsed.uri_param;
	skip_chars = skip_p-p;
	break;
      }
      
      const string& uri_params = parsed.uri_param;
      const char* c = uri_params.c_str();
      list<sip_avp*> params;
      if(parse_gen_params(&params,&c,uri_params.length(),0) < 0) {
	DBG("could not parse URI parameters");
	free_gen_params(&params);
	break;
      }

      string param;
      for(list<sip_avp*>::iterator it = params.begin(); 
	  it != params.end(); it++) {

	if(lower_cmp_n((*it)->name.s,(*it)->name.len,
		       param_name.c_str(),param_name.length()))
	  continue;

	param = c2stlstr((*it)->value);
      }
      free_gen_params(&params);
      res+=param;
      skip_chars = skip_p-p;
    }
    else {
      res+=parsed.uri_param; 
    }
  } break;
  case 'n': res+=parsed.display_name; break; // Params

  // case 't': { // tag
  //   map<string, string>::const_iterator it = parsed.params.find("tag");
  //   if (it != parsed.params.end())
  //     res+=it->second;
  // } break;
  default: WARN("unknown replace pattern $%c%c\n",
		s[p], s[p+1]); break;
  };

  return skip_chars;
}

/* Returns a url-decoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(const char *str);

string replaceParameters(const string& s,
			 const char* r_type,
			 const AmSipRequest& req,
			 const SBCCallProfile* call_profile,
			 const string& app_param,
			 AmUriParser& ruri_parser, 
			 AmUriParser& from_parser,
			 AmUriParser& to_parser,
			 bool rebuild_ruri,
			 bool rebuild_from,
			 bool rebuild_to) {
  string res;
  bool is_replaced = false;
  size_t p = 0;
  bool is_escaped = false;
  const string& used_hdrs = req.hdrs; //(hdrs == NULL) ? req.hdrs : *hdrs;
  int outbound_interface = call_profile->outbound_interface.empty() ?
              -1 : call_profile->outbound_interface_value;

  while (p<s.length()) {
    size_t skip_chars = 1;

    if (is_escaped) {
      switch (s[p]) {
      case 'r': res += '\r'; break;
      case 'n': res += '\n'; break;
      case 't': res += '\t'; break;
      default: res += s[p]; break;
      }
      is_escaped = false;
    } else { // not escaped
      if (s[p]=='\\') {
	if (p==s.length()-1) {
	  res += '\\'; // add single \ at the end
	} else {
	  is_escaped = true;
	  is_replaced = true;
	}
      } else if ((s[p]=='$') && (s.length() >= p+1)) {
	is_replaced = true;
	p++;
	switch (s[p]) {
	case 'f': { // from
	  if ((s.length() == p+1) || (s[p+1] == '.')) {
	    if (rebuild_from) {
	      res += from_parser.nameaddr_str();
	    } else {
	      res += req.from;
	    }

	    break;
	  }

	  if (s[p+1]=='t') { // $ft - from tag
	    res += req.from_tag;
	    break;
	  }

	  if (from_parser.uri.empty()) {
	    from_parser.uri = req.from;
	    if (!from_parser.parse_uri()) {
	      WARN("Error parsing From URI '%s'\n", req.from.c_str());
	      break;
	    }
	  }

	  skip_chars=replaceParsedParam(s, p, from_parser, res);

	}; break;

	case 't': { // to
	  if ((s.length() == p+1) || (s[p+1] == '.')) {
	    if (rebuild_to) {
	      res += to_parser.nameaddr_str();
	    } else {
	      res += req.to;
	    }
	    break;
	  }

	  if (s[p+1]=='t') { // $tt - to tag
	    res += req.to_tag;
	    break;
	  }

	  if (to_parser.uri.empty()) {
	    to_parser.uri = req.to;
	    if (!to_parser.parse_uri()) {
	      WARN("Error parsing To URI '%s'\n", req.to.c_str());
	      break;
	    }
	  }

	  skip_chars=replaceParsedParam(s, p, to_parser, res);

	}; break;

	case 'r': { // r-uri
	  if ((s.length() == p+1) || (s[p+1] == '.')) {
	    if (rebuild_ruri) {
	      res += ruri_parser.uri_str();
	    } else {
	      res += req.r_uri;
	    }
	    break;
	  }

	  if (ruri_parser.uri.empty()) {
	    ruri_parser.uri = req.r_uri;
	    if (!ruri_parser.parse_uri()) {
	      WARN("Error parsing R-URI '%s'\n", req.r_uri.c_str());
	      break;
	    }
	  }
	  skip_chars=replaceParsedParam(s, p, ruri_parser, res);
	}; break;

	case 'c': { // call-id
	  if ((s.length() == p+1) || (s[p+1] == 'i')) {
	    res += req.callid;
	    break;
	  }
	  WARN("unknown replacement $c%c\n", s[p+1]);
	}; break;

	case 's': { // source (remote)
	  if (s.length() < p+1) {
	    WARN("unknown replacement $s\n");
	    break;
	  }

	  if (s[p+1] == 'i') { // $si source IP address
	    res += req.remote_ip;
	    break;
	  } else if (s[p+1] == 'p') { // $sp source port
	    res += int2str(req.remote_port);
	    break;
	  }

	  WARN("unknown replacement $s%c\n", s[p+1]);
	}; break;

	case 'd': { // destination (remote UAS)
	  if (s.length() < p+1) {
	    WARN("unknown replacement $s\n");
	    break;
	  }

	  if(!call_profile->next_hop.empty()) {
	    cstring _next_hop = stl2cstr(call_profile->next_hop);
	    list<sip_destination> dest_list;
	    if(parse_next_hop(_next_hop,dest_list)) {
	      WARN("parse_next_hop %.*s failed\n",
		   _next_hop.len, _next_hop.s);
	      break;
	    }

	    if(dest_list.size() == 0) {
	      WARN("next-hop is not empty, but the resulting destination list is\n");
	      break;
	    }

	    const sip_destination& dest = dest_list.front();
	    if (s[p+1] == 'i') { // $di remote UAS IP address
	      res += c2stlstr(dest.host);
	      break;
	    } else if (s[p+1] == 'p') { // $dp remote UAS port
	      res += int2str(dest.port);
	      break;
	    }
	    WARN("unknown replacement $d%c\n", s[p+1]);
	    break;
	  }

	  if (ruri_parser.uri.empty()) {
	    ruri_parser.uri = req.r_uri;
	    if (!ruri_parser.parse_uri()) {
	      WARN("Error parsing R-URI '%s'\n", req.r_uri.c_str());
	      break;
	    }
	  }

	  if (s[p+1] == 'i') { // $di remote UAS IP address
	    res += ruri_parser.uri_host;
	    break;
	  } else if (s[p+1] == 'p') { // $dp remote UAS port
	    res += ruri_parser.uri_port;
	    break;
	  }

	  WARN("unknown replacement $d%c\n", s[p+1]);
	}; break;

	case 'R': { // received (local)
	  if (s.length() < p+1) {
	    WARN("unknown replacement $R\n");
	    break;
	  }

	  if (s[p+1] == 'i') { // $Ri received IP address
	    res += req.local_ip.c_str();
	    break;
	  } else if (s[p+1] == 'p') { // $Rp received port
	    res += int2str(req.local_port);
	    break;
	  } else if (s[p+1] == 'f') { // $Rf received interface id
	    res += int2str(req.local_if);
	    break;
	  } else if (s[p+1] == 'n') { // $Rn received interface name
        if (req.local_if < AmConfig.sip_ifs.size()) {
          res += AmConfig.sip_ifs[req.local_if].name;
	    }
	    break;
	  } else if (s[p+1] == 'I') { // $RI received interface public IP
        if (req.local_if < AmConfig.sip_ifs.size()) {
          //TODO: use smth like req.local_proto to get correct public_ip
          res += AmConfig.sip_ifs[req.local_if].proto_info[0]->public_ip;
        }
	    break;
	  }
	  WARN("unknown replacement $R%c\n", s[p+1]);
	}; break;

	case 'O': { // outbound (after route)
		if (s.length() < p+1) {
			WARN("unknown replacement $O\n");
			break;
		}
		if (s[p+1] == 'i') { // $Oi outbound IP address
			if(outbound_interface == -1)
				outbound_interface = getOutboundInterface(call_profile->next_hop,
														  call_profile->outbound_proxy,
														  call_profile->force_outbound_proxy,
														  req.route,
														  call_profile->ruri);
            //TODO: use smth like req.local_proto to get correct public_ip
            res += AmConfig.sip_ifs[outbound_interface].proto_info[0]->getHost();
			break;
		}
		WARN("unknown replacement $O%c\n", s[p+1]);
	}; break;

#define case_HDR(pv_char, pv_name, hdr_name)				\
	  case pv_char: {						\
	    AmUriParser uri_parser;					\
	    uri_parser.uri = getHeader(used_hdrs, hdr_name);		\
	    if ((s.length() == p+1) || (s[p+1] == '.')) {		\
	      res += uri_parser.uri;					\
	      break;							\
	    }								\
									\
	    if (!uri_parser.parse_uri()) {				\
	      WARN("Error parsing " pv_name " URI '%s'\n", uri_parser.uri.c_str()); \
	      break;							\
	    }								\
	    if (s[p+1] == 'i') {					\
	      res+=uri_parser.uri_user+"@"+uri_parser.uri_host;		\
	      if (!uri_parser.uri_port.empty())				\
		res+=":"+uri_parser.uri_port;				\
	    } else {							\
	      skip_chars=replaceParsedParam(s, p, uri_parser, res);	\
	    }								\
	  }; break;

	  case_HDR('a', "PAI", SIP_HDR_P_ASSERTED_IDENTITY);  // P-Asserted-Identity
	  case_HDR('p', "PPI", SIP_HDR_P_PREFERRED_IDENTITY); // P-Preferred-Identity

	case 'P': { // app-params
	  if (s[p+1] != '(') {
	    WARN("Error parsing P param replacement (missing '(')\n");
	    break;
	  }
	  if (s.length()<p+3) {
	    WARN("Error parsing P param replacement (short string)\n");
	    break;
	  }

	  size_t skip_p = p+2;
	  for (;skip_p<s.length() && s[skip_p] != ')';skip_p++) { }
	  if (skip_p==s.length()) {
	    WARN("Error parsing P param replacement (unclosed brackets)\n");
	    break;
	  }
	  string param_name = s.substr(p+2, skip_p-p-2);
	  // DBG("param_name = '%s' (skip-p - p = %d)\n", param_name.c_str(), skip_p-p);
	  res += get_header_keyvalue(app_param, param_name);
	  skip_chars = skip_p-p;
	} break;

	case 'H': { // header
	  size_t name_offset = 2;
	  if (s[p+1] != '(') {
	    if (s[p+2] != '(') {
	      WARN("Error parsing H header replacement (missing '(')\n");
	      break;
	    }
	    name_offset = 3;
	  }
	  if (s.length()<name_offset+1) {
	    WARN("Error parsing H header replacement (short string)\n");
	    break;
	  }

	  size_t skip_p = p+name_offset;
	  for (;skip_p<s.length() && s[skip_p] != ')';skip_p++) { }
	  if (skip_p==s.length()) {
	    WARN("Error parsing H header replacement (unclosed brackets)\n");
	    break;
	  }
	  string hdr_name = s.substr(p+name_offset, skip_p-p-name_offset);
	  // DBG("param_name = '%s' (skip-p - p = %d)\n", param_name.c_str(), skip_p-p);
	  if (name_offset == 2) {
	    // full header
	    res += getHeader(used_hdrs, hdr_name);
	  } else {
	    // parse URI and use component
	    AmUriParser uri_parser;
	    uri_parser.uri = getHeader(used_hdrs, hdr_name);
	    if ((s[p+1] == '.')) {
	      res += uri_parser.uri;
	      break;
	    }

	    if (!uri_parser.parse_uri()) {
	      WARN("Error parsing header %s URI '%s'\n",
		   hdr_name.c_str(), uri_parser.uri.c_str());
	      break;
	    }
	    //TODO: find out how to correct skip_chars correctly
	    replaceParsedParam(s, p, uri_parser, res);
	  }
	  skip_chars = skip_p-p;
	} break;

	case '_': { // modify
	  if (s.length()<p+4) { // $_O()
	    WARN("Error parsing $_ modifier replacement (short string)\n");
	    break;
	  }

	  char operation = s[p+1];
	  if (operation != 'U' && operation != 'l'
	      && operation != 's' && operation != '5') {
	    WARN("Error parsing $_%c string modifier: unknown operator '%c'\n",
		 operation, operation);
	  }

	  if (s[p+2] != '(') {
	    WARN("Error parsing $U upcase replacement (missing '(')\n");
	    break;
	  }

	  size_t skip_p = p+3;
	  skip_p = skip_to_end_of_brackets(s, skip_p);

	  if (skip_p==s.length()) {
	    WARN("Error parsing $_ modifier (unclosed brackets)\n");
	    skip_chars = skip_p-p;
	    break;
	  }

	  string br_str = s.substr(p+3, skip_p-p-3);
	  string br_str_replaced = 
	    replaceParameters(br_str, "$_*(...)",
			      req, call_profile, app_param,
			      ruri_parser, from_parser, to_parser,
			      rebuild_ruri, rebuild_from, rebuild_to);

	  br_str = br_str_replaced;
	  switch(operation) {
	  case 'u': // uppercase
	    transform(br_str_replaced.begin(), br_str_replaced.end(),
		      br_str_replaced.begin(), ::toupper); break;
	  case 'l': // lowercase
	    transform(br_str_replaced.begin(), br_str_replaced.end(),
		      br_str_replaced.begin(), ::tolower); break;

	  case 's': // size (string length)
	    br_str_replaced = int2str((unsigned int)br_str.length());
	    break;

	  case '5': // md5
	    br_str_replaced = calculateMD5(br_str);
	    break;

	  case 't': // extract 'transport' (last 3 characters)
	    if (br_str.length() >= 4) {
	      br_str_replaced = br_str.substr(br_str.length()-3);
	    }
	    break;

	  case 'r': // random
	    {
	      int r_max;
	      if (!str2int(br_str, r_max)){
		WARN("Error parsing $_r(%s) for random value, returning 0\n", br_str.c_str());
		br_str_replaced = "0";
	      } else {
		br_str_replaced = int2str(rand()%r_max);
	      }
	    }
	    break;

	  default:
	    WARN("Error parsing $_%c string modifier: unknown operator '%c'\n",
		 operation, operation);
	    break;
	  }
	  DBG("applied operator '%c': '%s' => '%s'\n", operation,
	      br_str.c_str(), br_str_replaced.c_str());
	  res+=br_str_replaced;

	  skip_chars = skip_p-p;
	} break;

	case 'm': // Request method
	  res += req.method;
	  break;

	case '#': { // URL encoding
	  if (s[p+1] != '(') {
	    WARN("Error parsing $# URL encoding (missing '(')\n");
	    break;
	  }
	  if (s.length()<p+3) {
	    WARN("Error parsing $# URL encoding (short string)\n");
	    break;
	  }

	  size_t skip_p = p+2;
	  skip_p = skip_to_end_of_brackets(s, skip_p);

	  if (skip_p==s.length()) {
	    WARN("Error parsing $# URL encoding (unclosed brackets)\n");
	    skip_chars = skip_p-p;
	    break;
	  }

	  string expr_str = s.substr(p+2, skip_p-p-2);
	  string expr_replaced = 
	    replaceParameters(expr_str, r_type, req,
			      call_profile, app_param, 
			      ruri_parser, from_parser, to_parser,
			      rebuild_ruri, rebuild_from, rebuild_to);

	  char* val_escaped = url_encode(expr_replaced.c_str());
	  res += string(val_escaped);
	  free(val_escaped);

	  skip_chars = skip_p-p;
	} break;

	default: {
	  WARN("unknown replace pattern $%c%c\n",
	       s[p], s[p+1]);
	}; break;
	};

	p+=skip_chars; // skip $.X
      } else {
	res += s[p];
      }
    } // end not escaped

    p++;
  }

  if (is_replaced) {
    DBG("%s pattern replace: '%s' -> '%s'\n", r_type, s.c_str(), res.c_str());
  }
  return res;
}


//
// URL encoding functions
//
// source code from http://www.geekhideout.com/urlcode.shtml
//

/* Converts a hex character to its integer value */
char from_hex(char ch) {
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
char to_hex(char code) {
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(const char *str) {

  const char* pstr = str;
  char* buf = (char*)malloc(strlen(str) * 3 + 1);
  char* pbuf = buf;

  while (*pstr) {
    if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || 
	*pstr == '.' || *pstr == '~') 
      *pbuf++ = *pstr;
    else if (*pstr == ' ') 
      *pbuf++ = '+';
    else 
      *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}

/* Returns a url-decoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_decode(char *str) {
  char *pstr = str, *buf = (char*)malloc(strlen(str) + 1), *pbuf = buf;
  while (*pstr) {
    if (*pstr == '%') {
      if (pstr[1] && pstr[2]) {
        *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
        pstr += 2;
      }
    } else if (*pstr == '+') { 
      *pbuf++ = ' ';
    } else {
      *pbuf++ = *pstr;
    }
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}
