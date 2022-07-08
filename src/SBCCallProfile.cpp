/*
 * Copyright (C) 2010-2011 Stefan Sayer
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

#include "SBCCallProfile.h"
#include "SBC.h"
#include <algorithm>

#include "log.h"
#include "AmUtils.h"
#include "AmPlugIn.h"
#include "AmLcConfig.h"

#include "SBCCallControlAPI.h"
#include "RTPParameters.h"
#include "SDPFilter.h"

#include "sip/pcap_logger.h"

typedef vector<SdpPayload>::iterator PayloadIterator;
//static string payload2str(const SdpPayload &p);

void PlaceholdersHash::update(const PlaceholdersHash &h)
{
    for(PlaceholdersHash::const_iterator i = h.begin();
        i != h.end(); i++)
    {
        (*this)[i->first] = i->second;
    }
}

//////////////////////////////////////////////////////////////////////////////////
// helper defines for parameter evaluation

#define REPLACE_VALS req, app_param, ruri_parser, from_parser, to_parser

// FIXME: r_type in replaceParameters is just for debug output?

#define REPLACE_STR(what) do {			  \
    what = ctx.replaceParameters(what, #what, req);	\
    DBG(#what " = '%s'", what.c_str());		\
  } while(0)

#define REPLACE_NONEMPTY_STR(what) do {		\
    if (!what.empty()) {			\
      REPLACE_STR(what);			\
    }						\
  } while(0)

#define REPLACE_NUM(what, dst_num) do {		\
    if (!what.empty()) {			    \
      what = ctx.replaceParameters(what, #what, req);	\
      unsigned int num;					\
      if (str2i(what, num)) {				   \
	ERROR(#what " '%s' not understood", what.c_str());	\
	return false;						\
      }								\
      DBG(#what " = '%s'", what.c_str());			\
      dst_num = num;						\
    }								\
  } while(0)

#define REPLACE_BOOL(what, dst_value) do {	\
    if (!what.empty()) {			    \
      what = ctx.replaceParameters(what, #what, req);	\
      if (!what.empty()) {				\
	if (!str2bool(what, dst_value)) {			\
	  ERROR(#what " '%s' not understood", what.c_str());	\
	  return false;						\
	}							\
      }								\
      DBG(#what " = '%s'", dst_value ? "yes" : "no");		\
    }								\
  } while(0)

#define REPLACE_IFACE_RTP(what, iface) do {				\
    if (!what.empty()) {						\
      what = ctx.replaceParameters(what, #what, req);			\
      DBG("set " #what " to '%s'", what.c_str());			\
      if (!what.empty()) {						\
	EVALUATE_IFACE_RTP(what, iface);				\
      }									\
    }									\
  } while(0)

#define EVALUATE_IFACE_RTP(what, iface) do {				\
    if (what == "default") iface = 0;					\
    else {								\
      map<string,unsigned short>::iterator name_it =			\
    AmConfig.media_if_names.find(what);				\
      if (name_it != AmConfig.media_if_names.end())			\
	iface = name_it->second;					\
      else {								\
	ERROR("selected " #what " '%s' does not exist as a media interface. " \
	      "Please check the 'additional_interfaces' "		\
	      "parameter in the main configuration file.",		\
	      what.c_str());						\
	return false;							\
      }									\
    }									\
  } while(0)

#define REPLACE_IFACE_SIP(what, iface) do {		\
    if (!what.empty()) {			    \
      what = ctx.replaceParameters(what, #what, req);	\
      DBG("set " #what " to '%s'", what.c_str());	\
      if (!what.empty()) {				\
	if (what == "default") iface = 0;		\
	else {								\
	  map<string,unsigned short>::iterator name_it =		\
        AmConfig.sip_if_names.find(what);				\
      if (name_it != AmConfig.sip_if_names.end()) \
	    iface = name_it->second;					\
	  else {							\
	    ERROR("selected " #what " '%s' does not exist as a signaling" \
		  " interface. "					\
		  "Please check the 'additional_interfaces' "		\
		  "parameter in the main configuration file.",		\
		  what.c_str());					\
	    return false;						\
	  }								\
	}								\
      }									\
    }									\
  } while(0)

//////////////////////////////////////////////////////////////////////////////////

/*static bool payloadDescsEqual(const vector<PayloadDesc> &a, const vector<PayloadDesc> &b)
{
  // not sure if this function is really needed (seems that vectors can be
  // compared using builtin operator== but anyway ...)
  if (a.size() != b.size()) return false;
  vector<PayloadDesc>::const_iterator ia = a.begin();
  vector<PayloadDesc>::const_iterator ib = b.begin();
  for (; ia != a.end(); ++ia, ++ib) {
    if (!(*ia == *ib)) return false;
  }

  return true;
}*/

bool SBCCallProfile::operator==(const SBCCallProfile& rhs) const {
  bool res =
    ruri == rhs.ruri &&
    ruri_host == rhs.ruri_host &&
    from == rhs.from &&
    to == rhs.to &&
    //contact == rhs.contact &&
    callid == rhs.callid &&
    outbound_proxy == rhs.outbound_proxy &&
    force_outbound_proxy == rhs.force_outbound_proxy &&
    aleg_outbound_proxy == rhs.aleg_outbound_proxy &&
    aleg_force_outbound_proxy == rhs.aleg_force_outbound_proxy &&
    next_hop == rhs.next_hop &&
    next_hop_1st_req == rhs.next_hop_1st_req &&
    next_hop_fixed == rhs.next_hop_fixed &&
    patch_ruri_next_hop == rhs.patch_ruri_next_hop &&
    aleg_next_hop == rhs.aleg_next_hop &&
    headerfilter_a2b == rhs.headerfilter_a2b &&
    headerfilter_b2a == rhs.headerfilter_b2a &&
    sdpfilter == rhs.sdpfilter &&
    mediafilter == rhs.mediafilter &&
    sst_enabled == rhs.sst_enabled &&
    sst_aleg_enabled == rhs.sst_aleg_enabled &&
    auth_enabled == rhs.auth_enabled &&
    auth_aleg_enabled == rhs.auth_aleg_enabled &&
    reply_translations == rhs.reply_translations &&
    append_headers == rhs.append_headers &&
    refuse_with == rhs.refuse_with &&
    rtprelay_enabled == rhs.rtprelay_enabled &&
    force_symmetric_rtp == rhs.force_symmetric_rtp;

  if (auth_enabled) {
    res = res &&
      auth_credentials.user == rhs.auth_credentials.user &&
      auth_credentials.pwd == rhs.auth_credentials.pwd;
  }
  if (auth_aleg_enabled) {
    res = res &&
      auth_aleg_credentials.user == rhs.auth_aleg_credentials.user &&
      auth_aleg_credentials.pwd == rhs.auth_aleg_credentials.pwd;
  }
  res = res && (transcoder == rhs.transcoder);
  return res;
}

string stringset_print(const set<string>& s) {
  string res;
  for (set<string>::const_iterator i=s.begin(); i != s.end(); i++)
    res += *i+" ";
  return res;
}

string SBCCallProfile::print() const {
  string res = 
    "SBC call profile dump: ~~~~~~~~~~~~~~~~~\n";
  res += "ruri:                 " + ruri + "\n";
  res += "ruri_host:            " + ruri_host + "\n";
  res += "from:                 " + from + "\n";
  res += "to:                   " + to + "\n";
  // res += "contact:              " + contact + "\n";
  res += "callid:               " + callid + "\n";
  res += "outbound_proxy:       " + outbound_proxy + "\n";
  res += "force_outbound_proxy: " + string(force_outbound_proxy?"true":"false") + "\n";
  res += "aleg_outbound_proxy:       " + aleg_outbound_proxy + "\n";
  res += "aleg_force_outbound_proxy: " + string(aleg_force_outbound_proxy?"true":"false") + "\n";
  res += "next_hop:             " + next_hop + "\n";
  res += "next_hop_1st_req:     " + string(next_hop_1st_req ? "true":"false") + "\n";
  res += "next_hop_fixed:       " + string(next_hop_fixed ? "true":"false") + "\n";
  res += "aleg_next_hop:        " + aleg_next_hop + "\n";
  // res += "headerfilter:         " + string(FilterType2String(headerfilter)) + "\n";
  // res += "headerfilter_list:    " + stringset_print(headerfilter_list) + "\n";
  // res += "messagefilter:        " + string(FilterType2String(messagefilter)) + "\n";
  // res += "messagefilter_list:   " + stringset_print(messagefilter_list) + "\n";
  // res += "sdpfilter_enabled:    " + string(sdpfilter_enabled?"true":"false") + "\n";
  // res += "sdpfilter:            " + string(FilterType2String(sdpfilter)) + "\n";
  // res += "sdpfilter_list:       " + stringset_print(sdpfilter_list) + "\n";
  // res += "sdpalinesfilter:      " + string(FilterType2String(sdpalinesfilter)) + "\n";
  // res += "sdpalinesfilter_list: " + stringset_print(sdpalinesfilter_list) + "\n";
  res += "sst_enabled:          " + int2str(sst_enabled) + "\n";
  res += "sst_aleg_enabled:     " + int2str(sst_aleg_enabled) + "\n";
  res += "auth_enabled:         " + string(auth_enabled?"true":"false") + "\n";
  res += "auth_user:            " + auth_credentials.user+"\n";
  res += "auth_pwd:             " + auth_credentials.pwd+"\n";
  res += "auth_aleg_enabled:    " + string(auth_aleg_enabled?"true":"false") + "\n";
  res += "auth_aleg_user:       " + auth_aleg_credentials.user+"\n";
  res += "auth_aleg_pwd:        " + auth_aleg_credentials.pwd+"\n";
  res += "rtprelay_enabled:     " + string(rtprelay_enabled?"true":"false") + "\n";
  res += "force_symmetric_rtp:  " + force_symmetric_rtp;

  res += transcoder.print();

  if (reply_translations.size()) {
    string reply_trans_codes;
    for(map<unsigned int, std::pair<unsigned int, string> >::const_iterator it=
	  reply_translations.begin(); it != reply_translations.end(); it++)
      reply_trans_codes += int2str(it->first)+"=>"+
	int2str(it->second.first)+" " + it->second.second+", ";
    reply_trans_codes.erase(reply_trans_codes.length()-2);

    res += "reply_trans_codes:     " + reply_trans_codes +"\n";
  }
  res += "append_headers:     " + append_headers + "\n";
  res += "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
  return res;
}

/*static bool isTranscoderNeeded(const AmSipRequest& req, vector<PayloadDesc> &caps,
			       bool default_value)
{
  const AmMimeBody* body = req.body.hasContentType(SIP_APPLICATION_SDP);
  if (!body) return default_value;

  AmSdp sdp;
  int res = sdp.parse((const char *)body->getPayload());
  if (res != 0) {
    DBG("SDP parsing failed!");
    return default_value;
  }
  
  // not nice, but we need to compare codec names and thus normalized SDP is
  // required
  normalizeSDP(sdp, false, "");

  // go through payloads and try find one of the supported ones
  for (vector<SdpMedia>::iterator m = sdp.media.begin(); m != sdp.media.end(); ++m) { 
    for (vector<SdpPayload>::iterator p = m->payloads.begin(); p != m->payloads.end(); ++p) {
      for (vector<PayloadDesc>::iterator i = caps.begin(); i != caps.end(); ++i) {
        if (i->match(*p)) return false; // found compatible codec
      }
    }
  }

  return true; // no compatible codec found, transcoding needed
}*/

void SBCCallProfile::eval_sst_config(ParamReplacerCtx& ctx,
				     const AmSipRequest& req,
				     AmConfigReader& sst_cfg)
{

#define SST_CFG_PARAM_COUNT 5  // Change if you add/remove params in below
  
  static const char* _sst_cfg_params[] = {
    "session_expires",
    "minimum_timer",
    "maximum_timer",
    "session_refresh_method",
    "accept_501_reply",
  };

  for(unsigned int i=0; i<SST_CFG_PARAM_COUNT; i++) {
    if (sst_cfg.hasParameter(_sst_cfg_params[i])) {
      string newval = 
	ctx.replaceParameters(sst_cfg.getParameter(_sst_cfg_params[i]),
			      _sst_cfg_params[i],req);
      if (newval.empty()) {
	sst_cfg.eraseParameter(_sst_cfg_params[i]);
      } else{
	sst_cfg.setParameter(_sst_cfg_params[i],newval);
      }
    }
  }
}

bool SBCCallProfile::evaluate_routing(
    ParamReplacerCtx& ctx,
    const AmSipRequest& req,
    AmSipDialog &dlg)
{
    REPLACE_NONEMPTY_STR(ruri);
    REPLACE_NONEMPTY_STR(ruri_host);

    REPLACE_NONEMPTY_STR(outbound_proxy);
    REPLACE_NONEMPTY_STR(next_hop);

    //apply routing-related values to dlg

    ctx.ruri_parser.uri = ruri.empty() ? req.r_uri : ruri;
    if(!ctx.ruri_parser.parse_uri()) {
        if(!ruri.empty()) {
            ERROR("Error parsing profile R-URI '%s'", ctx.ruri_parser.uri.data());
            throw AmSession::Exception(500,SIP_REPLY_SERVER_INTERNAL_ERROR);
        } else {
            DBG("Error parsing request R-URI '%s'",ctx.ruri_parser.uri.data());
            throw AmSession::Exception(400,"Failed to parse R-URI");
        }
    }

    if(!ruri_host.empty()) {
        ctx.ruri_parser.uri_port.clear();
        ctx.ruri_parser.uri_host = ruri_host;
        ctx.ruri_parser.uri = ctx.ruri_parser.uri_str();
    }

    if(!apply_b_routing(ctx.ruri_parser.uri, dlg))
        return false;

    //get outbound interface address
    int oif = dlg.getOutboundIf();
    const auto &pi = AmConfig.
        sip_ifs[static_cast<size_t>(oif)].
        proto_info[static_cast<size_t>(dlg.getOutboundProtoId())];

    ctx.outbound_interface_host = pi->getHost();

    return true;
}

bool SBCCallProfile::evaluate(ParamReplacerCtx& ctx, const AmSipRequest& req)
{
  REPLACE_NONEMPTY_STR(to);
  REPLACE_NONEMPTY_STR(callid);

  REPLACE_NONEMPTY_STR(dlg_contact_params);
  REPLACE_NONEMPTY_STR(bleg_dlg_contact_params);

  fix_append_hdrs(ctx, req);

  /*
   * must be evaluated after outbound_proxy & next_hop
   * because they are determine outbound inteface
   */
  REPLACE_NONEMPTY_STR(from); //must be evaluated after outbound_proxy

  if (!transcoder.evaluate(ctx,req)) return false;

  if (rtprelay_enabled || transcoder.isActive()) {
    // evaluate other RTP relay related params only if enabled
    // FIXME: really not evaluate rtprelay_enabled itself?
    /*REPLACE_BOOL(force_symmetric_rtp, force_symmetric_rtp_value);
    REPLACE_BOOL(aleg_force_symmetric_rtp, aleg_force_symmetric_rtp_value);*/

    REPLACE_IFACE_RTP(rtprelay_interface, rtprelay_interface_value);
    REPLACE_IFACE_RTP(aleg_rtprelay_interface, aleg_rtprelay_interface_value);
  }

  //REPLACE_BOOL(sst_enabled, sst_enabled_value);
  if(sst_enabled) {
    AmConfigReader& sst_cfg = sst_b_cfg;
    eval_sst_config(ctx,req,sst_cfg);
  }

  REPLACE_NONEMPTY_STR(append_headers);

  REPLACE_IFACE_SIP(outbound_interface, outbound_interface_value);

  if (!hold_settings.evaluate(ctx,req)) return false;

  // TODO: activate filter if transcoder or codec_prefs is set?
/*  if ((!aleg_payload_order.empty() || !bleg_payload_order.empty()) && (!sdpfilter_enabled)) {
    sdpfilter_enabled = true;
    sdpfilter = Transparent;
  }*/

  return true;
}


bool SBCCallProfile::evaluateOutboundInterface() {
  if (outbound_interface == "default") {
    outbound_interface_value = -1;
  } else {
    map<string,unsigned short>::const_iterator name_it =
      AmConfig.sip_if_names.find(outbound_interface);
    if (name_it != AmConfig.sip_if_names.end()) {
      outbound_interface_value = name_it->second;
    } else {
      ERROR("selected outbound_interface '%s' does not exist as a signaling"
	    " interface. "
	    "Please check the 'additional_interfaces' "
	    "parameter in the main configuration file.",
	    outbound_interface.c_str());
      return false;
    }
  }
  DBG("oubound interface resolved '%s' -> %d",
      outbound_interface.c_str(),outbound_interface_value);
  return true;
}

bool SBCCallProfile::evaluateRTPRelayInterface() {
  EVALUATE_IFACE_RTP(rtprelay_interface, rtprelay_interface_value);
  return true;
}

bool SBCCallProfile::evaluateRTPRelayAlegInterface() {
  EVALUATE_IFACE_RTP(aleg_rtprelay_interface, aleg_rtprelay_interface_value);
  return true;
}

static int apply_outbound_interface(const string& oi, AmBasicSipDialog& dlg)
{
  if (oi == "default")
    dlg.setOutboundInterface(0);
  else {
    map<string,unsigned short>::iterator name_it = AmConfig.sip_if_names.find(oi);
    if (name_it != AmConfig.sip_if_names.end()) {
      dlg.setOutboundInterface(name_it->second);
    } else {
      ERROR("selected [aleg_]outbound_interface '%s' "
	    "does not exist as an interface. "
	    "Please check the 'additional_interfaces' "
	    "parameter in the main configuration file.",
	    oi.c_str());
      
      return -1;
    }
  }

  return 0;
}

int SBCCallProfile::apply_a_routing(ParamReplacerCtx& ctx,
				    const AmSipRequest& req,
				    AmBasicSipDialog& dlg) const
{
  if (!aleg_outbound_interface.empty()) {
    string aleg_oi =
      ctx.replaceParameters(aleg_outbound_interface, 
			    "aleg_outbound_interface", req);

    if(apply_outbound_interface(aleg_oi,dlg) < 0)
      return -1;
  }

  if (!aleg_next_hop.empty()) {

    string aleg_nh = ctx.replaceParameters(aleg_next_hop, 
					   "aleg_next_hop", req);

    DBG("set next hop ip to '%s'", aleg_nh.c_str());
    dlg.setNextHop(aleg_nh);
  }
  else {
    dlg.nat_handling = dlg_nat_handling;
    if(dlg_nat_handling && req.first_hop) {
      string nh = req.remote_ip + ":"
	+ int2str(req.remote_port)
	+ "/" + req.trsp;
      dlg.setNextHop(nh);
      dlg.setNextHop1stReq(false);
    }
  }

  if (!aleg_outbound_proxy.empty()) {
    string aleg_op = 
      ctx.replaceParameters(aleg_outbound_proxy, "aleg_outbound_proxy", req);
    dlg.outbound_proxy = aleg_op;
    dlg.force_outbound_proxy = aleg_force_outbound_proxy;
  }

  return 0;
}

bool SBCCallProfile::apply_b_routing(
    const string &ruri,
    AmBasicSipDialog& dlg) const
{
    dlg.setRemoteUri(ruri);

    if (!outbound_proxy.empty()) {
        dlg.outbound_proxy = outbound_proxy;
        dlg.force_outbound_proxy = force_outbound_proxy;
    }

    if(!route.empty()) {
        DBG("set route to: %s",route.c_str());
        dlg.setRouteSet(route);
    }

    if (!next_hop.empty()) {
        DBG("set next hop to '%s' (1st_req=%s,fixed=%s)",
            next_hop.c_str(), next_hop_1st_req?"true":"false",
            next_hop_fixed?"true":"false");
        dlg.setNextHop(next_hop);
        dlg.setNextHop1stReq(next_hop_1st_req);
        dlg.setNextHopFixed(next_hop_fixed);
    }

    DBG("patch_ruri_next_hop = %i",patch_ruri_next_hop);
    dlg.setPatchRURINextHop(patch_ruri_next_hop);

    if (outbound_interface_value >= 0) {
        dlg.resetOutboundIf();
        dlg.setOutboundInterfaceName(outbound_interface);
    }

    dlg.setResolvePriority(static_cast<int>(bleg_protocol_priority_id));

    return true;
}

int SBCCallProfile::apply_common_fields(ParamReplacerCtx& ctx,
					AmSipRequest& req) const
{
  if(!ruri.empty()) {
    req.r_uri = ctx.replaceParameters(ruri, "RURI", req);
  }

  if (!ruri_host.empty()) {
    string ruri_h = ctx.replaceParameters(ruri_host, "RURI-host", req);

    ctx.ruri_parser.uri = req.r_uri;
    if (!ctx.ruri_parser.parse_uri()) {
      WARN("Error parsing R-URI '%s'", ctx.ruri_parser.uri.c_str());
      return -1;
    }
    else {
      ctx.ruri_parser.uri_port.clear();
      ctx.ruri_parser.uri_host = ruri_host;
      req.r_uri = ctx.ruri_parser.uri_str();
    }
  }

  if(!from.empty()) {
    req.from = ctx.replaceParameters(from, "From", req);
  }

  if(!to.empty()) {
    req.to = ctx.replaceParameters(to, "To", req);
  }

  if(!callid.empty()){
    req.callid = ctx.replaceParameters(callid, "Call-ID", req);
  }

  return 0;
}

#if 0
int SBCCallProfile::refuse(ParamReplacerCtx& ctx, const AmSipRequest& req) const
{
  string m_refuse_with = ctx.replaceParameters(refuse_with, "refuse_with", req);
  if (m_refuse_with.empty()) {
    ERROR("refuse_with empty after replacing (was '%s' in profile %s)",
	  refuse_with.c_str(), profile_file.c_str());
    return -1;
  }

  size_t spos = m_refuse_with.find(' ');
  unsigned int refuse_with_code;
  if (spos == string::npos || spos == m_refuse_with.size() ||
      str2i(m_refuse_with.substr(0, spos), refuse_with_code)) {
    ERROR("invalid refuse_with '%s'->'%s' in  %s. Expected <code> <reason>",
	  refuse_with.c_str(), m_refuse_with.c_str(), profile_file.c_str());
    return -1;
  }

  string refuse_with_reason = m_refuse_with.substr(spos+1);
  string hdrs = ctx.replaceParameters(append_headers, "append_headers", req);
  //TODO: hdrs = remove_empty_headers(hdrs);
  if (hdrs.size()>2) assertEndCRLF(hdrs);

  DBG("refusing call with %u %s", refuse_with_code, refuse_with_reason.c_str());
  AmSipDialog::reply_error(req, refuse_with_code, refuse_with_reason, hdrs);

  return 0;
}
#endif

/** removes headers with empty values from headers list separated by "\r\n" */
static string remove_empty_headers(const string& s, const char* field_name)
{
  string res(s), hdr;
  size_t start = 0, end = 0, len = 0, col = 0;
  DBG("%s: remove_empty_headers '%s'", field_name, s.c_str());

  if (res.empty())
    return res;

  do {
    end = res.find_first_of("\n", start);
    len = (end == string::npos ? res.size() - start : end - start + 1);
    hdr = res.substr(start, len);
    col = hdr.find_first_of(':');

    if (col && hdr.find_first_not_of(": \r\n", col) == string::npos) {
      // remove empty header
      DBG("%s: Ignored empty header: %s", field_name, res.substr(start, len).c_str());
      res.erase(start, len);
      // start remains the same
    }
    else {
      if (string::npos == col)
        DBG("%s: Malformed append header: %s", field_name, hdr.c_str());
      start = end + 1;
    }
  } while (end != string::npos && start < res.size());

  return res;
}

static void fix_append_hdr_list(const AmSipRequest& req, ParamReplacerCtx& ctx,
				string& append_hdr, const char* field_name)
{
  append_hdr = ctx.replaceParameters(append_hdr, field_name, req);
  append_hdr = remove_empty_headers(append_hdr, field_name);
  if (append_hdr.size()>2) assertEndCRLF(append_hdr);
}

void SBCCallProfile::fix_append_hdrs(ParamReplacerCtx& ctx,
				     const AmSipRequest& req)
{
  fix_append_hdr_list(req, ctx, append_headers, "append_headers");
  fix_append_hdr_list(req, ctx, append_headers_req,"append_headers_req");
  fix_append_hdr_list(req, ctx, aleg_append_headers_req,"aleg_append_headers_req");
  fix_append_hdr_list(req, ctx, aleg_append_headers_reply, "aleg_append_headers_reply");
}

static bool readPayload(SdpPayload &p, const string &src)
{
  vector<string> elems = explode(src, "/");

  if (elems.size() < 1) return false;

  if (elems.size() > 2) str2int(elems[1], p.encoding_param);
  if (elems.size() > 1) str2int(elems[1], p.clock_rate);
  else p.clock_rate = 8000; // default value
  p.encoding_name = elems[0];
  
  string pname = p.encoding_name;
  transform(pname.begin(), pname.end(), pname.begin(), ::tolower);

  // fix static payload type numbers
  // (http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xml)
  for (int i = 0; i < IANA_RTP_PAYLOADS_SIZE; i++) {
    string s = IANA_RTP_PAYLOADS[i].payload_name;
    transform(s.begin(), s.end(), s.begin(), ::tolower);
    if (p.encoding_name == s && 
        (unsigned)p.clock_rate == IANA_RTP_PAYLOADS[i].clock_rate && 
        (p.encoding_param == -1 || ((unsigned)p.encoding_param == IANA_RTP_PAYLOADS[i].channels))) 
      p.payload_type = i;
  }

  return true;
}

static bool read(const std::string &src, vector<SdpPayload> &codecs)
{
  vector<string> elems = explode(src, ",");

  AmPlugIn* plugin = AmPlugIn::instance();

  for (vector<string>::iterator it=elems.begin(); it != elems.end(); ++it) {
    SdpPayload p;
    if (!readPayload(p, *it)) return false;
    int payload_id = plugin->getDynPayload(p.encoding_name, p.clock_rate, 0);
    amci_payload_t* payload = plugin->payload(payload_id);
    if(!payload) {
      ERROR("Ignoring unknown payload found in call profile: %s/%i",
	    p.encoding_name.c_str(), p.clock_rate);
    }
    else {
      if(payload_id < DYNAMIC_PAYLOAD_TYPE_START)
	p.payload_type = payload->payload_id;
      else
	p.payload_type = -1;

      codecs.push_back(p);
    }
  }
  return true;
}

//////////////////////////////////////////////////////////////////////////////////

/*bool SBCCallProfile::TranscoderSettings::readTranscoderMode(const std::string &src)
{
  static const string always("always");
  static const string never("never");
  static const string on_missing_compatible("on_missing_compatible");

  if (src == always) { transcoder_mode = Always; return true; }
  if (src == never) { transcoder_mode = Never; return true; }
  if (src == on_missing_compatible) { transcoder_mode = OnMissingCompatible; return true; }
  if (src.empty()) { transcoder_mode = Never; return true; } // like default value
  ERROR("unknown value of enable_transcoder option: %s", src.c_str());

  return false;
}*/

void SBCCallProfile::TranscoderSettings::infoPrint() const
{
  //DBG("transcoder audio codecs: %s", audio_codecs_str.c_str());
  //DBG("callee codec capabilities: %s", callee_codec_capabilities_str.c_str());
  //DBG("enable transcoder: %s", transcoder_mode_str.c_str());
  //DBG("norelay audio codecs: %s", audio_codecs_norelay_str.c_str());
  //DBG("norelay audio codecs (aleg): %s", audio_codecs_norelay_aleg_str.c_str());
}

bool SBCCallProfile::TranscoderSettings::readConfig(AmConfigReader &cfg)
{
  return true;
}

bool SBCCallProfile::TranscoderSettings::operator==(const TranscoderSettings& rhs) const
{
  //bool res = (transcoder_mode == rhs.transcoder_mode);
  bool res = (enabled == rhs.enabled);
  //res = res && (payloadDescsEqual(callee_codec_capabilities, rhs.callee_codec_capabilities));
  //res = res && (audio_codecs == rhs.audio_codecs);
  return res;
}

string SBCCallProfile::TranscoderSettings::print() const
{
  /*string res("transcoder audio codecs:");
  for (vector<SdpPayload>::const_iterator i = audio_codecs.begin(); i != audio_codecs.end(); ++i) {
    res += " ";
    res += payload2str(*i);
  }*/

  /*res += "\ncallee codec capabilities:";
  for (vector<PayloadDesc>::const_iterator i = callee_codec_capabilities.begin(); 
      i != callee_codec_capabilities.end(); ++i)
  {
    res += " ";
    res += i->print();
  }*/

  /*string s("?");
  switch (transcoder_mode) {
    case Always: s = "always"; break;
    case Never: s = "never"; break;
    case OnMissingCompatible: s = "on_missing_compatible"; break;
  }
  res += "\nenable transcoder: " + s;*/
  
  string res("transcoder currently enabled: ");
  //res += "\ntranscoder currently enabled: ";
  if (enabled) res += "yes\n";
  else res += "no\n";
  
  return res;
}

bool SBCCallProfile::TranscoderSettings::evaluate(ParamReplacerCtx& ctx,
						  const AmSipRequest& req)
{
  DBG("transcoder is %s", enabled ? "enabled": "disabled");
  return true;
}

void SBCCallProfile::create_logger(const AmSipRequest& req)
{
  if (msg_logger_path.empty()) return;

  ParamReplacerCtx ctx(this);
  string log_path = ctx.replaceParameters(msg_logger_path, "msg_logger_path", req);
  if (log_path.empty()) return;

  file_msg_logger *log = new pcap_logger();

  if(log->open(log_path.c_str()) != 0) {
    // open error
    delete log;
    return;
  }

  // opened successfully
  logger.reset(log);
}

msg_logger* SBCCallProfile::get_logger(const AmSipRequest& req)
{
  if (!logger.get() && !msg_logger_path.empty()) create_logger(req);
  return logger.get();
}

//////////////////////////////////////////////////////////////////////////////////

bool PayloadDesc::match(const SdpPayload &p) const
{
  string enc_name = p.encoding_name;
  transform(enc_name.begin(), enc_name.end(), enc_name.begin(), ::tolower);
      
  if ((name.size() > 0) && (name != enc_name)) return false;
  if (clock_rate && (p.clock_rate > 0) && clock_rate != (unsigned)p.clock_rate) return false;
  return true;
}

bool PayloadDesc::read(const std::string &s)
{
  vector<string> elems = explode(s, "/");
  if (elems.size() > 1) {
    name = elems[0];
    str2i(elems[1], clock_rate);
  }
  else if (elems.size() > 0) {
    name = elems[0];
    clock_rate = 0;
  }
  transform(name.begin(), name.end(), name.begin(), ::tolower);
  return true;
}

string PayloadDesc::print() const
{
    std::string s(name); 
    s += " / "; 
    if (!clock_rate) s += "whatever rate";
    else s += int2str(clock_rate); 
    return s; 
}
    
bool PayloadDesc::operator==(const PayloadDesc &other) const
{
  if (name != other.name) return false;
  if (clock_rate != other.clock_rate) return false;
  return true;
}

//////////////////////////////////////////////////////////////////////////////////

void SBCCallProfile::HoldSettings::readConfig(AmConfigReader &cfg)
{
  // store string values for later evaluation
  aleg.mark_zero_connection_str = cfg.getParameter("hold_zero_connection_aleg");
  aleg.activity_str = cfg.getParameter("hold_activity_aleg");
  aleg.alter_b2b_str = cfg.getParameter("hold_alter_b2b_aleg");

  bleg.mark_zero_connection_str = cfg.getParameter("hold_zero_connection_bleg");
  bleg.activity_str = cfg.getParameter("hold_activity_bleg");
  bleg.alter_b2b_str = cfg.getParameter("hold_alter_b2b_bleg");
}

bool SBCCallProfile::HoldSettings::HoldParams::setActivity(const string &s)
{
  if (s == "sendrecv") activity = sendrecv;
  else if (s == "sendonly") activity = sendonly;
  else if (s == "recvonly") activity = recvonly;
  else if (s == "inactive") activity = inactive;
  else {
    ERROR("unsupported hold stream activity: %s", s.c_str());
    return false;
  }

  return true;
}

bool SBCCallProfile::HoldSettings::evaluate(ParamReplacerCtx& ctx, const AmSipRequest& req)
{
  REPLACE_BOOL(aleg.mark_zero_connection_str, aleg.mark_zero_connection);
  REPLACE_STR(aleg.activity_str);
  REPLACE_BOOL(aleg.alter_b2b_str, aleg.alter_b2b);

  REPLACE_BOOL(bleg.mark_zero_connection_str, bleg.mark_zero_connection);
  REPLACE_STR(bleg.activity_str);
  REPLACE_BOOL(bleg.alter_b2b_str, bleg.alter_b2b);

  if (!aleg.activity_str.empty() && !aleg.setActivity(aleg.activity_str)) return false;
  if (!bleg.activity_str.empty() && !bleg.setActivity(bleg.activity_str)) return false;

  return true;
}
