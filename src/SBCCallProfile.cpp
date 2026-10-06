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
#include "yeti.h"

#include "log.h"
#include "AmUtils.h"
#include "AmLcConfig.h"
#include "AmShallowUriParser.h"
#include "jsonArg.h"

#include "sip/pcap_logger.h"
#include "sip/parse_route.h"
#include "sip/parse_via.h"
#include "db/DbHelpers.h"
#include "resources/ResourceControl.h"

#include <algorithm>

void PlaceholdersHash::update(const PlaceholdersHash &h)
{
    for (PlaceholdersHash::const_iterator i = h.begin(); i != h.end(); i++) {
        (*this)[i->first] = i->second;
    }
}

//////////////////////////////////////////////////////////////////////////////////
// helper defines for parameter evaluation

#define REPLACE_VALS req, app_param, ruri_parser, from_parser, to_parser

// FIXME: r_type in replaceParameters is just for debug output?

#define REPLACE_STR(what)                                                                                              \
    do {                                                                                                               \
        what = ctx.replaceParameters(what, #what, req);                                                                \
        DBG(#what " = '%s'", what.c_str());                                                                            \
    } while (0)

#define REPLACE_NONEMPTY_STR(what)                                                                                     \
    do {                                                                                                               \
        if (!what.empty()) {                                                                                           \
            REPLACE_STR(what);                                                                                         \
        }                                                                                                              \
    } while (0)

#define REPLACE_NUM(what, dst_num)                                                                                     \
    do {                                                                                                               \
        if (!what.empty()) {                                                                                           \
            what = ctx.replaceParameters(what, #what, req);                                                            \
            unsigned int num;                                                                                          \
            if (str2i(what, num)) {                                                                                    \
                ERROR(#what " '%s' not understood", what.c_str());                                                     \
                return false;                                                                                          \
            }                                                                                                          \
            DBG(#what " = '%s'", what.c_str());                                                                        \
            dst_num = num;                                                                                             \
        }                                                                                                              \
    } while (0)

#define REPLACE_BOOL(what, dst_value)                                                                                  \
    do {                                                                                                               \
        if (!what.empty()) {                                                                                           \
            what = ctx.replaceParameters(what, #what, req);                                                            \
            if (!what.empty()) {                                                                                       \
                if (!str2bool(what, dst_value)) {                                                                      \
                    ERROR(#what " '%s' not understood", what.c_str());                                                 \
                    return false;                                                                                      \
                }                                                                                                      \
            }                                                                                                          \
            DBG(#what " = '%s'", dst_value ? "yes" : "no");                                                            \
        }                                                                                                              \
    } while (0)

#define REPLACE_IFACE_RTP(what, iface)                                                                                 \
    do {                                                                                                               \
        if (!what.empty()) {                                                                                           \
            what = ctx.replaceParameters(what, #what, req);                                                            \
            DBG("set " #what " to '%s'", what.c_str());                                                                \
            if (!what.empty()) {                                                                                       \
                EVALUATE_IFACE_RTP(what, iface);                                                                       \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

#define EVALUATE_IFACE_RTP(what, iface)                                                                                \
    do {                                                                                                               \
        if (what == "default")                                                                                         \
            iface = 0;                                                                                                 \
        else {                                                                                                         \
            map<string, unsigned short>::iterator name_it = AmConfig.media_if_names.find(what);                        \
            if (name_it != AmConfig.media_if_names.end())                                                              \
                iface = name_it->second;                                                                               \
            else {                                                                                                     \
                ERROR("selected " #what " '%s' does not exist as a media interface. "                                  \
                      "Please check the 'additional_interfaces' "                                                      \
                      "parameter in the main configuration file.",                                                     \
                      what.c_str());                                                                                   \
                return false;                                                                                          \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

#define REPLACE_IFACE_SIP(what, iface)                                                                                 \
    do {                                                                                                               \
        if (!what.empty()) {                                                                                           \
            what = ctx.replaceParameters(what, #what, req);                                                            \
            DBG("set " #what " to '%s'", what.c_str());                                                                \
            if (!what.empty()) {                                                                                       \
                if (what == "default")                                                                                 \
                    iface = 0;                                                                                         \
                else {                                                                                                 \
                    map<string, unsigned short>::iterator name_it = AmConfig.sip_if_names.find(what);                  \
                    if (name_it != AmConfig.sip_if_names.end())                                                        \
                        iface = name_it->second;                                                                       \
                    else {                                                                                             \
                        ERROR("selected " #what " '%s' does not exist as a signaling"                                  \
                              " interface. "                                                                           \
                              "Please check the 'additional_interfaces' "                                              \
                              "parameter in the main configuration file.",                                             \
                              what.c_str());                                                                           \
                        return false;                                                                                  \
                    }                                                                                                  \
                }                                                                                                      \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

//////////////////////////////////////////////////////////////////////////////////

string SBCCallProfile::print() const
{
    string res = "SBC call profile dump: ~~~~~~~~~~~~~~~~~\n";
    res += "ruri:                 " + ruri + "\n";
    res += "ruri_host:            " + ruri_host + "\n";
    res += "from:                 " + from + "\n";
    res += "to:                   " + to + "\n";
    res += "callid:               " + callid + "\n";
    res += "bleg_route_set:       " + bleg_route_set + "\n";
    res += "outbound_proxy:       " + outbound_proxy + "\n";
    res += "force_outbound_proxy: " + string(force_outbound_proxy ? "true" : "false") + "\n";
    res += "aleg_route_set:            " + aleg_route_set + "\n";
    res += "aleg_outbound_proxy:       " + aleg_outbound_proxy + "\n";
    res += "aleg_force_outbound_proxy: " + string(aleg_force_outbound_proxy ? "true" : "false") + "\n";
    res += "next_hop:             " + next_hop + "\n";
    res += "next_hop_1st_req:     " + string(next_hop_1st_req ? "true" : "false") + "\n";
    res += "next_hop_fixed:       " + string(next_hop_fixed ? "true" : "false") + "\n";
    res += "aleg_next_hop:        " + aleg_next_hop + "\n";
    res += "sst_enabled:          " + int2str(sst_enabled) + "\n";
    res += "sst_aleg_enabled:     " + int2str(sst_aleg_enabled) + "\n";
    res += "auth_enabled:         " + string(auth_enabled ? "true" : "false") + "\n";
    res += "auth_user:            " + auth_credentials.user + "\n";
    res += "auth_pwd:             " + auth_credentials.pwd + "\n";
    res += "auth_aleg_enabled:    " + string(auth_aleg_enabled ? "true" : "false") + "\n";
    res += "auth_aleg_user:       " + auth_aleg_credentials.user + "\n";
    res += "auth_aleg_pwd:        " + auth_aleg_credentials.pwd + "\n";
    res += "rtprelay_enabled:     " + string(rtprelay_enabled ? "true" : "false") + "\n";
    res += "force_symmetric_rtp:  " + int2str(force_symmetric_rtp);

    res += transcoder.print();

    if (reply_translations.size()) {
        string reply_trans_codes;
        for (map<unsigned int, std::pair<unsigned int, string>>::const_iterator it = reply_translations.begin();
             it != reply_translations.end(); it++)
            reply_trans_codes += int2str(it->first) + "=>" + int2str(it->second.first) + " " + it->second.second + ", ";
        reply_trans_codes.erase(reply_trans_codes.length() - 2);

        res += "reply_trans_codes:     " + reply_trans_codes + "\n";
    }
    res += "append_headers:     " + append_headers + "\n";
    res += "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    return res;
}

static void readMediaAcl(const AmArg &t, const char key[], std::vector<AmSubnet> &acl)
{
    if (!t.hasMember(key))
        return;

    AmArg &v = t[key];
    if (!isArgArray(v)) {
        DBG("expected array by the key: %s", key);
        return;
    }

    for (size_t i = 0; i < v.size(); i++) {
        AmArg &a = v[i];
        if (!isArgCStr(a)) {
            ERROR("skip unexpected array entry: %s", a.print().data());
            continue;
        }
        AmSubnet subnet;
        if (!subnet.parse(a.asCStr())) {
            ERROR("failed to parse subnet '%s' for %s", a.asCStr(), key);
            continue;
        }
        acl.emplace_back(subnet);
    }
}

static TransProt encryption_mode2transport(int mode, bool &allow_zrtp, const char *field_name)
{
    /*
     * 0  - RTP/AVP
     * 1  - RTP/SAVP
     * 2  - UDP/TLS/RTP/SAVP
     * 3  - ZRTP (RTP/AVP + zrtp_hash)
     */

    allow_zrtp = false;
    switch (mode) {
    case 3:  allow_zrtp = true;
    case 0:  return TP_RTPAVP;

    case 1:  return TP_RTPSAVP;
    case 2:  return TP_UDPTLSRTPSAVP;

    default: ERROR("unexpected %s value %d", field_name, mode); return TP_NONE;
    }
}

static void _patch_uri_transport(string &uri, unsigned int transport_id, const char *field_name,
                                 const char *transport_field_name)
{
    if (!transport_id || uri.empty())
        return;
    switch (transport_id) {
    case sip_transport::UDP: break;
    case sip_transport::TCP:
    case sip_transport::TLS:
    {
        AmShallowUriParser parser;
        auto               transport_name = transport_str(transport_id);
        DBG("patch %s to use transport %d. current value is: '%s'", field_name, transport_id, uri.c_str());

        if (!parser.parse_uri(uri)) {
            ERROR("Error parsing %s '%s' for protocol patching to %.*s. leave it as is", field_name, uri.c_str(),
                  transport_name.len, transport_name.s);
            break;
        }

        if (parser.patch_uri_transport_param(static_cast<sip_transport::sip_transport_id>(transport_id))) {
            uri = parser.uri_str();
            DBG("%s patched to: '%s'", field_name, uri.c_str());
        } else {
            const auto &transport_param = parser.get_uri_params().at("transport");
            ERROR("attempt to patch %s with existent transport parameter: '%.*s'."
                  " leave it as is",
                  field_name, transport_param.length(), transport_param.data());
        }
    } break;
    default: ERROR("%s %d is not supported yet. ignore it", transport_field_name, transport_id);
    }
}

bool SBCCallProfile::is_empty_profile(const AmArg &a)
{
    if (a.hasMember("ruri") && isArgCStr(a["ruri"]))
        return false;

    if (a.hasMember("disconnect_code_id") && isArgInt(a["disconnect_code_id"]))
        return false;

    return true;
}

bool SBCCallProfile::readFromTuple(const AmArg &t, const string &local_tag, const DynFieldsT &df,
                                   const string &lega_gw_cache_key, const string &legb_gw_cache_key)
{
    aleg_local_tag = local_tag;

    // common fields both for routing and refusing profiles

    ruri           = DbAmArg_hash_get_str(t, "ruri");
    outbound_proxy = DbAmArg_hash_get_str(t, "outbound_proxy");
    bleg_route_set = DbAmArg_hash_get_str(t, "bleg_route_set");

    string lega_res;
    if (t.hasMember("lega_res") || t.hasMember("legb_res")) {
        lega_res               = DbAmArg_hash_get_str(t, "lega_res");
        resources              = DbAmArg_hash_get_str(t, "legb_res");
        legab_res_mode_enabled = true;
    } else {
        resources = DbAmArg_hash_get_str(t, "resources");
    }

    append_headers = DbAmArg_hash_get_str(t, "append_headers");

    time_limit       = DbAmArg_hash_get_int(t, "time_limit", 0);
    aleg_override_id = DbAmArg_hash_get_int(t, "aleg_policy_id", 0);

    trusted_hdrs_gw = DbAmArg_hash_get_bool(t, "trusted_hdrs_gw", false);
    record_audio    = DbAmArg_hash_get_bool(t, "record_audio", false);

    dump_level_id = DbAmArg_hash_get_int(t, "dump_level_id", 0);
    dump_level_id |= AmConfig.dump_level;
    log_rtp = dump_level_id & LOG_RTP_MASK;
    log_sip = dump_level_id & LOG_SIP_MASK;

    if (!readDynFields(t, df)) {
        ERROR("failed to read dynamic fields");
        return false;
    }

    if (Yeti::instance().config.use_radius) {
        for (const auto &f : t) {
            placeholders_hash[f.first] = arg2json(f.second);
        }
    }

    disconnect_code_id = DbAmArg_hash_get_int(t, "disconnect_code_id", 0);
    if (0 != disconnect_code_id)
        return true; // skip excess fields reading for refusing profile

    // fields fore the routing profiles only

    try {
        lega_rl.parse(lega_res);
        rl.parse(resources);
    } catch (ResourceParseException &e) {
        ERROR("%s: resources parse error:  %s <ctx = '%s'>", aleg_local_tag.data(), e.what.c_str(), e.ctx.c_str());
    }

    from   = DbAmArg_hash_get_str(t, "from");
    to     = DbAmArg_hash_get_str(t, "to");
    callid = DbAmArg_hash_get_str(t, "call_id");

    dlg_nat_handling = DbAmArg_hash_get_bool(t, "dlg_nat_handling", false);

    force_outbound_proxy = DbAmArg_hash_get_bool(t, "force_outbound_proxy", false);
    outbound_proxy       = DbAmArg_hash_get_str(t, "outbound_proxy");

    aleg_force_outbound_proxy = DbAmArg_hash_get_bool(t, "aleg_force_outbound_proxy", false);
    aleg_outbound_proxy       = DbAmArg_hash_get_str(t, "aleg_outbound_proxy");
    aleg_route_set            = DbAmArg_hash_get_str(t, "aleg_route_set");

    next_hop            = DbAmArg_hash_get_str(t, "next_hop");
    next_hop_1st_req    = DbAmArg_hash_get_bool(t, "next_hop_1st_req", false);
    patch_ruri_next_hop = DbAmArg_hash_get_bool(t, "patch_ruri_next_hop", false);
    aleg_next_hop       = DbAmArg_hash_get_str(t, "aleg_next_hop");

    if (!readFilterSet(t, "transit_headers_a2b", headerfilter_a2b)) {
        ERROR("failed to read transit_headers_a2b");
        return false;
    }

    if (!readFilterSet(t, "transit_headers_b2a", headerfilter_b2a)) {
        ERROR("failed to read transit_headers_b2a");
        return false;
    }

    // SDP alines filter
    // filter out all unknown a-lines
    FilterEntry whitelist;
    whitelist.filter_type = Whitelist;
    sdpalinesfilter.push_back(whitelist);
    bleg_sdpalinesfilter.push_back(whitelist);

    sst_enabled = DbAmArg_hash_get_bool_any(t, "enable_session_timer", false);
    if (t.hasMember("enable_aleg_session_timer")) {
        sst_aleg_enabled = DbAmArg_hash_get_bool_any(t, "enable_aleg_session_timer", false);
    } else {
        sst_aleg_enabled = sst_enabled;
    }

#define CP_SST_CFGVAR(cfgprefix, cfgkey, dstcfg)                                                                       \
    if (t.hasMember(cfgprefix cfgkey)) {                                                                               \
        dstcfg.setParameter(cfgkey, DbAmArg_hash_get_str_any(t, cfgprefix cfgkey));                                    \
    } else {                                                                                                           \
        dstcfg.setParameter(cfgkey, DbAmArg_hash_get_str_any(t, cfgkey));                                              \
    }

#define CP_SESSION_REFRESH_METHOD(method_id, dstcfg)                                                                   \
    switch (method_id) {                                                                                               \
    case REFRESH_METHOD_INVITE: dstcfg.setParameter("session_refresh_method", "INVITE"); break;                        \
    case REFRESH_METHOD_UPDATE: dstcfg.setParameter("session_refresh_method", "UPDATE"); break;                        \
    case REFRESH_METHOD_UPDATE_FALLBACK_INVITE:                                                                        \
        dstcfg.setParameter("session_refresh_method", "UPDATE_FALLBACK_INVITE");                                       \
        break;                                                                                                         \
    default: ERROR("unknown session_refresh_method id '%d'", method_id); return false;                                 \
    }

    if (sst_enabled) {
        if (nullptr == SBCFactory::instance()->session_timer_fact) {
            ERROR("session_timer module not loaded thus SST not supported, but required");
            return false;
        }
        sst_b_cfg.setParameter("enable_session_timer", "yes");
        // create sst_cfg with values from aleg_*
        CP_SST_CFGVAR("", "session_expires", sst_b_cfg);
        CP_SST_CFGVAR("", "minimum_timer", sst_b_cfg);
        CP_SST_CFGVAR("", "maximum_timer", sst_b_cfg);
        // CP_SST_CFGVAR("", "session_refresh_method", sst_b_cfg);
        CP_SST_CFGVAR("", "accept_501_reply", sst_b_cfg);
        int refresh_method_id = DbAmArg_hash_get_int(t, "session_refresh_method_id", 1);
        CP_SESSION_REFRESH_METHOD(refresh_method_id, sst_b_cfg);
    }

    if (sst_aleg_enabled) {
        sst_a_cfg.setParameter("enable_session_timer", "yes");
        // create sst_a_cfg superimposing values from aleg_*
        CP_SST_CFGVAR("aleg_", "session_expires", sst_a_cfg);
        CP_SST_CFGVAR("aleg_", "minimum_timer", sst_a_cfg);
        CP_SST_CFGVAR("aleg_", "maximum_timer", sst_a_cfg);
        // CP_SST_CFGVAR("aleg_", "session_refresh_method", sst_a_cfg);
        CP_SST_CFGVAR("aleg_", "accept_501_reply", sst_a_cfg);
        int refresh_method_id = DbAmArg_hash_get_int(t, "aleg_session_refresh_method_id", 1);
        CP_SESSION_REFRESH_METHOD(refresh_method_id, sst_a_cfg);
    }
#undef CP_SST_CFGVAR
#undef CP_SESSION_REFRESH_METHOD

    auth_enabled          = DbAmArg_hash_get_bool(t, "enable_auth", false);
    auth_credentials.user = DbAmArg_hash_get_str(t, "auth_user");
    auth_credentials.pwd  = DbAmArg_hash_get_str(t, "auth_pwd");

    auth_aleg_enabled          = DbAmArg_hash_get_bool(t, "enable_aleg_auth", false);
    auth_aleg_credentials.user = DbAmArg_hash_get_str(t, "auth_aleg_user");
    auth_aleg_credentials.pwd  = DbAmArg_hash_get_str(t, "auth_aleg_pwd");

    vector<string> reply_translations_v = explode(DbAmArg_hash_get_str_any(t, "reply_translations"), "|");

    for (vector<string>::iterator it = reply_translations_v.begin(); it != reply_translations_v.end(); it++) {
        // expected: "603=>488 Not acceptable here"
        vector<string> trans_components = explode(*it, "=>");
        if (trans_components.size() != 2) {
            ERROR("entry '%s' in reply_translations could not be understood.", it->c_str());
            ERROR("expected 'from_code=>to_code reason'");
            return false;
        }

        unsigned int from_code, to_code;
        if (str2i(trans_components[0], from_code)) {
            ERROR("code '%s' in reply_translations not understood.", trans_components[0].c_str());
            return false;
        }
        unsigned int s_pos    = 0;
        string       to_reply = trans_components[1];
        while (s_pos < to_reply.length() && to_reply[s_pos] != ' ')
            s_pos++;
        if (str2i(to_reply.substr(0, s_pos), to_code)) {
            ERROR("code '%s' in reply_translations not understood.", to_reply.substr(0, s_pos).c_str());
            return false;
        }
        if (s_pos < to_reply.length())
            s_pos++;
        // DBG("got translation %u => %u %s",
        // 	from_code, to_code, to_reply.substr(s_pos).c_str());
        reply_translations[from_code] = make_pair(to_code, to_reply.substr(s_pos));
    }

    append_headers_req        = DbAmArg_hash_get_str(t, "append_headers_req");
    aleg_append_headers_req   = DbAmArg_hash_get_str(t, "aleg_append_headers_req");
    aleg_append_headers_reply = DbAmArg_hash_get_str(t, "aleg_append_headers_reply");

    rtprelay_enabled         = DbAmArg_hash_get_bool(t, "enable_rtprelay", false);
    force_symmetric_rtp      = DbAmArg_hash_get_bool(t, "bleg_force_symmetric_rtp", false);
    aleg_force_symmetric_rtp = DbAmArg_hash_get_bool(t, "aleg_force_symmetric_rtp", false);

    rtprelay_interface      = DbAmArg_hash_get_str(t, "rtprelay_interface");
    aleg_rtprelay_interface = DbAmArg_hash_get_str(t, "aleg_rtprelay_interface");

    outbound_interface      = DbAmArg_hash_get_str(t, "outbound_interface");
    aleg_outbound_interface = DbAmArg_hash_get_str(t, "aleg_outbound_interface");

    bleg_force_cancel_routeset = DbAmArg_hash_get_bool(t, "bleg_force_cancel_routeset", false);

    if (!readCodecPrefs(t)) {
        ERROR("failed to read codec prefs");
        return false;
    }

    disconnect_code_id = DbAmArg_hash_get_int(t, "disconnect_code_id", 0);

    bleg_override_id = DbAmArg_hash_get_int(t, "bleg_policy_id", 0);

    ringing_timeout = DbAmArg_hash_get_int(t, "ringing_timeout", 0);

    global_tag = DbAmArg_hash_get_str(t, "global_tag");

    rtprelay_dtmf_filtering   = DbAmArg_hash_get_bool(t, "rtprelay_dtmf_filtering", false);
    rtprelay_dtmf_detection   = DbAmArg_hash_get_bool(t, "rtprelay_dtmf_detection", false);
    rtprelay_force_dtmf_relay = DbAmArg_hash_get_bool(t, "rtprelay_force_dtmf_relay", true);

    aleg_symmetric_rtp_nonstop = DbAmArg_hash_get_bool(t, "aleg_symmetric_rtp_nonstop", false);
    bleg_symmetric_rtp_nonstop = DbAmArg_hash_get_bool(t, "bleg_symmetric_rtp_nonstop", false);

    aleg_relay_options = DbAmArg_hash_get_bool(t, "aleg_relay_options", false);
    bleg_relay_options = DbAmArg_hash_get_bool(t, "bleg_relay_options", false);

    aleg_relay_update = DbAmArg_hash_get_bool(t, "aleg_relay_update", true);
    bleg_relay_update = DbAmArg_hash_get_bool(t, "bleg_relay_update", true);

    filter_noaudio_streams = DbAmArg_hash_get_bool(t, "filter_noaudio_streams", true);

    aleg_rtp_ping = DbAmArg_hash_get_bool(t, "aleg_rtp_ping", false);
    bleg_rtp_ping = DbAmArg_hash_get_bool(t, "bleg_rtp_ping", false);

    aleg_conn_location_id = DbAmArg_hash_get_int(t, "aleg_sdp_c_location_id", 0);
    bleg_conn_location_id = DbAmArg_hash_get_int(t, "bleg_sdp_c_location_id", 0);

    dead_rtp_time = DbAmArg_hash_get_int(t, "dead_rtp_time", AmConfig.dead_rtp_time);

    aleg_relay_reinvite = DbAmArg_hash_get_bool(t, "aleg_relay_reinvite", true);
    bleg_relay_reinvite = DbAmArg_hash_get_bool(t, "bleg_relay_reinvite", true);
    /*assign_bool_safe(aleg_relay_prack,"aleg_relay_prack",true,true);
    assign_bool_safe(bleg_relay_prack,"bleg_relay_prack",true,true);*/
    aleg_relay_hold = DbAmArg_hash_get_bool(t, "aleg_relay_hold", true);
    bleg_relay_hold = DbAmArg_hash_get_bool(t, "bleg_relay_hold", true);

    aleg_contact_user = DbAmArg_hash_get_str(t, "aleg_contact_user", "");
    bleg_contact_user = DbAmArg_hash_get_str(t, "bleg_contact_user", "");

    relay_timestamp_aligning = DbAmArg_hash_get_bool(t, "rtp_relay_timestamp_aligning", false);

    allow_1xx_without_to_tag = DbAmArg_hash_get_bool(t, "allow_1xx_wo2tag", false);

    inv_transaction_timeout  = DbAmArg_hash_get_int(t, "invite_timeout", 0);
    inv_srv_failover_timeout = DbAmArg_hash_get_int(t, "srv_failover_timeout", 0);
    /*assign_type_safe(inv_transaction_timeout,"invite_timeout",0,unsigned int,0);
    assign_type_safe(inv_srv_failover_timeout,"srv_failover_timeout",0,unsigned int,0);*/

    force_relay_CN = DbAmArg_hash_get_bool(t, "rtp_force_relay_cn", false);

    aleg_sensor_id       = DbAmArg_hash_get_int(t, "aleg_sensor_id", -1);
    bleg_sensor_id       = DbAmArg_hash_get_int(t, "bleg_sensor_id", -1);
    aleg_sensor_level_id = DbAmArg_hash_get_int(t, "aleg_sensor_level_id", 0);
    bleg_sensor_level_id = DbAmArg_hash_get_int(t, "bleg_sensor_level_id", 0);

    aleg_dtmf_send_mode_id = DbAmArg_hash_get_int(t, "aleg_dtmf_send_mode_id", DTMF_TX_MODE_RFC2833);
    bleg_dtmf_send_mode_id = DbAmArg_hash_get_int(t, "bleg_dtmf_send_mode_id", DTMF_TX_MODE_RFC2833);
    aleg_dtmf_recv_modes   = DbAmArg_hash_get_int(t, "aleg_dtmf_recv_modes", DTMF_RX_MODE_ALL);
    bleg_dtmf_recv_modes   = DbAmArg_hash_get_int(t, "bleg_dtmf_recv_modes", DTMF_RX_MODE_ALL);

    aleg_rtp_filter_inband_dtmf = DbAmArg_hash_get_bool(t, "aleg_rtp_filter_inband_dtmf", false);
    bleg_rtp_filter_inband_dtmf = DbAmArg_hash_get_bool(t, "bleg_rtp_filter_inband_dtmf", false);

    if (aleg_rtp_filter_inband_dtmf || bleg_rtp_filter_inband_dtmf || (aleg_dtmf_recv_modes & DTMF_RX_MODE_INBAND) ||
        (bleg_dtmf_recv_modes & DTMF_RX_MODE_INBAND))
    {
        transcoder.dtmf_mode = TranscoderSettings::DTMFAlways;
        force_transcoding    = true;
    } else {
        transcoder.dtmf_mode = TranscoderSettings::DTMFNever;
    }

    suppress_early_media      = DbAmArg_hash_get_bool_optional(t, "suppress_early_media");
    force_one_way_early_media = DbAmArg_hash_get_bool(t, "force_one_way_early_media", false);
    fake_ringing_timeout      = DbAmArg_hash_get_int(t, "fake_180_timer", 0);

    aleg_rel100_mode_id = DbAmArg_hash_get_int(t, "aleg_rel100_mode_id", -1);
    bleg_rel100_mode_id = DbAmArg_hash_get_int(t, "bleg_rel100_mode_id", -1);

    radius_profile_id          = DbAmArg_hash_get_int(t, "radius_auth_profile_id", 0);
    aleg_radius_acc_profile_id = DbAmArg_hash_get_int(t, "aleg_radius_acc_profile_id", 0);
    bleg_radius_acc_profile_id = DbAmArg_hash_get_int(t, "bleg_radius_acc_profile_id", 0);

    _patch_uri_transport(ruri, DbAmArg_hash_get_int(t, "bleg_transport_protocol_id", 0), "ruri",
                         "bleg_transport_protocol_id");
    _patch_uri_transport(outbound_proxy, DbAmArg_hash_get_int(t, "bleg_outbound_proxy_transport_protocol_id", 0),
                         "outbound_proxy", "bleg_outbound_proxy_transport_protocol_id");
    _patch_uri_transport(aleg_outbound_proxy, DbAmArg_hash_get_int(t, "aleg_outbound_proxy_transport_protocol_id", 0),
                         "aleg_outbound_proxy", "aleg_outbound_proxy_transport_protocol_id");

    bleg_protocol_priority_id = DbAmArg_hash_get_int(t, "bleg_protocol_priority_id", dns_priority::IPv4_only);

    bleg_max_30x_redirects = DbAmArg_hash_get_int(t, "bleg_max_30x_redirects", 0);
    bleg_max_transfers     = DbAmArg_hash_get_int(t, "bleg_max_transfers", 0);

    auth_required = DbAmArg_hash_get_bool(t, "aleg_auth_required", false);

    registered_aor_id      = DbAmArg_hash_get_int(t, "registered_aor_id", 0);
    registered_aor_mode_id = DbAmArg_hash_get_int(t, "registered_aor_mode_id", REGISTERED_AOR_MODE_AS_IS);

    pidflo_mode_id = DbAmArg_hash_get_int(t, "pidflo_mode_id", PIDFLO_MODE_DISABLED);

    aleg_media_transport = encryption_mode2transport(DbAmArg_hash_get_int(t, "aleg_media_encryption_mode_id", 0),
                                                     aleg_media_allow_zrtp, "aleg_media_encryption_mode_id");
    bleg_media_transport = encryption_mode2transport(DbAmArg_hash_get_int(t, "bleg_media_encryption_mode_id", 0),
                                                     bleg_media_allow_zrtp, "bleg_media_encryption_mode_id");

    readMediaAcl(t, "aleg_rtp_acl", aleg_rtp_acl);
    readMediaAcl(t, "bleg_rtp_acl", bleg_rtp_acl);

    ss_crt_id    = DbAmArg_hash_get_int(t, "ss_crt_id", 0);
    ss_attest_id = DbAmArg_hash_get_int(t, "ss_attest_id", 3 /* attest level C */);
    ss_otn       = DbAmArg_hash_get_str(t, "ss_otn");
    ss_dtn       = DbAmArg_hash_get_str(t, "ss_dtn");

    if (ss_otn.empty() || ss_dtn.empty()) {
        // disable jwt signing on empty orig_tn/dest_tn
        ss_crt_id = 0;
    }

    push_token = DbAmArg_hash_get_str(t, "push_token");

    lega_gw_cache_id = !lega_gw_cache_key.empty()
                           ? DbAmArg_hash_get_as_number<decltype(lega_gw_cache_id)>(t, lega_gw_cache_key, 0)
                           : 0;
    legb_gw_cache_id = !legb_gw_cache_key.empty()
                           ? DbAmArg_hash_get_as_number<decltype(legb_gw_cache_id)>(t, legb_gw_cache_key, 0)
                           : 0;

    DBG("Yeti: loaded SQL profile");

    return true;
}

bool SBCCallProfile::readFilterSet(const AmArg &t, const char *cfg_key_filter, vector<FilterEntry> &filter_list)
{
    string s;
    s = DbAmArg_hash_get_str(t, cfg_key_filter);

    if (s.empty()) {
        FilterEntry f;
        f.filter_type = Whitelist;
        filter_list.push_back(f);
        return true;
    }

    vector<string> filters = explode(s, ";", true);
    for (vector<string>::iterator filter = filters.begin(); filter != filters.end(); filter++) {
        FilterEntry f;
        f.filter_type = Whitelist;

        if (filter->empty()) {
            filter_list.push_back(f);
            continue;
        }

        std::transform(filter->begin(), filter->end(), filter->begin(), ::tolower);

        vector<string> values = explode(*filter, ",");
        for (vector<string>::iterator value = values.begin(); value != values.end(); value++) {
            f.filter_list.insert(*value);
        }
        filter_list.push_back(f);
    }
    return true;
}

bool SBCCallProfile::readCodecPrefs(const AmArg &t)
{
    static_codecs_aleg_id = DbAmArg_hash_get_int(t, "aleg_codecs_group_id", 0);
    static_codecs_bleg_id = DbAmArg_hash_get_int(t, "bleg_codecs_group_id", 0);

    aleg_single_codec = DbAmArg_hash_get_bool(t, "aleg_single_codec_in_200ok", false);
    bleg_single_codec = DbAmArg_hash_get_bool(t, "bleg_single_codec_in_200ok", false);
    avoid_transcoding = DbAmArg_hash_get_bool(t, "try_avoid_transcoding", false);

    return true;
}

bool SBCCallProfile::readDynFields(const AmArg &t, const DynFieldsT &df)
{
    dyn_fields.assertStruct();
    for (DynFieldsT::const_iterator it = df.begin(); it != df.end(); ++it) {
        dyn_fields[it->name] = t.hasMember(it->name) ? t[it->name] : AmArg();
    }
    return true;
}

ResourceList &SBCCallProfile::getResourceList(bool a_leg)
{
    return legab_res_mode_enabled ? (a_leg ? lega_rl : rl) : rl;
}

bool SBCCallProfile::eval_resources(const ResourceControl &rctl)
{
    rctl.eval_resources(lega_rl);
    rctl.eval_resources(rl);
    return true;
}

bool SBCCallProfile::eval_radius()
{
    if (Yeti::instance().config.use_radius) {
        AmDynInvoke *radius_client = NULL;
        if (aleg_radius_acc_profile_id) {
            AmArg rules;
            radius_client = AmPlugIn::instance()->getFactory4Di("radius_client")->getInstance();
            radius_client->invoke("r", aleg_radius_acc_profile_id, rules);
            aleg_radius_acc_rules.unpack(rules);
        }
        if (bleg_radius_acc_profile_id) {
            AmArg rules;
            if (!radius_client)
                radius_client = AmPlugIn::instance()->getFactory4Di("radius_client")->getInstance();
            radius_client->invoke("r", bleg_radius_acc_profile_id, rules);
            bleg_radius_acc_rules.unpack(rules);
        }
    } else {
        if (radius_profile_id) {
            ERROR("%s: got call_profile with radius_profile_id set, but radius_client module is not loaded",
                  aleg_local_tag.data());
            return false;
        }
        if (aleg_radius_acc_profile_id) {
            ERROR("%s: got call_profile with aleg_radius_acc_profile_id set, but radius_client module is not loaded",
                  aleg_local_tag.data());
            return false;
        }
        if (bleg_radius_acc_profile_id) {
            ERROR("%s: got call_profile with bleg_radius_acc_profile_id set, but radius_client module is not loaded",
                  aleg_local_tag.data());
            return false;
        }
    }
    return true;
}

bool SBCCallProfile::eval_media_encryption()
{
    if (TP_NONE == aleg_media_transport) {
        ERROR("%s: unsupported aleg media encryption mode", aleg_local_tag.data());
        return false;
    }

    if (TP_NONE == bleg_media_transport) {
        ERROR("%s: unsupported bleg media encryption mode", aleg_local_tag.data());
        return false;
    }

    return true;
}

bool SBCCallProfile::eval_protocol_priority()
{
    switch (bleg_protocol_priority_id) {
    case IPv4_only:
    case IPv6_only:
    case Dualstack:
    case IPv4_pref:
    case IPv6_pref: return true;
    default:        ERROR("%s: unknown protocol priority: %d", aleg_local_tag.data(), bleg_protocol_priority_id);
    }
    return false;
}

bool SBCCallProfile::eval(const ResourceControl &rctl)
{
    if (0 != disconnect_code_id) {
        DBG("skip evals for refusing profile");
        return true;
    }

    if (ruri.empty()) {
        ERROR("%s: got non-refusing profile with empty RURI", aleg_local_tag.data());
        return false;
    }

    if (!outbound_interface.empty())
        if (!evaluateOutboundInterface())
            return false;

    if (registered_aor_mode_id < REGISTERED_AOR_MODE_DISABLED ||
        registered_aor_mode_id > REGISTERED_AOR_MODE_REPLACE_RURI_TRANSPORT_INFO)
    {
        DBG("%s: incorrect registered_aor_mode_id value. replace %d -> %d", aleg_local_tag.data(),
            registered_aor_mode_id, REGISTERED_AOR_MODE_AS_IS);
        registered_aor_mode_id = REGISTERED_AOR_MODE_AS_IS;
    }

    if (!bleg_route_set.empty() && (parse_and_validate_route(bleg_route_set) != 0)) {
        ERROR("failed to parse bleg_route_set. ignore it: %s", bleg_route_set.c_str());
        bleg_route_set.clear();
    }

    if (!aleg_route_set.empty() && (parse_and_validate_route(aleg_route_set) != 0)) {
        ERROR("failed to parse aleg_route_set. ignore it: %s", aleg_route_set.c_str());
        aleg_route_set.clear();
    }

    return eval_protocol_priority() && eval_resources(rctl) && eval_radius() && eval_media_encryption();
}

void SBCCallProfile::info(AmArg &s)
{
    s["ruri"]               = ruri;
    s["from"]               = from;
    s["to"]                 = to;
    s["resource_handler"]   = resource_handler;
    s["append_headers"]     = append_headers;
    s["outbound_interface"] = outbound_interface;
    for (const auto &f : dyn_fields)
        s[f.first] = f.second;
}

void SBCCallProfile::eval_sst_config(ParamReplacerCtx &ctx, const AmSipRequest &req, AmConfigReader &sst_cfg)
{

#define SST_CFG_PARAM_COUNT 5 // Change if you add/remove params in below

    static const char *_sst_cfg_params[] = {
        "session_expires", "minimum_timer", "maximum_timer", "session_refresh_method", "accept_501_reply",
    };

    for (unsigned int i = 0; i < SST_CFG_PARAM_COUNT; i++) {
        if (sst_cfg.hasParameter(_sst_cfg_params[i])) {
            string newval = ctx.replaceParameters(sst_cfg.getParameter(_sst_cfg_params[i]), _sst_cfg_params[i], req);
            if (newval.empty()) {
                sst_cfg.eraseParameter(_sst_cfg_params[i]);
            } else {
                sst_cfg.setParameter(_sst_cfg_params[i], newval);
            }
        }
    }
}

bool SBCCallProfile::evaluate_routing(ParamReplacerCtx &ctx, const AmSipRequest &req, AmSipDialog &dlg)
{
    REPLACE_NONEMPTY_STR(ruri);
    REPLACE_NONEMPTY_STR(ruri_host);

    REPLACE_NONEMPTY_STR(outbound_proxy);
    REPLACE_NONEMPTY_STR(bleg_route_set);
    REPLACE_NONEMPTY_STR(next_hop);

    // apply routing-related values to dlg

    const auto &r_uri = ruri.empty() ? req.r_uri : ruri;
    if (!ctx.ruri_parser.parse_uri(r_uri)) {
        if (!ruri.empty()) {
            ERROR("Error parsing profile R-URI '%s'", r_uri.data());
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        } else {
            DBG("Error parsing request R-URI '%s'", r_uri.data());
            throw AmSession::Exception(400, "Failed to parse R-URI");
        }
    }

    if (!ruri_host.empty()) {
        ctx.ruri_parser.set_uri_port(0);
        ctx.ruri_parser.set_uri_host(ruri_host);
        ctx.ruri_parser.set_uri_host(ruri_host);
    }

    if (!apply_b_routing(ctx.ruri_parser.uri_str(), dlg))
        return false;

    // get outbound interface address
    int         oif = dlg.getOutboundIf();
    const auto &pi =
        AmConfig.sip_ifs[static_cast<size_t>(oif)].proto_info[static_cast<size_t>(dlg.getOutboundProtoId())];

    ctx.outbound_interface_host = pi->getHost();

    return true;
}

bool SBCCallProfile::evaluate(ParamReplacerCtx &ctx, const AmSipRequest &req)
{
    REPLACE_NONEMPTY_STR(to);
    REPLACE_NONEMPTY_STR(callid);

    REPLACE_NONEMPTY_STR(dlg_contact_params);
    REPLACE_NONEMPTY_STR(bleg_dlg_contact_params);
    REPLACE_NONEMPTY_STR(aleg_contact_user);
    REPLACE_NONEMPTY_STR(bleg_contact_user);

    fix_append_hdrs(ctx, req);

    /*
     * must be evaluated after outbound_proxy & next_hop
     * because they are determine outbound inteface
     */
    REPLACE_NONEMPTY_STR(from); // must be evaluated after outbound_proxy

    if (!transcoder.evaluate(ctx, req))
        return false;

    if (rtprelay_enabled || transcoder.isActive()) {
        REPLACE_IFACE_RTP(rtprelay_interface, rtprelay_interface_value);
        REPLACE_IFACE_RTP(aleg_rtprelay_interface, aleg_rtprelay_interface_value);
    }

    // REPLACE_BOOL(sst_enabled, sst_enabled_value);
    if (sst_enabled) {
        AmConfigReader &sst_cfg = sst_b_cfg;
        eval_sst_config(ctx, req, sst_cfg);
    }

    REPLACE_NONEMPTY_STR(append_headers);

    REPLACE_IFACE_SIP(outbound_interface, outbound_interface_value);

    if (!hold_settings.evaluate(ctx, req))
        return false;

    // TODO: activate filter if transcoder or codec_prefs is set?
    /*  if ((!aleg_payload_order.empty() || !bleg_payload_order.empty()) && (!sdpfilter_enabled)) {
        sdpfilter_enabled = true;
        sdpfilter = Transparent;
      }*/

    return true;
}


bool SBCCallProfile::evaluateOutboundInterface()
{
    if (outbound_interface == "default") {
        outbound_interface_value = -1;
    } else {
        map<string, unsigned short>::const_iterator name_it = AmConfig.sip_if_names.find(outbound_interface);
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
    DBG("oubound interface resolved '%s' -> %d", outbound_interface.c_str(), outbound_interface_value);
    return true;
}

static int apply_outbound_interface(const string &oi, AmBasicSipDialog &dlg)
{
    if (oi == "default")
        dlg.setOutboundInterface(0);
    else {
        map<string, unsigned short>::iterator name_it = AmConfig.sip_if_names.find(oi);
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

int SBCCallProfile::apply_a_routing(ParamReplacerCtx &ctx, const AmSipRequest &req, AmBasicSipDialog &dlg) const
{
    if (!aleg_outbound_interface.empty()) {
        string aleg_oi = ctx.replaceParameters(aleg_outbound_interface, "aleg_outbound_interface", req);

        if (apply_outbound_interface(aleg_oi, dlg) < 0)
            return -1;
    }

    if (!aleg_next_hop.empty()) {

        string aleg_nh = ctx.replaceParameters(aleg_next_hop, "aleg_next_hop", req);

        DBG("set next hop ip to '%s'", aleg_nh.c_str());
        dlg.setNextHop(aleg_nh);
    } else {
        dlg.nat_handling = dlg_nat_handling;
        if (dlg_nat_handling && req.first_hop) {
            string remote_ip = req.remote_ip;
            ensure_ipv6_reference(remote_ip);
            string nh = remote_ip + ":" + int2str(req.remote_port) + "/" + req.trsp;
            dlg.setNextHop(nh);
            dlg.setNextHop1stReq(false);
        }
    }

    if (!aleg_route_set.empty()) {
        string aleg_op = ctx.replaceParameters(aleg_route_set, "aleg_route_set", req);
        if (parse_and_validate_route(aleg_op) == 0)
            dlg.setRouteSet(aleg_op);
    } else if (!aleg_outbound_proxy.empty()) {
        string aleg_op           = ctx.replaceParameters(aleg_outbound_proxy, "aleg_outbound_proxy", req);
        dlg.outbound_proxy       = aleg_op;
        dlg.force_outbound_proxy = aleg_force_outbound_proxy;
    }

    return 0;
}

bool SBCCallProfile::apply_b_routing(const string &ruri, AmBasicSipDialog &dlg) const
{
    dlg.setRemoteUri(ruri);

    if (!bleg_route_set.empty()) {
        dlg.setRouteSet(bleg_route_set);
    } else if (!outbound_proxy.empty()) {
        dlg.outbound_proxy       = outbound_proxy;
        dlg.force_outbound_proxy = force_outbound_proxy;
    }

    if (!route.empty()) {
        DBG("set route to: %s", route.c_str());
        dlg.setRouteSet(route);
    }

    if (!next_hop.empty()) {
        DBG("set next hop to '%s' (1st_req=%s,fixed=%s)", next_hop.c_str(), next_hop_1st_req ? "true" : "false",
            next_hop_fixed ? "true" : "false");
        dlg.setNextHop(next_hop);
        dlg.setNextHop1stReq(next_hop_1st_req);
        dlg.setNextHopFixed(next_hop_fixed);
    }

    DBG("patch_ruri_next_hop = %i", patch_ruri_next_hop);
    dlg.setPatchRURINextHop(patch_ruri_next_hop);

    if (outbound_interface_value >= 0) {
        dlg.resetOutboundIf();
        dlg.setOutboundInterfaceName(outbound_interface);
    }

    dlg.setResolvePriority(static_cast<int>(bleg_protocol_priority_id));

    if (bleg_force_cancel_routeset) {
        DBG("force to use dialog route-set for CANCEL requests");
        dlg.setForceCancelRouteSet(true);
    }

    return true;
}

/** removes headers with empty values from headers list separated by "\r\n" */
static string remove_empty_headers(const string &s, const char *field_name)
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
        } else {
            if (string::npos == col)
                DBG("%s: Malformed append header: %s", field_name, hdr.c_str());
            start = end + 1;
        }
    } while (end != string::npos && start < res.size());

    return res;
}

static void fix_append_hdr_list(const AmSipRequest &req, ParamReplacerCtx &ctx, string &append_hdr,
                                const char *field_name)
{
    append_hdr = ctx.replaceParameters(append_hdr, field_name, req);
    append_hdr = remove_empty_headers(append_hdr, field_name);
    if (append_hdr.size() > 2)
        assertEndCRLF(append_hdr);
}

void SBCCallProfile::fix_append_hdrs(ParamReplacerCtx &ctx, const AmSipRequest &req)
{
    fix_append_hdr_list(req, ctx, append_headers, "append_headers");
    fix_append_hdr_list(req, ctx, append_headers_req, "append_headers_req");
    fix_append_hdr_list(req, ctx, aleg_append_headers_req, "aleg_append_headers_req");
    fix_append_hdr_list(req, ctx, aleg_append_headers_reply, "aleg_append_headers_reply");
}

string SBCCallProfile::TranscoderSettings::print() const
{
    string res("transcoder currently enabled: ");
    if (enabled)
        res += "yes\n";
    else
        res += "no\n";

    return res;
}

bool SBCCallProfile::TranscoderSettings::evaluate(ParamReplacerCtx &ctx, const AmSipRequest &req)
{
    DBG("transcoder is %s", enabled ? "enabled" : "disabled");
    return true;
}

void SBCCallProfile::create_logger(const AmSipRequest &req)
{
    if (msg_logger_path.empty())
        return;

    ParamReplacerCtx ctx(this);
    string           log_path = ctx.replaceParameters(msg_logger_path, "msg_logger_path", req);
    if (log_path.empty())
        return;

    file_msg_logger *log = new pcap_logger();

    if (log->open(log_path.c_str()) != 0) {
        // open error
        delete log;
        return;
    }

    // opened successfully
    logger.reset(log);
}

msg_logger *SBCCallProfile::get_logger(const AmSipRequest &req)
{
    if (!logger.get() && !msg_logger_path.empty())
        create_logger(req);
    return logger.get();
}

//////////////////////////////////////////////////////////////////////////////////

bool SBCCallProfile::HoldSettings::HoldParams::setActivity(const string &s)
{
    if (s == "sendrecv")
        activity = sendrecv;
    else if (s == "sendonly")
        activity = sendonly;
    else if (s == "recvonly")
        activity = recvonly;
    else if (s == "inactive")
        activity = inactive;
    else {
        ERROR("unsupported hold stream activity: %s", s.c_str());
        return false;
    }

    return true;
}

bool SBCCallProfile::HoldSettings::evaluate(ParamReplacerCtx &ctx, const AmSipRequest &req)
{
    REPLACE_BOOL(aleg.mark_zero_connection_str, aleg.mark_zero_connection);
    REPLACE_STR(aleg.activity_str);
    REPLACE_BOOL(aleg.alter_b2b_str, aleg.alter_b2b);

    REPLACE_BOOL(bleg.mark_zero_connection_str, bleg.mark_zero_connection);
    REPLACE_STR(bleg.activity_str);
    REPLACE_BOOL(bleg.alter_b2b_str, bleg.alter_b2b);

    if (!aleg.activity_str.empty() && !aleg.setActivity(aleg.activity_str))
        return false;
    if (!bleg.activity_str.empty() && !bleg.setActivity(bleg.activity_str))
        return false;

    return true;
}
