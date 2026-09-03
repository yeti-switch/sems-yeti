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

#include "log.h"
#include "AmUtils.h"
#include "AmLcConfig.h"

#include "sip/pcap_logger.h"
#include "sip/parse_route.h"

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
