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

/* 
SBC - feature-wishlist
- accounting (MySQL DB, cassandra DB)
- RTP transcoding mode (bridging)
- overload handling (parallel call to target thresholds)
- call distribution
- select profile on monitoring in-mem DB record
 */
#include "SBC.h"

#include "SBCCallControlAPI.h"

#include "log.h"
#include "AmUtils.h"
#include "AmAudio.h"
#include "AmPlugIn.h"
#include "AmMediaProcessor.h"
#include "AmConfigReader.h"
#include "AmSessionContainer.h"
#include "AmSipHeaders.h"
#include "sip/pcap_logger.h"
#include "sip/sip_parser.h"
#include "sip/sip_trans.h"
#include "sip/parse_nameaddr.h"

#include "HeaderFilter.h"
#include "ParamReplacer.h"
#include "SDPFilter.h"
#include "SBCCallLeg.h"

#include "AmEventQueueProcessor.h"

#include <algorithm>
#include <set>

#include "yeti.h"
#include "SipCtrlInterface.h"
#include "cdr/AuthCdr.h"

using std::map;

EXPORT_PLUGIN_CLASS_FACTORY(SBCFactory)
EXPORT_PLUGIN_CONF_FACTORY(SBCFactory)

SBCFactory* SBCFactory::instance()
{
    static auto _instance = new SBCFactory(MOD_NAME);
    return _instance;
}

// helper functions

void assertEndCRLF(string& s) {
    if (s[s.size()-2] != '\r' ||
        s[s.size()-1] != '\n')
    {
        while ((s[s.size()-1] == '\r') ||
               (s[s.size()-1] == '\n'))
            s.erase(s.size()-1);
        s += "\r\n";
    }
}

///////////////////////////////////////////////////////////////////////////////////////////

SBCCallLeg* CallLegCreator::create(fake_logger *logger,
                                   OriginationPreAuth::Reply &ip_auth_data,
                                   Auth::auth_id_type auth_result_id)
{
    return new SBCCallLeg(logger, ip_auth_data, auth_result_id, new AmSipDialog());
}

SBCCallLeg* CallLegCreator::create(SBCCallLeg* caller)
{
    return new SBCCallLeg(caller);
}

SBCFactory::SBCFactory(const string& _app_name)
  : AmSessionFactory(_app_name), 
    AmConfigFactory(_app_name),
    AmDynInvokeFactory(_app_name),
    yeti_invoke(nullptr),
    core_options_handling(false),
    callLegCreator(new CallLegCreator())
{
    pre_auth_ret[0] = 403;
    pre_auth_ret[1] = "Forbidden";
    pre_auth_ret[2] = "";
    pre_auth_ret[3] = "IP auth";
}

SBCFactory::~SBCFactory() {
    yeti.reset();
}

int SBCFactory::onLoad()
{
    if(yeti->onLoad()) {
        ERROR("yeti configuration error\n");
        yeti->stop();
        return -1;
    }
    yeti_invoke = dynamic_cast<AmDynInvoke *>(yeti.get());

    registrar_enabled = yeti->config.registrar_enabled;
    auth_feedback = yeti->config.auth_feedback;

    session_timer_fact = AmPlugIn::instance()->getFactory4Seh("session_timer");
    if(!session_timer_fact) {
        WARN("session_timer plug-in not loaded - "
             "SIP Session Timers will not be supported\n");
    }

    core_options_handling = yeti->getCoreOptionsHandling();
    DBG("OPTIONS messages handled by the core: %s\n", core_options_handling?"yes":"no");

    if (!AmPlugIn::registerApplication(MOD_NAME, this)) {
        ERROR("registering " MOD_NAME " application\n");
        return -1;
    }

    // TODO: add config param for the number of threads
    subnot_processor.addThreads(1);

    return 0;
}

int SBCFactory::configure(const std::string& config)
{
    yeti.reset(Yeti::create_instance());

    if(yeti->configure(config))
        return -1;

    return 0;
}

int SBCFactory::reconfigure(const std::string& config)
{
    WARN("runtime reconfiguration has not implemented yet");
    return 0;
}

inline void answer_100_trying(const AmSipRequest &req, fake_logger *logger)
{
    AmSipReply reply;
    reply.code = 100;
    reply.reason = "Connecting";
    reply.tt = req.tt;

    AmLcConfig::instance().addSignatureHdr(reply);

    if(SipCtrlInterface::send(reply,string(""),logger,nullptr)) {
        ERROR("Could not send early 100 Trying. call-id=%s, cseq = %i\n",
              req.callid.c_str(),req.cseq);
    }
}

void SBCFactory::send_auth_error_reply(
    const AmSipRequest& req,
    AmArg &ret,
    int auth_feedback_code)
{
    string hdr;
    if(auth_feedback && auth_feedback_code) {
        hdr = yeti_auth_feedback_header + int2str(auth_feedback_code) + CRLF;
    }
    AmSipDialog::reply_error(
        req,
        static_cast<unsigned int>(ret[0].asInt()),
        ret[1].asCStr(),
        hdr + ret[2].asCStr());
    yeti->router.log_auth(req,false,ret);
}

void SBCFactory::send_and_log_auth_challenge(
    const AmSipRequest& req,
    const string &internal_reason,
    int auth_feedback_code)
{
    string hdrs;
    if(auth_feedback && auth_feedback_code) {
        hdrs = yeti_auth_feedback_header + int2str(auth_feedback_code) + CRLF;
    }
    yeti->router.send_and_log_auth_challenge(req,internal_reason, hdrs);
}

AmSession* SBCFactory::onInvite(
    const AmSipRequest& req,
    const string&,
    const map<string,string>&)
{
    OriginationPreAuth::Reply ip_auth_data;

    fake_logger *early_trying_logger = new fake_logger();
    inc_ref(early_trying_logger);

    if(yeti->config.early_100_trying)
        answer_100_trying(req,early_trying_logger);

    PROF_START(pre_auth);
    auto pre_auth_result = yeti->orig_pre_auth.onInvite(req, ip_auth_data);
    PROF_END(pre_auth);
    PROF_PRINT("orig pre auth", pre_auth);

    DBG("pre auth result: %d", pre_auth_result);

    if(!pre_auth_result) {
        DBG("request rejected by origination pre auth");
        send_auth_error_reply(req, pre_auth_ret, Auth::NO_IP_AUTH);
        dec_ref(early_trying_logger);
        return nullptr;
    }

    AmArg ret;
    auto auth_result_id = yeti->router.check_request_auth(req,ret);
    if(auth_result_id > 0) {
        DBG("successfully authorized with id %d",auth_result_id);
        yeti->router.log_auth(req,true,ret,auth_result_id);
    } else if(auth_result_id < 0) {
        DBG("auth error. reply with 401");
        switch(-auth_result_id) {
        case Auth::UAC_AUTH_ERROR:
            send_auth_error_reply(req, ret, -auth_result_id);
            break;
        default:
            send_and_log_auth_challenge(req,ret.asCStr(), -auth_result_id);
            break;
        }

        dec_ref(early_trying_logger);
        return nullptr;

    } else if(ip_auth_data.require_incoming_auth) { //Auth::NO_AUTH
        DBG("SIP auth required. reply with 401");
        static string no_auth_internal_reason("no Authorization header");
        send_and_log_auth_challenge(req,no_auth_internal_reason);

        dec_ref(early_trying_logger);
        return nullptr;
    }

    SBCCallLeg* leg = callLegCreator->create(
        early_trying_logger,
        ip_auth_data,
        auth_result_id);

    if(!leg) {
        DBG("failed to create B2B leg");
        dec_ref(early_trying_logger);
        return nullptr;
    }

    /* not functional here after DB routing was moved to the SBCCallLeg

    SBCCallProfile& call_profile = leg->getCallProfile();

    if (call_profile.auth_aleg_enabled) {
        // adding auth handler
        AmSessionEventHandlerFactory* uac_auth_f =
            AmPlugIn::instance()->getFactory4Seh("uac_auth");
        if (nullptr == uac_auth_f)  {
            INFO("uac_auth module not loaded. uac auth for caller session NOT enabled.\n");
        } else {
            AmSessionEventHandler* h = uac_auth_f->getHandler(leg);
            // we cannot use the generic AmSessionEventHandler hooks,
            // because the hooks don't work in AmB2BSession
            leg->setAuthHandler(h);
            DBG("uac auth enabled for caller session.\n");
        }
    }*/

    return leg;
}

void SBCFactory::onOoDRequest(const AmSipRequest& req)
{
    DBG("processing message %s %s\n", req.method.c_str(), req.r_uri.c_str());

    if (core_options_handling && req.method == SIP_METH_OPTIONS) {
        DBG("processing OPTIONS in core\n");
        AmSessionFactory::onOoDRequest(req);
        return;
    }

    if(registrar_enabled && req.method == SIP_METH_REGISTER) {
        AmArg ret;
        Auth::auth_id_type auth_id = yeti->router.check_request_auth(req,ret);

        if(auth_id == Auth::NO_AUTH) {
            send_and_log_auth_challenge(req,"no Authorization header");
            return;
        }

        if(auth_id < 0) {
            switch(-auth_id) {
            case Auth::UAC_AUTH_ERROR:
                DBG("REGISTER auth error. reply with 401");
                send_auth_error_reply(req, ret, -auth_id);
                break;
            default:
                DBG("REGISTER no auth. reply 401 with challenge");
                send_and_log_auth_challenge(req,ret.asCStr(), -auth_id);
                break;
            }
            return;
        }

        DBG("REGISTER successfully authorized with id %d",auth_id);
        yeti->router.log_auth(req,true,ret,auth_id);
        processAuthorizedRegister(req, auth_id);
        return;
    }

    AmSipDialog::reply_error(req, 405, "Method Not Allowed");
    return;
}

void SBCFactory::processAuthorizedRegister(const AmSipRequest& req, Auth::auth_id_type auth_id)
{
    static string user_agent_header_name("User-Agent");
    static string path_header_name("Path");
    static string expires_param_header_name("expires");

    list<cstring> contact_list;
    vector<AmUriParser> contacts;

    bool asterisk_contact = false;

    if(parse_nameaddr_list(contact_list,
        req.contact.c_str(), static_cast<int>(req.contact.length())) < 0)
    {
        DBG("could not parse contact list");
        AmSipDialog::reply_error(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        return;
    }

    size_t end;
    for(const auto &c: contact_list)
    {
        if(1==c.len && *c.s=='*') {
            asterisk_contact = true;
            continue;
        }
        AmUriParser contact_uri;
        if (!contact_uri.parse_contact(c2stlstr(c), 0, end)) {
            DBG("error parsing contact: '%.*s'\n",c.len, c.s);
            AmSipDialog::reply_error(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
            return;
        } else {
            DBG("successfully parsed contact %s@%s\n",
            contact_uri.uri_user.c_str(),
            contact_uri.uri_host.c_str());
            contacts.push_back(contact_uri);
        }
    }

    if(asterisk_contact && !contacts.empty()) {
        DBG("additional Contact headers with Contact: *");
        AmSipDialog::reply_error(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        return;
    }

    if(contacts.empty() && !asterisk_contact) {
        //request bindings list
        if(!yeti->registrar_redis.fetch_all(req, auth_id))
            AmSipDialog::reply_error(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    } else {
        //renew/replace/update binding
        string contact;
        bool expires_found = false;
        string expires;

        if(!asterisk_contact) {
            AmUriParser &first_contact = contacts.front();
            contact = first_contact.uri_str();
            for(auto p: first_contact.params) {
                //DBG("param: %s -> %s",p.first.c_str(),p.second.c_str());
                if(p.first==expires_param_header_name) {
                    //DBG("found expires param");
                    expires_found = true;
                    expires = p.second;
                    break;
                }
            }
        }

        if(!expires_found) {
            //try to find Expires header as failover
            size_t start_pos = 0;
            while (start_pos<req.hdrs.length()) {
                size_t name_end, val_begin, val_end, hdr_end;
                int res;
                if ((res = skip_header(req.hdrs, start_pos, name_end, val_begin,
                           val_end, hdr_end)) != 0)
                {
                    break;
                }
                if(0==strncasecmp(req.hdrs.c_str() + start_pos,
                                  expires_param_header_name.c_str(), name_end-start_pos))
                {
                    /*DBG("matched Expires header: %.*s",
                        static_cast<int>(hdr_end-start_pos), req.hdrs.c_str()+start_pos);*/
                    expires = req.hdrs.substr(val_begin, val_end-val_begin);
                    expires_found = true;
                    break;
                }
                start_pos = hdr_end;
            }
        }

        if(!expires_found) {
            DBG("no either Contact param expire or header Expire");
            AmSipDialog::reply_error(req, 400, "Invalid Request");
            return;
        }
        DBG("expires: %s",expires.c_str());

        int expires_int;
        if(!str2int(expires, expires_int)) {
            DBG("failed to cast expires value '%s'",expires.c_str());
            AmSipDialog::reply_error(req, 400, "Invalid Request");
            return;
        }

        if(asterisk_contact) {
            if(expires_int!=0) {
                DBG("non zero expires with Contact: *");
                AmSipDialog::reply_error(req, 400, "Invalid Request");
                return;
            }
            if(!yeti->registrar_redis.unbind_all(req, auth_id))
                AmSipDialog::reply_error(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
            return;
        }

        //check min/max expires
        if(yeti->config.registrar_expires_min &&
           expires_int &&
           expires_int < 3600 &&
           expires_int < yeti->config.registrar_expires_min)
        {
            DBG("expires %d is lower than allowed min: %d. reply with 423",
                expires_int, yeti->config.registrar_expires_min);
            static string min_expires_header =
                SIP_HDR_COL("Min-Expires") + int2str(yeti->config.registrar_expires_min) + CRLF;
            AmSipDialog::reply_error(req, 423, "Interval Too Brief", min_expires_header);
            return;
        }
        if(yeti->config.registrar_expires_max &&
           expires_int > yeti->config.registrar_expires_max)
        {
            DBG("expires %d is greater than allowed max: %d. set it to max",
                expires_int, yeti->config.registrar_expires_max);
            expires_int = yeti->config.registrar_expires_max;
        }

        //find Path/User-Agent headers
        string path;
        string user_agent;
        size_t start_pos = 0;
        while (start_pos<req.hdrs.length()) {
            size_t name_end, val_begin, val_end, hdr_end;
            int res;
            if ((res = skip_header(req.hdrs, start_pos, name_end, val_begin,
                val_end, hdr_end)) != 0)
            {
                break;
            }
            if(0==strncasecmp(req.hdrs.c_str() + start_pos,
                              path_header_name.c_str(), name_end-start_pos))
            {
                if(!path.empty()) path += ",";
                path += req.hdrs.substr(val_begin, val_end-val_begin);
            } else if(0==strncasecmp(req.hdrs.c_str() + start_pos,
                                  user_agent_header_name.c_str(), name_end-start_pos))
            {
                user_agent = req.hdrs.substr(val_begin, val_end-val_begin);
            }
            start_pos = hdr_end;
        }

        if(!yeti->registrar_redis.bind(
            req, auth_id,
            contact, expires_int,
            user_agent, path))
        {
            AmSipDialog::reply_error(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
    }
}

void SBCFactory::invoke(const string& method, const AmArg& args, 
				AmArg& ret)
{
    if (method == "postControlCmd"){
        args.assertArrayFmt("ss"); // at least call-ltag, cmd
        postControlCmd(args,ret);
    } else if(method == "printCallStats") {
        B2BMediaStatistics::instance()->getReport(args, ret);
    } else if(method == "_list"){
        ret.push(AmArg("postControlCmd"));
        ret.push(AmArg("printCallStats"));
    } else {
        throw AmDynInvoke::NotImplemented(method);
    }
}

void SBCFactory::postControlCmd(const AmArg& args, AmArg& ret) {
    SBCControlEvent* evt;

    if (args.size()<3) {
        evt = new SBCControlEvent(args[1].asCStr());
    } else {
        evt = new SBCControlEvent(args[1].asCStr(), args[2]);
    }

    if (!AmSessionContainer::instance()->postEvent(args[0].asCStr(), evt)) {
        ret.push(404);
        ret.push("Not found");
    } else {
        ret.push(202);
        ret.push("Accepted");
    }
}

