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

using std::map;

EXPORT_PLUGIN_CLASS_FACTORY(SBCFactory)
EXPORT_PLUGIN_CONF_FACTORY(SBCFactory)

static AmArg jwt_auth_ret{
    AmArg(403),
    AmArg("Forbidden"),
    AmArg(""),
    AmArg("JWT Auth")
};

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

SBCCallLeg* CallLegCreator::create(SBCCallLeg* caller, AmSipDialog* dlg)
{
    return new SBCCallLeg(caller, dlg);
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
        ERROR("yeti configuration error");
        yeti->stop();
        return -1;
    }
    yeti_invoke = dynamic_cast<AmDynInvoke *>(yeti.get());

    auth_feedback = yeti->config.auth_feedback;

    session_timer_fact = AmPlugIn::instance()->getFactory4Seh("session_timer");
    if(!session_timer_fact) {
        WARN("session_timer plug-in not loaded - "
             "SIP Session Timers will not be supported\n");
    }

    core_options_handling = yeti->getCoreOptionsHandling();
    DBG3("OPTIONS messages handled by the core: %s", core_options_handling?"yes":"no");

    if (!AmPlugIn::registerApplication(MOD_NAME, this)) {
        ERROR("registering " MOD_NAME " application");
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
        ERROR("Could not send early 100 Trying. call-id=%s, cseq = %i",
              req.callid.c_str(),req.cseq);
    }
}

void SBCFactory::send_auth_error_reply(
    const AmSipRequest& req,
    AmArg &ret,
    int auth_feedback_code)
{
    string hdr;
    if(auth_feedback) {
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
    bool post_auth_log,
    int auth_feedback_code)
{
    string hdrs;
    if(auth_feedback) {
        hdrs = yeti_auth_feedback_header + int2str(auth_feedback_code) + CRLF;
    }
    yeti->router.send_and_log_auth_challenge(req,internal_reason, hdrs, post_auth_log);
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
        DBG("INVITE %s from %s:%hu not matched by origination pre auth",
            req.r_uri.data(), req.remote_ip.data(), req.remote_port);
        if(yeti->config.ip_auth_reject_if_no_matched) {
            send_auth_error_reply(req, pre_auth_ret, Auth::NO_IP_AUTH);
            dec_ref(early_trying_logger);
            return nullptr;
        } else {
            //yeti->router.log_auth(req,false,pre_auth_ret);
            INFO("INVITE not matched by ip auth. "
                 "ruri:%s,remote_endpoint:%s:%hu,orig_ip:%s,x_yeti_auth:'%s'",
                 req.r_uri.data(), req.remote_ip.data(), req.remote_port,
                 ip_auth_data.orig_ip.data(),
                 ip_auth_data.x_yeti_auth.data());
        }
    }

    AmArg ret;
    auto auth_result_id = yeti->router.check_request_auth(req,ret);
    if(auth_result_id > 0) {
        DBG("successfully authorized with id %d",auth_result_id);
        if(!yeti->router.is_skip_logging_invite_success())
            yeti->router.log_auth(req,true,ret,auth_result_id);
    } else if(auth_result_id < 0) {
        auto auth_result_id_negated = -auth_result_id;
        if(auth_result_id_negated > Auth::NO_IP_AUTH) {
            if(auth_result_id_negated >= Auth::UAC_AUTH_ERROR) {
                DBG("auth error %d. reply with 401", auth_result_id);
                send_auth_error_reply(req, ret, auth_result_id_negated);
            } else {
                DBG("JWT auth error %d. reply with 403", auth_result_id);
                send_auth_error_reply(req, jwt_auth_ret, auth_result_id_negated);
            }
        } else {
            DBG("no auth. reply 401 with challenge");
            send_and_log_auth_challenge(req, ret.asCStr(), true, auth_result_id_negated);
        }

        dec_ref(early_trying_logger);
        return nullptr;
    } else if(ip_auth_data.require_incoming_auth) { //Auth::NO_AUTH
        DBG("SIP auth required. reply with 401");
        static string no_auth_internal_reason("no Authorization header");
        send_and_log_auth_challenge(
            req,no_auth_internal_reason,
            !yeti->router.is_skip_logging_invite_challenge());
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

    leg->dlg->setAllowedMethods(yeti->config.allowed_methods);

    /* not functional here after DB routing was moved to the SBCCallLeg

    SBCCallProfile& call_profile = leg->getCallProfile();

    if (call_profile.auth_aleg_enabled) {
        // adding auth handler
        AmSessionEventHandlerFactory* uac_auth_f =
            AmPlugIn::instance()->getFactory4Seh("uac_auth");
        if (nullptr == uac_auth_f)  {
            INFO("uac_auth module not loaded. uac auth for caller session NOT enabled.");
        } else {
            AmSessionEventHandler* h = uac_auth_f->getHandler(leg);
            // we cannot use the generic AmSessionEventHandler hooks,
            // because the hooks don't work in AmB2BSession
            leg->setAuthHandler(h);
            DBG("uac auth enabled for caller session.");
        }
    }*/

    return leg;
}

void SBCFactory::onOoDRequest(const AmSipRequest& req)
{
    DBG("processing message %s %s", req.method.c_str(), req.r_uri.c_str());

    if (core_options_handling && req.method == SIP_METH_OPTIONS) {
        DBG("processing OPTIONS in core");
        AmSessionFactory::onOoDRequest(req);
        return;
    }

    if(req.method == SIP_METH_REGISTER) {
        if(!yeti->isRegistrarAvailable()) {
            AmSipDialog::reply_error(req, 405, "Method Not Allowed");
            return;
        }

        AmArg ret;
        Auth::auth_id_type auth_id = yeti->router.check_request_auth(req,ret);

        if(auth_id == Auth::NO_AUTH) {
            send_and_log_auth_challenge(req,"no Authorization header", true);
            return;
        }

        if(auth_id < 0) {
            auto auth_result_id_negated = -auth_id;
            if(auth_result_id_negated > Auth::NO_IP_AUTH) {
                if(auth_result_id_negated >= Auth::UAC_AUTH_ERROR) {
                    DBG("REGISTER auth error. reply with 401");
                    send_auth_error_reply(req, ret, auth_result_id_negated);
                } else {
                    DBG("REGISTER JWT auth error. reply with 403");
                    send_auth_error_reply(req, jwt_auth_ret, auth_result_id_negated);
                }
            } else {
                DBG("REGISTER no auth. reply 401 with challenge");
                send_and_log_auth_challenge(req, ret.asCStr(), true, auth_result_id_negated);
            }
            return;
        }

        DBG("REGISTER successfully authorized with id %d",auth_id);
        yeti->router.log_auth(req,true,ret,auth_id);

        if(false ==AmSessionContainer::instance()->postEvent(
            SIP_REGISTRAR_QUEUE,
            new SipRegistrarRegisterRequestEvent(req, string(), std::to_string(auth_id))))
        {
            ERROR("failed to post 'register' event to registrar");
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }

        return;
    }

    AmSipDialog::reply_error(req, 405, "Method Not Allowed");
    return;
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

