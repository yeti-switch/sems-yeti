#include "SBCCallLeg.h"

#include "SBCCallControlAPI.h"

#include "log.h"
#include "AmUtils.h"
#include "AmAudio.h"
#include "AmPlugIn.h"
#include "AmMediaProcessor.h"
#include "AmConfigReader.h"
#include "AmSessionContainer.h"
#include "AmSipHeaders.h"
#include "Am100rel.h"
#include "jsonArg.h"
#include "format_helper.h"

#include "sip/pcap_logger.h"
#include "sip/sip_parser.h"
#include "sip/sip_trans.h"
#include "sip/parse_nameaddr.h"
#include "sip/parse_common.h"

#include "HeaderFilter.h"
#include "ParamReplacer.h"
#include "SDPFilter.h"

#include <algorithm>

#include "AmAudioFileRecorder.h"
#include "AmAudioFileRecorderStereo.h"
#include "radius_hooks.h"
#include "Sensors.h"

#include "sdp_filter.h"
#include "dtmf_sip_info.h"

#include "ampi/RadiusClientAPI.h"
#include "ampi/HttpClientAPI.h"
#include "ampi/SipRegistrarApi.h"

using namespace std;

#define TRACE DBG

#define FILE_RECORDER_COMPRESSED_EXT ".mp3"
#define FILE_RECORDER_RAW_EXT        ".wav"

#define MEMORY_LOGGER_MAX_ENTRIES 100

inline void replace(string &s, const string &from, const string &to)
{
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != string::npos) {
        s.replace(pos, from.length(), to);
        pos += s.length();
    }
}

static const char *callStatus2str(const CallLeg::CallStatus state)
{
    static const char *disconnected  = "Disconnected";
    static const char *disconnecting = "Disconnecting";
    static const char *noreply       = "NoReply";
    static const char *ringing       = "Ringing";
    static const char *connected     = "Connected";
    static const char *unknown       = "???";

    switch (state) {
    case CallLeg::Disconnected:  return disconnected;
    case CallLeg::Disconnecting: return disconnecting;
    case CallLeg::NoReply:       return noreply;
    case CallLeg::Ringing:       return ringing;
    case CallLeg::Connected:     return connected;
    }

    return unknown;
}

#define getCtx_void                                                                                                    \
    if (!call_ctx)                                                                                                     \
        return;

#define getCtx_chained                                                                                                 \
    if (!call_ctx)                                                                                                     \
        break;

#define with_cdr_for_read                                                                                              \
    Cdr *cdr = call_ctx->cdr.get();                                                                                    \
    if (cdr)

in_memory_msg_logger::log_entry::log_entry(const char *buf_arg, int len_arg, sockaddr_storage *src_ip_arg,
                                           sockaddr_storage *dst_ip_arg, cstring method_arg, int reply_code_arg)
    : len(len_arg)
{
    buf = new char[len_arg];
    memcpy(buf, buf_arg, len_arg);

    memcpy(&local_ip, src_ip_arg, SA_len(src_ip_arg));
    memcpy(&remote_ip, dst_ip_arg, SA_len(dst_ip_arg));

    if (method_arg.s && method_arg.len) {
        method.s   = strndup(method_arg.s, method_arg.len);
        method.len = method_arg.len;
    }
}

in_memory_msg_logger::log_entry::~log_entry()
{
    delete[] buf;
    if (method.s && method.len) {
        free((void *)method.s);
    }
}

int in_memory_msg_logger::log(const char *buf, int len, sockaddr_storage *src_ip, sockaddr_storage *dst_ip,
                              cstring method, int reply_code)
{
    AmLock l(mutex);
    if (packets.size() >= MEMORY_LOGGER_MAX_ENTRIES)
        return 0;
    // TODO: save entry creation time
    packets.emplace_back(buf, len, src_ip, dst_ip, method, reply_code);
    return 0;
}

void in_memory_msg_logger::feed_to_logger(msg_logger *logger)
{
    AmLock l(mutex);
    for (auto &p : packets) {
        logger->log(p.buf, p.len, &p.local_ip, &p.remote_ip, p.method, p.reply_code);
    }
}

///////////////////////////////////////////////////////////////////////////////////////////

// A leg constructor (from SBCDialog)
SBCCallLeg::SBCCallLeg(fake_logger *early_logger, OriginationPreAuth::Reply &ip_auth_data,
                       Auth::auth_id_type auth_result_id, AmSipDialog *p_dlg, AmSipSubscription *p_subs)
    : CallLeg(p_dlg, p_subs)
    , m_state(BB_Init)
    , yeti(Yeti::instance())
    , sdp_session_version(0)
    , has_sdp_session_version(false)
    , sdp_session_offer_last_cseq(0)
    , sdp_session_answer_last_cseq(0)
    , thread_id(0)
    , call_ctx(nullptr)
    , early_trying_logger(early_logger)
    , ip_auth_data(ip_auth_data)
    , auth_result_id(auth_result_id)
    , auth(nullptr)
    , placeholders_hash(call_profile.placeholders_hash)
    , logger(nullptr)
    , sensor(nullptr)
    , memory_logger_enabled(false)
    , waiting_for_location(false)
    , router(yeti.router)
    , cdr_list(yeti.cdr_list)
    , rctl(yeti.rctl)
{
    DBG3("SBCCallLeg[%p](%p,%p)", to_void(this), to_void(p_dlg), to_void(p_subs));

    setLocalTag();
}

// B leg constructor (from SBCCalleeSession)
SBCCallLeg::SBCCallLeg(SBCCallLeg *caller, AmSipDialog *p_dlg, AmSipSubscription *p_subs)
    : CallLeg(caller, p_dlg, p_subs)
    , yeti(Yeti::instance())
    , sdp_session_version(0)
    , has_sdp_session_version(false)
    , sdp_session_offer_last_cseq(0)
    , sdp_session_answer_last_cseq(0)
    , global_tag(caller->getGlobalTag())
    , call_ctx(caller->getCallCtx())
    , early_trying_logger(nullptr)
    , auth(nullptr)
    , call_profile(caller->getCallProfile())
    , placeholders_hash(caller->getPlaceholders())
    , logger(nullptr)
    , sensor(nullptr)
    , memory_logger_enabled(caller->getMemoryLoggerEnabled())
    , router(yeti.router)
    , cdr_list(yeti.cdr_list)
    , rctl(yeti.rctl)
{
    DBG3("SBCCallLeg[%p](caller %p,%p,%p)", to_void(this), to_void(caller), to_void(p_dlg), to_void(p_subs));

    if (call_profile.bleg_rel100_mode_id != -1) {
        dlg->setRel100State(static_cast<Am100rel::State>(call_profile.bleg_rel100_mode_id));
    } else {
        dlg->setRel100State(Am100rel::REL100_IGNORED);
    }

    // copy RTP rate limit from caller leg
    if (caller->rtp_relay_rate_limit.get()) {
        rtp_relay_rate_limit.reset(new RateLimit(*caller->rtp_relay_rate_limit.get()));
    }

    call_ctx->references++;
    init();

    setLogger(caller->getLogger());
}

void SBCCallLeg::init()
{
    Cdr &cdr = *call_ctx->cdr.get();

    if (a_leg) {
        call_profile.set_logger_path(
            format("{}/{}_{}.pcap", yeti.config.msg_logger_dir, getLocalTag(), AmConfig.node_id));

        if (global_tag.empty()) {
            ERROR("%s empty global_tag. disable recording", getLocalTag().data());
            call_profile.record_audio = false;
        }

        cdr.update_sbc(call_profile);
        setSensor(Sensors::instance()->getSensor(call_profile.aleg_sensor_id));
        cdr.update_init_aleg(getLocalTag(), global_tag, getCallID());
    } else {
        if (!call_profile.callid.empty()) {
            string id = AmSession::getNewId();
            replace(call_profile.callid, "%uuid", id);
        }
        setSensor(Sensors::instance()->getSensor(call_profile.bleg_sensor_id));
        cdr.update_init_bleg(call_profile.callid.empty() ? getCallID() : call_profile.callid, getLocalTag());
    }

    if (call_profile.record_audio) {
        if (yeti.config.audio_recorder_compress) {
            call_profile.audio_record_path = format("{}/{}_{}_leg{}{}", yeti.config.audio_recorder_dir, global_tag,
                                                    AmConfig.node_id, a_leg ? "a" : "b", FILE_RECORDER_COMPRESSED_EXT);

            AmAudioFileRecorderProcessor::instance()->addRecorder(getLocalTag(), call_profile.audio_record_path);

            setRecordAudio(true);
        } else {
            // start recorder if leg is A
            if (a_leg) {
                call_profile.audio_record_path = global_tag + FILE_RECORDER_COMPRESSED_EXT;
                AmAudioFileRecorderProcessor::instance()->putEvent(new AudioRecorderCtlEvent(
                    global_tag, AudioRecorderEvent::addStereoRecorder, AmAudioFileRecorder::RecorderStereoRaw,
                    call_profile.audio_record_path,
                    yeti.config.audio_recorder_http_destination.empty() ? string() : getLocalTag()));

                addStereoRecorder(AudioRecorderChannelLeft, global_tag);
            } else {
                addStereoRecorder(AudioRecorderChannelRight, global_tag);
            }
        }
    }
}

void SBCCallLeg::terminateLegOnReplyException(const AmSipReply &reply, const InternalException &e)
{
    getCtx_void

        if (!getOtherId().empty())
    { // ignore not connected B legs
        with_cdr_for_read
        {
            cdr->update_internal_reason(DisconnectByTS, e.internal_reason, e.internal_code, e.icode);
            cdr->update_with_bleg_sip_reply(reply);
        }
    }

    relayError(reply.cseq_method, reply.cseq, true, static_cast<int>(e.response_code), e.response_reason.c_str());

    if (getCallStatus() == Connected) {
        DBG("if(getCallStatus()==Connected) {");
        stopCall(CallLeg::StatusChangeCause::InternalError);
    } else {
        DBG("if(getCallStatus()==Connected) { else");
        terminateLeg();
    }
}

void SBCCallLeg::processAorResolving()
{
    DBG("%s(%p,leg%s)", FUNC_NAME, static_cast<void *>(this), a_leg ? "A" : "B");

    std::unique_ptr<SipRegistrarResolveRequestEvent> event_ptr{ new SipRegistrarResolveRequestEvent{ getLocalTag() } };
    auto                                            &event = *event_ptr.get();

    // check for registered_aor_id in profiles
    for (const auto &p : call_ctx->profiles) {
        if (0 == p.disconnect_code_id && 0 != p.registered_aor_id) {
            event.aor_ids.emplace(std::to_string(p.registered_aor_id));
        }
    }

    if (event.aor_ids.empty()) {
        // no aor resolving requested. continue as usual
        processResourcesAndSdp();
        return;
    }

    if (false == AmSessionContainer::instance()->postEvent(SIP_REGISTRAR_QUEUE, event_ptr.release())) {
        ERROR("failed to post 'resolve request' event to registrar");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }
}

void SBCCallLeg::processResourcesAndSdp()
{
    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");

    SqlCallProfile *profile = nullptr;

    ResourceList::iterator ri;
    ResourceConfig         resource_config;
    Cdr                   *cdr = call_ctx->cdr.get();

    PROF_START(func);

    try {

        ResourceCtlResponse rctl_ret;

        PROF_START(rchk);

        profile = call_ctx->getCurrentProfile();

        if (!profile) {
            ERROR("%s no profile. ci:%s", getLocalTag().data(), uac_req.callid.data());
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }

        /* lega_res_chk_step:
         *   true - checking legA resources
         *   false - checking legB or combined resources
         */
        bool lega_res_chk_step = profile->legab_res_mode_enabled;
        auto now               = uac_req.recv_timestamp.tv_sec;
        int  attempt           = 0;
        do {
            DBG("check throttling for profile. attempt %d", attempt);

            if (profile->legb_gw_cache_id &&
                // check throttling before first resource checking only
                (!profile->legab_res_mode_enabled || lega_res_chk_step))
            {
                DBG("check throttling for profile. attempt %d", attempt);
                if (yeti.gateways_cache.should_skip(profile->legb_gw_cache_id, now)) {
                    DBG("skipped by throttling for legb_gw_cache_id:%d", profile->legb_gw_cache_id);

                    // get next profile
                    profile = call_ctx->getNextProfile(false, true);
                    /* save throttling disconnect reason if refuse_profile
                     * follows throttled profile */
                    if (nullptr == profile) {
                        unsigned int internal_code, response_code;
                        string       internal_reason, response_reason;

                        CodesTranslator::instance()->translate_db_code(DC_FAILURE_RATE_THROTTLING, internal_code,
                                                                       internal_reason, response_code, response_reason,
                                                                       call_ctx->getCurrentProfile()->aleg_override_id);

                        cdr->update_internal_reason(DisconnectByTS, internal_reason, internal_code,
                                                    DC_FAILURE_RATE_THROTTLING);

                        throw AmSession::Exception(response_code, response_reason);
                    }

                    attempt++;
                    continue;
                }
            }

            DBG("check resources for profile. attempt %d", attempt);

            ResourceList &rl      = profile->getResourceList(lega_res_chk_step);
            string       &handler = call_ctx->getResourceHandler(*profile, lega_res_chk_step);

            if (rl.empty()) {
                rctl_ret = RES_CTL_OK;
            } else {
                rctl_ret = rctl.get(rl, handler, getLocalTag(), resource_config, ri);
            }

            if (rctl_ret == RES_CTL_OK) {
                DBG("check resources succ");
                if (!lega_res_chk_step)
                    break;
                /* lega_res checked, try legb_res */
                lega_res_chk_step = false;
                continue;
            } else if (rctl_ret == RES_CTL_REJECT || rctl_ret == RES_CTL_ERROR) {
                DBG("check resources failed with code %d. internal code: %d", rctl_ret,
                    resource_config.internal_code_id);
                if (rctl_ret == RES_CTL_REJECT) {
                    cdr->update_failed_resource(*ri);
                }
                break;
            } else if (rctl_ret == RES_CTL_NEXT) {
                DBG("check resources failed with code %d. internal code: %d", rctl_ret,
                    resource_config.internal_code_id);
                profile = call_ctx->getNextProfile(true);

                if (nullptr == profile) {
                    cdr->update_failed_resource(*ri);
                    DBG("there are no more profiles");
                    throw AmSession::Exception(503, "no more profiles");
                }

                DBG("choosed next profile");

                /* show resource disconnect reason instead of
                 * refuse_profile if refuse_profile follows failed resource with
                 * failover to next */
                if (profile->disconnect_code_id != 0) {
                    unsigned int internal_code, response_code;
                    string       internal_reason, response_reason;

                    CodesTranslator::instance()->translate_db_code(
                        static_cast<unsigned int>(resource_config.internal_code_id), internal_code, internal_reason,
                        response_code, response_reason, call_ctx->getOverrideId(a_leg));

                    cdr->update_failed_resource(*ri);

                    rctl.replace(internal_reason, *ri, resource_config);
                    rctl.replace(response_reason, *ri, resource_config);

                    cdr->update_internal_reason(DisconnectByTS, internal_reason, internal_code,
                                                resource_config.internal_code_id);

                    throw AmSession::Exception(static_cast<int>(response_code), response_reason);
                }

                ParamReplacerCtx rctx(profile);
                if (router.check_and_refuse(profile, cdr, aleg_modified_req, rctx)) {
                    throw AmSession::Exception(cdr->disconnect_rewrited_code, cdr->disconnect_rewrited_reason);
                }
            }
            attempt++;
        } while (1);

        if (rctl_ret != RES_CTL_OK) {
            unsigned int internal_code, response_code;
            string       internal_reason, response_reason;

            CodesTranslator::instance()->translate_db_code(static_cast<unsigned int>(resource_config.internal_code_id),
                                                           internal_code, internal_reason, response_code,
                                                           response_reason, call_ctx->getOverrideId(a_leg));

            rctl.replace(internal_reason, *ri, resource_config);
            rctl.replace(response_reason, *ri, resource_config);

            cdr->update_internal_reason(DisconnectByTS, internal_reason, internal_code,
                                        resource_config.internal_code_id);

            throw AmSession::Exception(static_cast<int>(response_code), response_reason);
        }

        PROF_END(rchk);
        PROF_PRINT("check and grab resources", rchk);

        profile = call_ctx->getCurrentProfile();
        cdr->update_with_resource_list(*profile);
        updateCallProfile(*profile);

        PROF_START(sdp_processing);

        // filterSDP
        int res = processSdpOffer(this, call_profile, aleg_modified_req.body, aleg_modified_req.method,
                                  call_ctx->aleg_negotiated_media, call_profile.static_codecs_aleg_id);
        if (res != 0) {
            DBG("processSdpOffer: %d", res);
            throw InternalException(res, call_ctx->getOverrideId());
        }

        // next we should filter request for legB
        res = filterSdpOffer(this, modified_req, call_profile, modified_req.body, modified_req.method,
                             call_profile.static_codecs_bleg_id, nullptr, &call_ctx->bleg_initial_offer);
        if (res != 0) {
            DBG("filterSdpOffer: %d", res);
            throw AmSession::Exception(488, SIP_REPLY_NOT_ACCEPTABLE_HERE);
        }
        PROF_END(sdp_processing);
        PROF_PRINT("initial sdp processing", sdp_processing);

        call_ctx->bleg_negotiated_media = call_ctx->bleg_initial_offer.media;

        if (profile->time_limit) {
            DBG("save timer %d with timeout %d", YETI_CALL_DURATION_TIMER, profile->time_limit);
            saveCallTimer(YETI_CALL_DURATION_TIMER, profile->time_limit);
        }

        if (!call_profile.append_headers.empty()) {
            replace(call_profile.append_headers, "%global_tag", getGlobalTag());
        }

        onRoutingReady();

    } catch (InternalException &e) {
        DBG("catched InternalException(%d)", e.icode);
        rctl.put(call_profile.resource_handler);
        rctl.put(call_ctx->lega_resource_handler);
        cdr->update_internal_reason(DisconnectByTS, e.internal_reason, e.internal_code, e.icode);
        throw AmSession::Exception(static_cast<int>(e.response_code), e.response_reason);
    } catch (AmSession::Exception &e) {
        DBG("catched AmSession::Exception(%d,%s)", e.code, e.reason.c_str());
        rctl.put(call_profile.resource_handler);
        rctl.put(call_ctx->lega_resource_handler);
        cdr->update_internal_reason(DisconnectByTS, e.reason, static_cast<unsigned int>(e.code), 0);
        throw e;
    }

    PROF_END(func);
    PROF_PRINT("yeti processResourcesAndSdp()", func);
    return;
}

bool SBCCallLeg::chooseNextProfile()
{
    DBG("%s", getLocalTag().data());

    ResourceConfig         resource_config;
    SqlCallProfile        *profile = nullptr;
    ResourceCtlResponse    rctl_ret;
    ResourceList::iterator ri;
    bool                   has_profile = false;

    {
        profile = call_ctx->getNextProfile(false);
        if (nullptr == profile) {
            // pretend that nothing happen. we were never called
            DBG("no more profiles or refuse profile on serial fork. ignore it");
            return false;
        }
    }

    auto cdr = call_ctx->cdr.get();
    auto now = uac_req.recv_timestamp.tv_sec;

    do {
        DBG("choosed next profile. check it for refuse");

        {
            ParamReplacerCtx rctx(profile);
            if (router.check_and_refuse(profile, cdr, *call_ctx->initial_invite, rctx)) {
                DBG("profile contains refuse code");
                break;
            }
        }

        DBG("no refuse field. check it for throttling");
        if (profile->legb_gw_cache_id && yeti.gateways_cache.should_skip(profile->legb_gw_cache_id, now)) {
            DBG("skipped by throttling for legb_gw_cache_id:%d", profile->legb_gw_cache_id);

            profile = call_ctx->getNextProfile(false, true);
            if (nullptr == profile) {
                unsigned int internal_code, response_code;
                string       internal_reason, response_reason;

                CodesTranslator::instance()->translate_db_code(DC_FAILURE_RATE_THROTTLING, internal_code,
                                                               internal_reason, response_code, response_reason,
                                                               call_ctx->getOverrideId(a_leg));

                cdr->update_internal_reason(DisconnectByTS, internal_reason, internal_code, DC_FAILURE_RATE_THROTTLING);

                return false;
            }

            // has next non-disconnecting profile
            continue;
        }

        DBG("no throttling. check it for resources");
        ResourceList &rl      = profile->getResourceList();
        string       &handler = call_ctx->getResourceHandler(*profile);

        if (rl.empty()) {
            rctl_ret = RES_CTL_OK;
        } else {
            rctl_ret = rctl.get(rl, handler, getLocalTag(), resource_config, ri);
        }

        if (rctl_ret == RES_CTL_OK) {
            DBG("check resources  successed");
            has_profile = true;
            break;
        } else {
            DBG("check resources failed with code %d. internal code: %d", rctl_ret, resource_config.internal_code_id);
            if (rctl_ret == RES_CTL_ERROR) {
                break;
            } else if (rctl_ret == RES_CTL_REJECT) {
                cdr->update_failed_resource(*ri);
                break;
            } else if (rctl_ret == RES_CTL_NEXT) {
                profile = call_ctx->getNextProfile(false, true);
                if (nullptr == profile) {
                    cdr->update_failed_resource(*ri);
                    DBG("there are no profiles more");
                    break;
                }
                if (profile->disconnect_code_id != 0) {
                    cdr->update_failed_resource(*ri);
                    DBG("failovered to refusing profile %d", profile->disconnect_code_id);
                    break;
                }
            }
        }
    } while (rctl_ret != RES_CTL_OK);

    if (!has_profile) {
        unsigned int internal_code, response_code;
        string       internal_reason, response_reason;
        CodesTranslator::instance()->translate_db_code(static_cast<unsigned int>(resource_config.internal_code_id),
                                                       internal_code, internal_reason, response_code, response_reason,
                                                       call_ctx->getOverrideId(a_leg));

        rctl.replace(internal_reason, *ri, resource_config);
        rctl.replace(response_reason, *ri, resource_config);

        cdr->update_internal_reason(DisconnectByTS, response_reason, response_code, resource_config.internal_code_id);

        return false;
    } else {
        DBG("update call profile for legA");
        cdr->update_with_resource_list(*profile);
        updateCallProfile(*profile);
        return true;
    }
}

bool SBCCallLeg::connectCalleeRequest(const AmSipRequest &orig_req)
{
    ParamReplacerCtx ctx(&call_profile);
    ctx.app_param = getHeader(orig_req.hdrs, PARAM_HDR, true);

    AmSipRequest uac_req(orig_req);
    AmUriParser  uac_ruri;

    uac_ruri.uri = uac_req.r_uri;
    if (!uac_ruri.parse_uri()) {
        DBG("Error parsing request R-URI '%s'", uac_ruri.uri.c_str());
        throw AmSession::Exception(400, "Failed to parse R-URI");
    }

    unique_ptr<AmSipDialog> callee_dlg(new AmSipDialog());

    if (!call_profile.evaluate_routing(ctx, orig_req, *callee_dlg)) {
        ERROR("call profile routing evaluation failed");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    if (!call_profile.evaluate(ctx, orig_req)) {
        ERROR("call profile evaluation failed");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    if (!call_profile.append_headers.empty()) {
        replace(call_profile.append_headers, "%global_tag", getGlobalTag());
    }

    /* moved to SBCCallProfile::evaluate_routing()
        string ruri = call_profile.ruri.empty() ? uac_req.r_uri : call_profile.ruri;

        ctx.ruri_parser.uri = ruri;
        if(!ctx.ruri_parser.parse_uri()) {
            ERROR("Error parsing  R-URI '%s'", ruri.data());
            throw AmSession::Exception(400,"Failed to parse R-URI");
        }

        if(!call_profile.ruri_host.empty()) {
            ctx.ruri_parser.uri_port.clear();
            ctx.ruri_parser.uri_host = call_profile.ruri_host;
            ruri = ctx.ruri_parser.uri_str();
        }
    */
    ruri = ctx.ruri_parser.uri; // set by SBCCallProfile::evaluate_routing()
    from = call_profile.from.empty() ? orig_req.from : call_profile.from;
    to   = call_profile.to.empty() ? orig_req.to : call_profile.to;

    AmUriParser from_uri, to_uri;
    if (!from_uri.parse_nameaddr(from)) {
        DBG("Error parsing From-URI '%s'", from.c_str());
        throw AmSession::Exception(400, "Failed to parse From-URI");
    }

    if (!to_uri.parse_nameaddr(to)) {
        DBG("Error parsing To-URI '%s'", to.c_str());
        throw AmSession::Exception(400, "Failed to parse To-URI");
    }

    if (to_uri.uri_host.empty()) {
        to_uri.uri_host = ctx.ruri_parser.uri_host;
        WARN("connectCallee: empty To domain. set to RURI domain: '%s'", ctx.ruri_parser.uri_host.data());
    }

    from = from_uri.nameaddr_str();
    to   = to_uri.nameaddr_str();

    applyAProfile();
    call_profile.apply_a_routing(ctx, orig_req, *dlg);

    AmSipRequest invite_req(orig_req);
    removeHeader(invite_req.hdrs, PARAM_HDR);
    removeHeader(invite_req.hdrs, "P-App-Name");

    if (call_profile.sst_enabled) {
        removeHeader(invite_req.hdrs, SIP_HDR_SESSION_EXPIRES);
        removeHeader(invite_req.hdrs, SIP_HDR_MIN_SE);
    }

    size_t start_pos = 0;
    while (start_pos < call_profile.append_headers.length()) {
        int    res;
        size_t name_end, val_begin, val_end, hdr_end;
        if ((res = skip_header(call_profile.append_headers, start_pos, name_end, val_begin, val_end, hdr_end)) != 0) {
            ERROR("skip_header for '%s' pos: %ld, return %d", call_profile.append_headers.c_str(), start_pos, res);
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
        string hdr_name = call_profile.append_headers.substr(start_pos, name_end - start_pos);
        while (!getHeader(invite_req.hdrs, hdr_name).empty()) {
            removeHeader(invite_req.hdrs, hdr_name);
        }
        start_pos = hdr_end;
    }

    inplaceHeaderPatternFilter(invite_req.hdrs, call_profile.headerfilter_a2b);

    if (call_profile.append_headers.size() > 2) {
        string append_headers = call_profile.append_headers;
        assertEndCRLF(append_headers);
        invite_req.hdrs += append_headers;
    }

    int res = filterSdpOffer(this, invite_req, call_profile, invite_req.body, invite_req.method,
                             call_profile.static_codecs_bleg_id, nullptr, &call_ctx->bleg_initial_offer);
    if (res != 0) {
        INFO("onInitialInvite() Not acceptable codecs for legB");
        throw AmSession::Exception(488, SIP_REPLY_NOT_ACCEPTABLE_HERE);
    }

    connectCallee(to, ruri, from, orig_req, invite_req, callee_dlg.release());

    return false;
}

void SBCCallLeg::onPostgresResponse(PGResponse &e)
{
    router.update_counters(profile_request_start_time);

    bool ret;
    // cast result to call profiles here
    try {
        if (!isArgArray(e.result)) {
            ERROR("unexpected db reply: %s", AmArg::print(e.result).data());
            throw GetProfileException(FC_READ_FROM_TUPLE_FAILED, false);
        }

        // iterate rows fill/evaluate profiles
        for (size_t i = 0; i < e.result.size(); i++) {
            AmArg &a = e.result.get(i);

            if (yeti.config.postgresql_debug) {
                for (auto &it : *a.asStruct()) {
                    DBG("%s/profile[%d]: %s %s", getLocalTag().data(), i, it.first.data(), arg2json(it.second).data());
                }
            }

            if (SqlCallProfile::is_empty_profile(a))
                continue;

            call_ctx->profiles.emplace_back();
            SqlCallProfile &p = call_ctx->profiles.back();

            // read profile
            ret = false;
            try {
                ret = yeti.callprofiles_cache.complete_profile(a);
                if (ret) {
                    if (yeti.config.postgresql_debug) {
                        for (auto &it : *a.asStruct()) {
                            DBG("%s/merged_profile[%d]: %s %s", getLocalTag().data(), i, it.first.data(),
                                arg2json(it.second).data());
                        }
                    }
                    ret = p.readFromTuple(a, getLocalTag(), router.getDynFields(), router.get_lega_gw_cache_key(),
                                          router.get_legb_gw_cache_key());
                }
            } catch (AmArg::OutOfBoundsException &e) {
                ERROR("OutOfBoundsException while reading from profile tuple: %s", AmArg::print(a).data());
            } catch (AmArg::TypeMismatchException &e) {
                ERROR("TypeMismatchException while reading from profile tuple: %s", AmArg::print(a).data());
            } catch (std::string &s) {
                ERROR("string exception '%s' while reading from profile tuple: %s", s.data(), AmArg::print(a).data());
            } catch (std::exception &e) {
                ERROR("std::exception '%s' while reading from profile tuple: %s", e.what(), AmArg::print(a).data());
            } catch (...) {
                ERROR("exception while reading from profile tuple: %s", AmArg::print(a).data());
            }

            if (!ret) {
                throw GetProfileException(FC_READ_FROM_TUPLE_FAILED, false);
            }

            if (!p.eval(rctl)) {
                throw GetProfileException(FC_EVALUATION_FAILED, false);
            }
        }

        if (call_ctx->profiles.empty())
            throw GetProfileException(FC_DB_EMPTY_RESPONSE, false);

    } catch (GetProfileException &e) {
        DBG("GetProfile exception. code:%d", e.code);

        call_ctx->profiles.clear();
        call_ctx->profiles.emplace_back();
        call_ctx->profiles.back().disconnect_code_id = e.code;
        call_ctx->SQLexception                       = true;
    }

    onProfilesReady();
}

void SBCCallLeg::onPostgresResponseError(PGResponseError &e)
{
    ERROR("getprofile db error: %s", e.error.data());

    delete call_ctx;
    call_ctx = nullptr;

    AmSipDialog::reply_error(uac_req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    dlg->drop();
    dlg->dropTransactions();
    setStopped();
    return;
}

void SBCCallLeg::onPostgresTimeout(PGTimeout &)
{
    ERROR("getprofile timeout");

    delete call_ctx;
    call_ctx = nullptr;

    AmSipDialog::reply_error(uac_req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    dlg->drop();
    dlg->dropTransactions();
    setStopped();
    return;
}

void SBCCallLeg::onProfilesReady()
{
    bool max_log_sip = false;
    bool max_log_rtp = false;

    for (const auto &p : call_ctx->profiles) {
        max_log_sip |= p.log_sip;
        max_log_rtp |= p.log_rtp;
    }

    for (auto &p : call_ctx->profiles) {
        p.log_sip = max_log_sip;
        p.log_rtp = max_log_rtp;
    }

    SqlCallProfile *profile = call_ctx->getFirstProfile();
    if (nullptr == profile) {
        delete call_ctx;
        call_ctx = nullptr;

        AmSipDialog::reply_error(uac_req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        dlg->drop();
        dlg->dropTransactions();
        setStopped();
        return;
    }

    Cdr *cdr = call_ctx->cdr.get();
    if (cdr && !isArgUndef(identity_data)) {
        cdr->identity_data = identity_data;
    }

    if (profile->auth_required) {
        call_ctx->cdr.reset();
        delete call_ctx;
        call_ctx = nullptr;

        if (auth_result_id <= 0) {
            DBG("auth required for not authorized request. send auth challenge");
            send_and_log_auth_challenge(uac_req, "no Authorization header", !router.is_skip_logging_invite_challenge());
        } else {
            ERROR("got callprofile with auth_required "
                  "for already authorized request. reply internal error. i:%s",
                  dlg->getCallid().data());
            AmSipDialog::reply_error(uac_req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }

        dlg->drop();
        dlg->dropTransactions();
        setStopped();
        return;
    }

    cdr->set_start_time(call_start_time);

    ctx.call_profile = profile;
    if (router.check_and_refuse(profile, cdr, uac_req, ctx, true)) {
        if (!call_ctx->SQLexception) { // avoid to write cdr on failed getprofile()
            cdr->dump_level_id = 0;    // override dump_level_id. we have no logging at this stage
            if (call_profile.global_tag.empty()) {
                global_tag = getLocalTag();
            } else {
                global_tag = call_profile.global_tag;
            }
            cdr->update_init_aleg(getLocalTag(), global_tag, uac_req.callid);

            router.write_cdr(call_ctx->cdr, true);
        } else {
            call_ctx->cdr.reset();
        }
        delete call_ctx;
        call_ctx = nullptr;

        // AmSipDialog::reply_error(req,500,SIP_REPLY_SERVER_INTERNAL_ERROR);
        dlg->drop();
        dlg->dropTransactions();
        setStopped();
        return;
    }


    // check for registered_aor_id in profiles
    std::set<int> aor_ids;
    for (const auto &p : call_ctx->profiles) {
        if (0 != p.registered_aor_id) {
            aor_ids.emplace(p.registered_aor_id);
        }
    }

    if (!aor_ids.empty()) {
        DBG("got %zd AoR ids to resolve", aor_ids.size());
    }

    call_profile      = *call_ctx->getCurrentProfile();
    placeholders_hash = call_ctx->getCurrentProfile()->placeholders_hash;

    set_sip_relay_only(false);

    if (call_profile.aleg_rel100_mode_id != -1) {
        dlg->setRel100State(static_cast<Am100rel::State>(call_profile.aleg_rel100_mode_id));
    } else {
        dlg->setRel100State(Am100rel::REL100_IGNORED);
    }

    if (call_profile.rtprelay_bw_limit_rate > 0 && call_profile.rtprelay_bw_limit_peak > 0) {
        RateLimit *limit = new RateLimit(static_cast<unsigned int>(call_profile.rtprelay_bw_limit_rate),
                                         static_cast<unsigned int>(call_profile.rtprelay_bw_limit_peak), 1000);
        rtp_relay_rate_limit.reset(limit);
    }

    if (call_profile.global_tag.empty()) {
        global_tag = getLocalTag();
    } else {
        global_tag = call_profile.global_tag;
    }

    ctx.call_profile = &call_profile;
    ctx.app_param    = getHeader(uac_req.hdrs, PARAM_HDR, true);

    init();

    modified_req      = uac_req;
    aleg_modified_req = uac_req;

    if (aleg_modified_req.max_forwards > yeti.config.max_forwards_decrement) {
        aleg_modified_req.max_forwards -= yeti.config.max_forwards_decrement;
        modified_req.max_forwards = aleg_modified_req.max_forwards;
    }

    if (!logger) {
        if (!call_profile.get_logger_path().empty() && (call_profile.log_sip || call_profile.log_rtp)) {
            DBG3("pcap logging requested by call_profile");
            // open the logger if not already opened
            ParamReplacerCtx ctx(&call_profile);
            string log_path = ctx.replaceParameters(call_profile.get_logger_path(), "msg_logger_path", uac_req);
            if (!openLogger(log_path)) {
                WARN("can't open msg_logger_path: '%s'", log_path.c_str());
            }
        } else if (yeti.config.pcap_memory_logger) {
            DBG3("no pcap logging by call_profile, but pcap_memory_logger enabled. set in-memory logger");
            setLogger(new in_memory_msg_logger());
            memory_logger_enabled = true;
        } else {
            DBG3("continue without pcap logger");
        }
    }

    uac_req.log((call_profile.log_sip || memory_logger_enabled) ? getLogger() : nullptr,
                call_profile.aleg_sensor_level_id & LOG_SIP_MASK ? getSensor() : nullptr);

    sip_uri uac_ruri;
    if (parse_uri(&uac_ruri, uac_req.r_uri.data(), uac_req.r_uri.length()) < 0) {
        DBG("Error parsing R-URI '%s'", uac_req.r_uri.data());
        throw AmSession::Exception(400, "Failed to parse R-URI");
    }

    call_ctx->cdr->update_with_aleg_sip_request(uac_req);
    call_ctx->initial_invite = new AmSipRequest(aleg_modified_req);

    if (yeti.config.early_100_trying) {
        msg_logger *logger = getLogger();
        if (logger) {
            early_trying_logger->relog(logger);
        }
    } else {
        dlg->reply(uac_req, 100, "Connecting");
    }


    radius_auth(this, *call_ctx->cdr, call_profile, uac_req);

    httpCallStartedHook();
    if (!radius_auth_post_event(this, call_profile)) {
        processAorResolving();
    }
}

void SBCCallLeg::onJsonRpcRequest(JsonRpcRequestEvent &request)
{
    switch (request.method_id) {
    case MethodRemoveCall:
    {
        AmArg ret;
        Yeti::instance().RemoveCall(this, ret);
        postJsonRpcReply(request, ret);
    } break;
    case MethodShowSessionInfo:
    {
        Yeti::instance().ShowSessionInfo(this, request);
    } break;
    case MethodGetCall:
    {
        AmArg ret;
        Yeti::instance().GetCall(this, ret);
        postJsonRpcReply(request, ret);
    } break;
    }
}

void SBCCallLeg::onRadiusReply(const RadiusReplyEvent &ev)
{
    DBG("got radius reply for %s", getLocalTag().c_str());

    if (AmBasicSipDialog::Cancelling == dlg->getStatus()) {
        DBG("[%s] ignore radius reply in Cancelling state", getLocalTag().c_str());
        return;
    }
    getCtx_void
    try {
        switch (ev.result) {
        case RadiusReplyEvent::Accepted: processAorResolving(); break;
        case RadiusReplyEvent::Rejected:
            throw InternalException(RADIUS_RESPONSE_REJECT, call_ctx->getOverrideId(a_leg));
        case RadiusReplyEvent::Error:
            if (ev.reject_on_error) {
                ERROR("[%s] radius error %d. reject", getLocalTag().c_str(), ev.error_code);
                throw InternalException(static_cast<unsigned int>(ev.error_code), call_ctx->getOverrideId(a_leg));
            } else {
                ERROR("[%s] radius error %d, but radius profile configured to ignore errors.", getLocalTag().c_str(),
                      ev.error_code);
                processAorResolving();
            }
            break;
        }
    } catch (AmSession::Exception &e) {
        onEarlyEventException(static_cast<unsigned int>(e.code), e.reason);
    } catch (InternalException &e) {
        onEarlyEventException(e.response_code, e.response_reason);
    }
}

static string print_uri_params(list<sip_avp *> params)
{
    string s;
    for (const auto &p : params) {
        if (!p->name.isEmpty()) {
            if (!s.empty())
                s += ';';
            s += p->name.toString();
            if (!p->value.isEmpty()) {
                s += '=';
                s += p->value.toString();
            }
        }
    }
    return s;
}

static void merge_uri_params(string &dst, const string &src)
{
    list<sip_avp *> dst_params;
    const char     *dst_params_str = dst.data();
    if (0 != parse_gen_params(&dst_params, &dst_params_str, dst.size(), 0)) {
        ERROR("failed to parse dst URI params: '%s'", dst.data());
        return;
    }

    list<sip_avp *> src_params;
    const char     *src_params_str = src.data();
    if (0 != parse_gen_params(&src_params, &src_params_str, src.size(), 0)) {
        ERROR("failed to parse src URI params: '%s'", src.data());
        return;
    }

    for (; !src_params.empty(); src_params.pop_front()) {
        auto src_param  = src_params.front();
        bool overridden = false;
        for (auto &dst_param : dst_params) {
            if ((!dst_param->name.isEmpty()) && dst_param->name == src_param->name) {
                overridden = true;
                delete dst_param;
                dst_param = src_param;

                break;
            }
        }

        if (!overridden)
            dst_params.emplace_back(src_param);
    }

    dst = print_uri_params(dst_params);
    free_gen_params(&dst_params);
}

static void replace_profile_fields(const SipRegistrarResolveResponseEvent::aor_data &data, SqlCallProfile &p)
{
    if (p.registered_aor_mode_id) {
        DBG(">> profile ruri: '%s', to: '%s', aor: '%s', registered_aor_mode_id:%d", p.ruri.data(), p.to.data(),
            data.contact.data(), p.registered_aor_mode_id);

        // parse AoR
        AmUriParser contact_parser;
        contact_parser.uri  = data.contact;
        bool contact_parsed = contact_parser.parse_uri();
        if (!contact_parsed) {
            ERROR("failed to parse AoR Contact: %s", data.contact.data());
        }

        // replace RURI
        switch (p.registered_aor_mode_id) {
        case SqlCallProfile::REGISTERED_AOR_MODE_AS_IS: p.ruri = data.contact; break;
        case SqlCallProfile::REGISTERED_AOR_MODE_REPLACE_RURI_TRANSPORT_INFO:
        {
            AmUriParser ruri_parser;
            ruri_parser.uri = p.ruri;
            if (ruri_parser.parse_uri()) {
                if (contact_parsed) {
                    contact_parser.uri_user = ruri_parser.uri_user;
                    merge_uri_params(contact_parser.uri_param, ruri_parser.uri_param);
                    p.ruri = contact_parser.uri_str();
                } else {
                    // fallback to the full replace
                    p.ruri = data.contact;
                }
            } else {
                ERROR("failed to parse RURI: %s", p.ruri.data());
                // fallback to the full replace
                p.ruri = data.contact;
            }
        } break;
        } // switch(p.registered_aor_mode_id)

        // replace To
        if (contact_parsed && !p.to.empty()) {
            AmUriParser to_parser;
            if (to_parser.parse_nameaddr(p.to)) {
                const static string invalid_domain("unknown.invalid");
                if (to_parser.uri_host.empty() || to_parser.uri_host == invalid_domain) {
                    to_parser.uri_host = contact_parser.uri_host;
                    p.to               = to_parser.nameaddr_str();
                }
            } else {
                ERROR("failed to parse To: '%s'", p.to.data());
            }
        }
    }

    // replace route
    if (!data.path.empty()) {
        p.route = data.path;
    }

    // replace outbound_interface and outbound_interface_value
    if (!data.interface_name.empty()) {
        p.outbound_interface = data.interface_name;
        p.evaluateOutboundInterface();
    }
}

void SBCCallLeg::process_push_token_profile(SqlCallProfile &p)
{
    // subscribe for the reg events
    std::unique_ptr<SipRegistrarResolveAorsSubscribeEvent> event_ptr{ new SipRegistrarResolveAorsSubscribeEvent{
        getLocalTag() } };
    event_ptr->timeout = std::chrono::milliseconds(4000);
    event_ptr->aor_ids.emplace(std::to_string(p.registered_aor_id));

    if (false == AmSessionContainer::instance()->postEvent(SIP_REGISTRAR_QUEUE, event_ptr.release())) {
        ERROR("failed to post 'resolve subscribe' event to registrar");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    waiting_for_location = true;

    // send push
    auto semi_pos = p.push_token.find(':');
    if (semi_pos == std::string::npos) {
        ERROR("unexpected token format: missed ':' type/value separator");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }
    int token_type;
    if (!str2int(p.push_token.substr(0, semi_pos), token_type)) {
        ERROR("failed to get token type from string: %s", p.push_token.substr(0, semi_pos).data());
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }
    DBG("token_type: %d", token_type);

    // TODO: move type -> http_dest,payload format,etc mappings to the cfg
    enum TokenTypes { FCM = 0, APNS_PROD = 1, APNS_SAND = 2 };

    switch (token_type) {
    case FCM:
    {
        AmUriParser from_uri;
        auto        from = p.from.empty() ? call_ctx->initial_invite->from : call_profile.from;
        if (!from_uri.parse_nameaddr(from)) {
            ERROR("Error parsing From-URI '%s'", from.c_str());
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
        using sc = std::chrono::system_clock;
        AmArg data{
            { "message", AmArg{ { "data",
                                  AmArg{ // TODO: clarify payload format
                                         { "born_at", std::to_string(sc::to_time_t(sc::now())) },
                                         { "from_user", from_uri.uri_user },
                                         { "from_display_name", from_uri.display_name },
                                         { "from_tag", getLocalTag() },
                                         { "call_id", call_ctx->initial_invite->callid },
                                         { "type", "call_start" } } },
                                { "android", AmArg{ { "priority", "high" } } },
                                { "token", p.push_token.substr(semi_pos + 1) } } }
        };

        DBG("data: %s", data.print().data());

        std::unique_ptr<HttpPostEvent> http_event{ new HttpPostEvent("fcm",            // destination_name
                                                                     arg2json(data),   // data
                                                                     "push",           // token
                                                                     getLocalTag()) }; // session_id

        if (!AmSessionContainer::instance()->postEvent(HTTP_EVENT_QUEUE, http_event.release())) {
            ERROR("failed to post push notification");
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
    } break;
    default:
        ERROR("token_type %d is not supported", token_type);
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        break;
    }
}

void SBCCallLeg::onSipRegistrarResolveResponse(const SipRegistrarResolveResponseEvent &e)
{
    DBG("%s onSipRegistrarResolveResponse", getLocalTag().c_str());

    getCtx_void;

    auto &profiles = call_ctx->profiles;

    if (e.aors.empty() && (!waiting_for_location)) {
        // check if we have at least one non-rejecting profile without registered_aor_id requirement
        auto it = std::find_if(profiles.begin(), profiles.end(), [](const SqlCallProfile &p) {
            return p.disconnect_code_id == 0 && p.registered_aor_id == 0;
        });

        if (it == profiles.end()) {
            // no valid profiles to create Blegs
            // search for the first profile with push_token
            it = std::find_if(profiles.begin(), profiles.end(),
                              [](const SqlCallProfile &p) { return !p.push_token.empty(); });

            if (it != profiles.end()) {
                process_push_token_profile(*it);
                return;
            }
        }
    }

    // resolve ruri in profiles
    DBG("profiles count before the processing: %lu", profiles.size());

    unsigned int profile_idx = 0, sub_profile_idx;
    for (auto it = profiles.begin(); it != profiles.end(); profile_idx++) {
        SqlCallProfile &p = *it;

        DBG("> process profile idx:%u, disconnect_code_id: %d, registered_aor_id:%d", profile_idx, p.disconnect_code_id,
            p.registered_aor_id);

        if (p.disconnect_code_id != 0 || p.registered_aor_id == 0) {
            ++it;
            DBG("< skip profile %u processing. "
                "disconnect code is set or aor resolving is not needed",
                profile_idx);
            continue;
        }

        auto a = e.aors.find(std::to_string(p.registered_aor_id));
        if (a == e.aors.end()) {
            p.skip_code_id = DC_NOT_REGISTERED;
            ++it;
            DBG("< mark profile %u as not registered using disconnect code %d", profile_idx, DC_NOT_REGISTERED);
            continue;
        }

        auto &aors_list = a->second;

        sub_profile_idx = 1;
        for (auto aor_it = ++aors_list.cbegin(); aor_it != aors_list.cend(); ++aor_it, sub_profile_idx++) {
            it             = profiles.insert(++it, p);
            auto &cloned_p = *it;

            DBG("< clone profile %d.0 to %d.%d because user resolved to the multiple AoRs", profile_idx, profile_idx,
                sub_profile_idx);

            replace_profile_fields(*aor_it, cloned_p);

            DBG("< set profile %d.%d ruri to: %s", profile_idx, sub_profile_idx, cloned_p.ruri.data());

            if (!aor_it->path.empty()) {
                DBG("< set profile %d.%d route to: %s", profile_idx, sub_profile_idx, cloned_p.route.data());
            }
        }

        auto const &aor_data = *aors_list.begin();

        replace_profile_fields(aor_data, p);

        DBG("< set profile %d.0 RURI: %s", profile_idx, p.ruri.data());

        DBG("< set profile %d.0 To: %s", profile_idx, p.to.data());

        if (!aor_data.path.empty()) {
            DBG("< set profile %d.0 route to: %s", profile_idx, p.route.data());
        }

        ++it;
    }

    DBG("%lu profiles after the processing:", profiles.size());
    profile_idx = 0;
    for (const auto &p : profiles) {
        DBG("profile idx:%u, disconnect_code_id:%d, registered_aor_id:%d, skip_code_id:%d, ruri:'%s', to:'%s', "
            "route:'%s'",
            profile_idx, p.disconnect_code_id, p.registered_aor_id, p.skip_code_id, p.ruri.data(), p.to.data(),
            p.route.data());
        profile_idx++;
    }

    // at this stage rejecting profile can not be the first one

    auto next_profile = call_ctx->current_profile;
    if ((*next_profile).skip_code_id != 0) {
        unsigned int internal_code, response_code;
        string       internal_reason, response_reason;

        // skip profiles with skip_code_id writing CDRs
        do {
            SqlCallProfile &p = *next_profile;
            DBG("process profile with skip_code_id: %d", p.skip_code_id);

            bool write_cdr = CodesTranslator::instance()->translate_db_code(
                p.skip_code_id, internal_code, internal_reason, response_code, response_reason, p.aleg_override_id);

            if (write_cdr) {
                with_cdr_for_read
                {
                    cdr->update_internal_reason(DisconnectByTS, internal_reason, internal_code, p.skip_code_id);
                    cdr->update_aleg_reason(response_reason, response_code);
                }
            }

            ++next_profile;

            if (next_profile == profiles.end() || (*next_profile).disconnect_code_id != 0) {
                DBG("no more profiles or reject profile after the skipped profile. terminate leg");
                router.write_cdr(call_ctx->cdr, true);
                AmSipDialog::reply_error(aleg_modified_req, response_code, response_reason);
                terminateLeg();
                return;
            }

            call_ctx->current_profile = next_profile;
            if (call_ctx->cdr) {
                std::unique_ptr<Cdr> new_cdr(new Cdr(*call_ctx->cdr, *next_profile));
                router.write_cdr(call_ctx->cdr, false);
                call_ctx->cdr.reset(new_cdr.release());
            }

        } while ((*next_profile).skip_code_id != 0);
    }

    if (auto cdr = call_ctx->cdr.get(); cdr) {
        cdr->update_sql(*call_ctx->current_profile);
    }

    processResourcesAndSdp();
}

void SBCCallLeg::onCertCacheReply(const CertCacheResponseEvent &e)
{
    DBG("onCertCacheReply(): got %d for %s", e.result, e.cert_url.data());

    awaited_identity_certs.erase(e.cert_url);
    if (awaited_identity_certs.empty()) {
        DBG("all awaited certs are ready. continue call processing");
        onIdentityReady();
    } else {
        DBG("%zd awaited certs left", awaited_identity_certs.size());
    }
}

void SBCCallLeg::onHttpPostResponse(const HttpPostResponseEvent &e)
{
    DBG("code: %ld, body:%s", e.code, e.data.data());
    /* TODO: unsubscribe from reg event and terminate call here
     * on http error reply for push notification */
}

void SBCCallLeg::onRtpTimeoutOverride(const AmRtpTimeoutEvent &)
{
    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");
    unsigned int internal_code, response_code;
    string       internal_reason, response_reason;

    getCtx_void;

    if (getCallStatus() != CallLeg::Connected) {
        WARN("%s: module catched RtpTimeout in no Connected state. ignore it", getLocalTag().c_str());
        return;
    }

    auto dc_code = a_leg ? DC_LEGA_RTP_TIMEOUT : DC_LEGB_RTP_TIMEOUT;

    CodesTranslator::instance()->translate_db_code(dc_code, internal_code, internal_reason, response_code,
                                                   response_reason, call_ctx->getOverrideId(a_leg));

    with_cdr_for_read
    {
        cdr->update_internal_reason(DisconnectByTS, internal_reason, internal_code, dc_code);
        cdr->update_aleg_reason("Bye", 200);
        cdr->update_bleg_reason("Bye", 200);
    }

    SBCCallLeg::onRtpTimeout();
}

bool SBCCallLeg::onTimerEvent(int timer_id)
{
    DBG("%s(%p,%d,leg%s)", FUNC_NAME, to_void(this), timer_id, a_leg ? "A" : "B");

    if (timer_id == YETI_REFER_TIMEOUT_TIMER) {
        DBG("transferor leg timeout. terminate leg");
        terminateLeg();
        return true;
    }

    if (!call_ctx) {
        return false;
    }

    with_cdr_for_read
    {
        switch (timer_id) {
        case YETI_CALL_DURATION_TIMER:
            cdr->update_internal_reason(DisconnectByTS, "Call duration limit reached", 200, 0);
            cdr->update_aleg_reason("Bye", 200);
            cdr->update_bleg_reason("Bye", 200);
            stopCall("Call duration limit reached");
            return true;
        case YETI_RINGING_TIMEOUT_TIMER:
            call_ctx->setRingingTimeout();
            dlg->cancel();
            return true;
        case YETI_RADIUS_INTERIM_TIMER:
            DBG("interim accounting timer fired for %s", getLocalTag().c_str());
            if (call_ctx->cdr) {
                radius_accounting_interim(this, *call_ctx->cdr);
                radius_accounting_interim_post_event_set_timer(this);
            }
            return true;
        case YETI_FAKE_RINGING_TIMER: onFakeRingingTimer(); return true;
        default:                      return false;
        }
    }
    return false;
}

void SBCCallLeg::onInterimRadiusTimer()
{
    DBG("interim accounting timer fired for %s", getLocalTag().c_str());
    if (call_ctx->cdr)
        radius_accounting_interim(this, *call_ctx->cdr);
}

void SBCCallLeg::onFakeRingingTimer()
{
    DBG("fake ringing timer fired for %s", getLocalTag().c_str());
    if (!call_ctx->ringing_sent) {
        dlg->reply(*call_ctx->initial_invite, 180, SIP_REPLY_RINGING);
        call_ctx->ringing_sent = true;
    }
}

void SBCCallLeg::onControlEvent(SBCControlEvent *event)
{
    DBG("%s(%p,leg%s) cmd = %s, event_id = %d", FUNC_NAME, to_void(this), a_leg ? "A" : "B", event->cmd.c_str(),
        event->event_id);
    if (event->cmd == "teardown") {
        onTearDown();
    }
}

void SBCCallLeg::onTearDown()
{
    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");
    getCtx_void with_cdr_for_read
    {
        cdr->update_internal_reason(DisconnectByTS, "Teardown", 200, 0);
        cdr->update_aleg_reason("Bye", 200);
        cdr->update_bleg_reason("Bye", 200);
    }
}

void SBCCallLeg::onSystemEventOverride(AmSystemEvent *event)
{
    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");
    if (event->sys_event == AmSystemEvent::ServerShutdown) {
        onServerShutdown();
    }
}

void SBCCallLeg::onServerShutdown()
{
    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");
    {
        getCtx_void with_cdr_for_read
        {
            cdr->update_internal_reason(DisconnectByTS, "ServerShutdown", 200, 0);
        }
    }
    // may never reach onDestroy callback so free resources here
    rctl.put(call_profile.resource_handler);
    if (call_ctx) {
        rctl.put(call_ctx->lega_resource_handler);
    }
}

void SBCCallLeg::onStart()
{
    thread_id = gettid();
    // this should be the first thing called in session's thread
    CallLeg::onStart();

    /* moved to the SBCCallLeg::connectCallee
    if (!a_leg) applyBProfile(); // A leg needs to evaluate profile first
    else if (!getOtherId().empty()) {
        // A leg but we already have a peer, what means that this call leg was
        // created as an A leg for already existing B leg (for example call
        // transfer)
        // we need to apply a profile, we use B profile and understand it as an
        // "outbound" profile though we are in A leg
        applyBProfile();
    } */
}

void SBCCallLeg::updateCallProfile(const SBCCallProfile &new_profile)
{
    call_profile = new_profile;
    placeholders_hash.update(call_profile.placeholders_hash);
}

void SBCCallLeg::applyAProfile()
{
    // apply A leg configuration (but most of the configuration is applied in
    // SBCFactory::onInvite)

    setAllow1xxWithoutToTag(call_profile.allow_1xx_without_to_tag);

    if (call_profile.rtprelay_enabled) {
        DBG("Enabling RTP relay mode for SBC call");

        setRtpRelayForceSymmetricRtp(call_profile.aleg_force_symmetric_rtp);
        DBG("%s", getRtpRelayForceSymmetricRtp() ? "forcing symmetric RTP (passive mode)"
                                                 : "disabled symmetric RTP (normal mode)");
        setRtpEndlessSymmetricRtp(call_profile.aleg_symmetric_rtp_nonstop);

        if (call_profile.aleg_rtprelay_interface_value >= 0) {
            setRtpInterface(call_profile.aleg_rtprelay_interface_value);
            DBG("using RTP interface %i for A leg", rtp_interface);
        }

        setRtpRelayTransparentSeqno(false);
        setRtpRelayTransparentSSRC(false);
        setRtpRelayTimestampAligning(call_profile.relay_timestamp_aligning);
        setEnableDtmfRtpFiltering(call_profile.rtprelay_dtmf_filtering);
        setEnableDtmfRtpDetection(call_profile.rtprelay_dtmf_detection);
        setEnableDtmfForceRelay(call_profile.rtprelay_force_dtmf_relay);
        setEnableCNForceRelay(call_profile.force_relay_CN);
        setEnableRtpPing(call_profile.aleg_rtp_ping);
        setRtpTimeout(call_profile.dead_rtp_time);
        setIgnoreRelayStreams(call_profile.filter_noaudio_streams);
        setEnableInboundDtmfFiltering(call_profile.bleg_rtp_filter_inband_dtmf);
        setMediaTransport(call_profile.aleg_media_transport);
        setZrtpEnabled(call_profile.aleg_media_allow_zrtp);

        if (call_profile.transcoder.isActive()) {
            setRtpRelayMode(RTP_Transcoding);
            switch (call_profile.transcoder.dtmf_mode) {
            case SBCCallProfile::TranscoderSettings::DTMFAlways: enable_dtmf_transcoding = true; break;
            case SBCCallProfile::TranscoderSettings::DTMFNever:  enable_dtmf_transcoding = false; break;
            };
        } else {
            setRtpRelayMode(RTP_Relay);
        }
        // copy stats counters
        rtp_pegs = call_profile.aleg_rtp_counters;

        setMediaAcl(call_profile.aleg_rtp_acl);
    }

    if (!call_profile.dlg_contact_params.empty())
        dlg->setContactParams(call_profile.dlg_contact_params);
}

int SBCCallLeg::applySSTCfg(AmConfigReader &sst_cfg, const AmSipRequest *p_req)
{
    DBG("Enabling SIP Session Timers");
    if (nullptr == SBCFactory::instance()->session_timer_fact) {
        ERROR("session_timer module not loaded - "
              "unable to create call with SST\n");
        return -1;
    }

    if (p_req && !SBCFactory::instance()->session_timer_fact->onInvite(*p_req, sst_cfg)) {
        return -1;
    }

    AmSessionEventHandler *h = SBCFactory::instance()->session_timer_fact->getHandler(this);
    if (!h) {
        ERROR("could not get a session timer event handler");
        return -1;
    }

    if (h->configure(sst_cfg)) {
        ERROR("Could not configure the session timer: "
              "disabling session timers.\n");
        delete h;
    } else {
        addHandler(h);
        // hack: repeat calling the handler again to start timers because
        // it was called before SST was applied
        if (p_req)
            h->onSipRequest(*p_req);
    }

    return 0;
}

void SBCCallLeg::applyBProfile()
{
    setAllow1xxWithoutToTag(call_profile.allow_1xx_without_to_tag);

    redirects_allowed = call_profile.bleg_max_30x_redirects;

    if (call_profile.auth_enabled) {
        // adding auth handler
        AmSessionEventHandlerFactory *uac_auth_f = AmPlugIn::instance()->getFactory4Seh("uac_auth");
        if (nullptr == uac_auth_f) {
            INFO("uac_auth module not loaded. uac auth NOT enabled.");
        } else {
            AmSessionEventHandler *h = uac_auth_f->getHandler(this);

            // we cannot use the generic AmSessi(onEvent)Handler hooks,
            // because the hooks don't work in AmB2BSession
            setAuthHandler(h);
            DBG("uac auth enabled for callee session.");
        }
    }

    if (call_profile.sst_enabled) {
        if (applySSTCfg(call_profile.sst_b_cfg, nullptr) < 0) {
            ERROR("%s SST cfg apply error", getLocalTag().data());
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
    }

    // was read from caller but reading directly from profile now
    if (call_profile.rtprelay_enabled) {

        if (call_profile.rtprelay_interface_value >= 0)
            setRtpInterface(call_profile.rtprelay_interface_value);

        setRtpRelayForceSymmetricRtp(call_profile.force_symmetric_rtp);
        DBG("%s", getRtpRelayForceSymmetricRtp() ? "forcing symmetric RTP (passive mode)"
                                                 : "disabled symmetric RTP (normal mode)");
        setRtpEndlessSymmetricRtp(call_profile.bleg_symmetric_rtp_nonstop);

        setRtpRelayTransparentSeqno(false);
        setRtpRelayTransparentSSRC(false);
        setRtpRelayTimestampAligning(call_profile.relay_timestamp_aligning);
        setEnableDtmfRtpFiltering(call_profile.rtprelay_dtmf_filtering);
        setEnableDtmfRtpDetection(call_profile.rtprelay_dtmf_detection);
        setEnableDtmfForceRelay(call_profile.rtprelay_force_dtmf_relay);
        setEnableCNForceRelay(call_profile.force_relay_CN);
        setEnableRtpPing(call_profile.bleg_rtp_ping);
        setRtpTimeout(call_profile.dead_rtp_time);
        setIgnoreRelayStreams(call_profile.filter_noaudio_streams);
        setEnableInboundDtmfFiltering(call_profile.aleg_rtp_filter_inband_dtmf);
        setMediaTransport(call_profile.bleg_media_transport);
        setZrtpEnabled(call_profile.bleg_media_allow_zrtp);

        // copy stats counters
        rtp_pegs = call_profile.bleg_rtp_counters;

        setMediaAcl(call_profile.bleg_rtp_acl);
    }

    // was read from caller but reading directly from profile now
    if (!call_profile.callid.empty())
        dlg->setCallid(call_profile.callid);

    if (!call_profile.bleg_dlg_contact_params.empty())
        dlg->setContactParams(call_profile.bleg_dlg_contact_params);

    setInviteTransactionTimeout(call_profile.inv_transaction_timeout);
    setInviteRetransmitTimeout(call_profile.inv_srv_failover_timeout);
}

void SBCCallLeg::addIdentityHeader(AmSipRequest &req)
{
    if (!yeti.config.identity_enabled || !call_profile.ss_crt_id)
        return;

    AmIdentity identity;

    AmIdentity::ident_attest attest_level;
    switch (call_profile.ss_attest_id) {
    case SS_ATTEST_A: attest_level = AmIdentity::AT_A; break;
    case SS_ATTEST_B: attest_level = AmIdentity::AT_B; break;
    case SS_ATTEST_C: attest_level = AmIdentity::AT_C; break;
    default:
        WARN("unexpected ss_attest_id:%d. failover to the level C", call_profile.ss_attest_id);
        attest_level = AmIdentity::AT_C;
    }

    identity.set_attestation(attest_level);
    identity.add_orig_tn(call_profile.ss_otn);
    identity.add_dest_tn(call_profile.ss_dtn);

    auto ret = yeti.cert_cache.getIdentityHeader(identity, call_profile.ss_crt_id);
    if (ret) {
        req.hdrs += "Identity: " + ret.value() + CRLF;
    }
}

int SBCCallLeg::relayEvent(AmEvent *ev)
{
    B2BSipReplyEvent *reply_ev;
    string            referrer_session;

    if (nullptr == call_ctx) {
        if (ev->event_id == B2BSipRequest && getOtherId().empty()) {
            B2BSipRequestEvent *req_ev = dynamic_cast<B2BSipRequestEvent *>(ev);
            assert(req_ev);
            AmSipRequest &req = req_ev->req;
            if (req.method == SIP_METH_BYE) {
                DBG("relayEvent(%p) reply 200 OK for leg without call_ctx and other_id", to_void(this));
                dlg->reply(req, 200, "OK");
                delete ev;
                return 0;
            }
        }
        DBG("relayEvent(%p) zero ctx. ignore event", to_void(this));
        return -1;
    }

    AmOfferAnswer::OAState dlg_oa_state = dlg->getOAState();

    switch (ev->event_id) {
    case B2BSipRequest:
    {
        B2BSipRequestEvent *req_ev = dynamic_cast<B2BSipRequestEvent *>(ev);
        assert(req_ev);

        AmSipRequest &req = req_ev->req;

        DBG("Yeti::relayEvent(%p) filtering request '%s' (c/t '%s') oa_state = %d", to_void(this), req.method.c_str(),
            req.body.getCTStr().c_str(), dlg_oa_state);

        try {
            int res;
            if (req.method == SIP_METH_ACK) {
                // ACK can contain only answer
                dump_SdpMedia(call_ctx->bleg_negotiated_media, "bleg_negotiated media_pre");
                dump_SdpMedia(call_ctx->aleg_negotiated_media, "aleg_negotiated media_pre");

                res = processSdpAnswer(this, req, req.body, req.method, call_ctx->get_other_negotiated_media(a_leg),
                                       a_leg ? call_profile.bleg_single_codec : call_profile.aleg_single_codec,
                                       a_leg ? call_profile.static_codecs_bleg_id : call_profile.static_codecs_aleg_id,
                                       call_profile.filter_noaudio_streams,
                                       // ACK request MUST contain SDP answer if we sent offer in reply
                                       dlg_oa_state == AmOfferAnswer::OA_OfferSent);

                dump_SdpMedia(call_ctx->bleg_negotiated_media, "bleg_negotiated media_post");
                dump_SdpMedia(call_ctx->aleg_negotiated_media, "aleg_negotiated media_post");

            } else {
                res = processSdpOffer(this, call_profile, req.body, req.method,
                                      call_ctx->get_self_negotiated_media(a_leg),
                                      a_leg ? call_profile.static_codecs_aleg_id : call_profile.static_codecs_bleg_id);
                if (res == 0) {
                    res =
                        filterSdpOffer(this, req, call_profile, req.body, req.method,
                                       a_leg ? call_profile.static_codecs_bleg_id : call_profile.static_codecs_aleg_id,
                                       &call_ctx->get_other_negotiated_media(a_leg));
                }
            }
            if (res != 0) {
                delete ev;
                return -488;
            }
        } catch (InternalException &exception) {
            DBG("got internal exception %d on request processing", exception.icode);
            delete ev;
            return -448;
        }

        inplaceHeaderPatternFilter(req.hdrs, a_leg ? call_profile.headerfilter_a2b : call_profile.headerfilter_b2a);

        if ((a_leg && call_profile.keep_vias) || (!a_leg && call_profile.bleg_keep_vias)) {
            req.hdrs = req.vias + req.hdrs;
        }
    } break;
    case B2BSipReply:
    {
        reply_ev = dynamic_cast<B2BSipReplyEvent *>(ev);
        assert(reply_ev);

        AmSipReply &reply = reply_ev->reply;

        reply.rseq = 0;

        if (call_ctx->transfer_intermediate_state && reply.cseq_method == SIP_METH_INVITE) {
            if (!call_ctx->referrer_session.empty()) {
                referrer_session = call_ctx->referrer_session;
                if (reply.code >= 200) {
                    call_ctx->referrer_session.clear();
                }
            }
        }

        if (getCallStatus() == CallLeg::Connected && (reply.code == 481 || reply.code == 408)) {
            DBG("got fatal error reply code for reINVITE. terminate call");
            terminateLegOnReplyException(reply,
                                         InternalException(DC_REINVITE_ERROR_REPLY, call_ctx->getOverrideId(a_leg)));
            delete ev;
            return -488;
        }

        DBG("Yeti::relayEvent(%p) filtering body for reply %d cseq.method '%s' (c/t '%s') oa_state = %d", to_void(this),
            reply.code, reply_ev->trans_method.c_str(), reply.body.getCTStr().c_str(), dlg_oa_state);

        // append headers for 200 OK reply in direction B -> A
        if (!reply.local_reply) {
            inplaceHeaderPatternFilter(reply.hdrs,
                                       a_leg ? call_profile.headerfilter_a2b : call_profile.headerfilter_b2a);
        }

        do {
            if (!a_leg) {
                if (!call_profile.aleg_append_headers_reply.empty() &&
                    (reply.code == 200 || (reply.code >= 180 && reply.code < 190)))
                {
                    size_t start_pos = 0;
                    while (start_pos < call_profile.aleg_append_headers_reply.length()) {
                        int    res;
                        size_t name_end, val_begin, val_end, hdr_end;
                        if ((res = skip_header(call_profile.aleg_append_headers_reply, start_pos, name_end, val_begin,
                                               val_end, hdr_end)) != 0)
                        {
                            ERROR("%s skip_header for '%s' pos: %ld, returned %d", getLocalTag().data(),
                                  call_profile.aleg_append_headers_reply.c_str(), start_pos, res);
                            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
                        }
                        string hdr_name =
                            call_profile.aleg_append_headers_reply.substr(start_pos, name_end - start_pos);
                        start_pos = hdr_end;
                        while (!getHeader(reply.hdrs, hdr_name).empty()) {
                            removeHeader(reply.hdrs, hdr_name);
                        }
                    }
                    assertEndCRLF(call_profile.aleg_append_headers_reply);
                    reply.hdrs += call_profile.aleg_append_headers_reply;
                }

                if (call_profile.suppress_early_media && reply.code >= 180 && reply.code < 190) {
                    DBG("convert B->A reply %d %s to %d %s and clear body", reply.code, reply.reason.c_str(), 180,
                        SIP_REPLY_RINGING);

                    // patch code and reason
                    reply.code   = 180;
                    reply.reason = SIP_REPLY_RINGING;
                    // сlear body
                    reply.body.clear();
                    break;
                }
            }

            try {
                int res;
                { // scope for call_ctx mutex AmLock
                    if (dlg_oa_state == AmOfferAnswer::OA_OfferRecved) {
                        DBG("relayEvent(): process offer in reply");
                        res = processSdpOffer(
                            this, call_profile, reply.body, reply.cseq_method,
                            call_ctx->get_self_negotiated_media(a_leg),
                            a_leg ? call_profile.static_codecs_aleg_id : call_profile.static_codecs_bleg_id, false,
                            a_leg ? call_profile.aleg_single_codec : call_profile.bleg_single_codec);

                        if (res == 0) {
                            res = filterSdpOffer(this, reply, call_profile, reply.body, reply.cseq_method,
                                                 a_leg ? call_profile.static_codecs_bleg_id
                                                       : call_profile.static_codecs_aleg_id);
                        }
                    } else {
                        DBG("relayEvent(): process asnwer in reply");
                        res = processSdpAnswer(
                            this, reply, reply.body, reply.cseq_method, call_ctx->get_other_negotiated_media(a_leg),
                            a_leg ? call_profile.bleg_single_codec : call_profile.aleg_single_codec,
                            a_leg ? call_profile.static_codecs_bleg_id : call_profile.static_codecs_aleg_id,
                            call_profile.filter_noaudio_streams,
                            // final positive reply MUST contain SDP answer if we sent offer
                            (dlg_oa_state == AmOfferAnswer::OA_OfferSent && reply.code >= 200 && reply.code < 300));
                    }
                }

                if (res != 0) {
                    terminateLegOnReplyException(reply, InternalException(res, call_ctx->getOverrideId(a_leg)));
                    delete ev;
                    return -488;
                }
            } catch (InternalException &exception) {
                DBG("got internal exception %d on reply processing", exception.icode);
                terminateLegOnReplyException(reply, exception);
                delete ev;
                return -488;
            }
        } while (0);

    } break;
    } // switch (ev->event_id)

    if (!referrer_session.empty()) {
        DBG("generate Notfy event %d/%s for referrer leg: %s", reply_ev->reply.code, reply_ev->reply.reason.c_str(),
            referrer_session.c_str());

        if (!AmSessionContainer::instance()->postEvent(
                referrer_session, new B2BNotifyEvent(static_cast<int>(reply_ev->reply.code), reply_ev->reply.reason)))
        {
            if (call_ctx)
                call_ctx->referrer_session.clear();
        }
    }

    return CallLeg::relayEvent(ev);
}

SBCCallLeg::~SBCCallLeg()
{
    DBG3("~SBCCallLeg[%p]", to_void(this));

    if (auth)
        delete auth;
    if (logger)
        dec_ref(logger);
    if (sensor)
        dec_ref(sensor);
    if (early_trying_logger)
        dec_ref(early_trying_logger);
}

void SBCCallLeg::onBeforeDestroy()
{
    DBG("%s(%p|%s,leg%s)", FUNC_NAME, to_void(this), getLocalTag().c_str(), a_leg ? "A" : "B");

    if (a_leg) {
        // ensure we will destroy sequencer state on missed hooks
        yeti.http_sequencer.cleanup(getLocalTag());
    }

    if (!call_ctx) {
        DBG("no call_ctx in onBeforeDestroy. return");
        return;
    }

    if (call_profile.record_audio) {
        if (yeti.config.audio_recorder_compress) {
            AmAudioFileRecorderProcessor::instance()->removeRecorder(getLocalTag());
        } else {
            // stop recorder and upload audio file if leg is A
            if (a_leg) {
                // stop recorder
                AmAudioFileRecorderProcessor::instance()->putEvent(
                    new AudioRecorderCtlEvent(global_tag, AudioRecorderEvent::delStereoRecorder));

                // upload audio file
                if (!global_tag.empty() && !yeti.config.audio_recorder_http_destination.empty()) {
                    string audio_record_path(AmConfig.rsr_path);
                    audio_record_path += "/" + global_tag + ".rsr";

                    if (!AmSessionContainer::instance()->postEvent(
                            HTTP_EVENT_QUEUE, new HttpUploadEvent(yeti.config.audio_recorder_http_destination,
                                                                  string(), // file_name
                                                                  audio_record_path,
                                                                  string(), // token
                                                                  string(), // session_id
                                                                  getLocalTag())))
                    {
                        ERROR("can't post http upload event. disable uploading or enable http_client module loading");
                    }
                }
            }
        }
    }

    if (call_ctx->references)
        call_ctx->references--;

    if (!call_ctx->references) {
        DBG3("last leg destroy. a_leg: %d", a_leg);

        if (!call_ctx->profiles.empty()) {
            /* put lega resources */
            rctl.put(call_ctx->lega_resource_handler);

            /* put legb_res/resources from the current profile */
            if (const auto p = call_ctx->getCurrentProfile(); p != nullptr)
                rctl.put(p->resource_handler);
        } else {
            DBG("%s empty profiles. callid:%s, from:%s, to:%s, remote_ip/port: %s:%d", getLocalTag().data(),
                uac_req.callid.data(), uac_req.from.data(), uac_req.to.data(), uac_req.remote_ip.data(),
                uac_req.remote_port);

            setRejectCdr(DC_FIN_BEFORE_DB_RESPONSE);
        }

        router.write_cdr(call_ctx->cdr, true);
        delete call_ctx;
    }

    call_ctx = nullptr;
}

void SBCCallLeg::finalize()
{
    DBG("%s(%p|%s,leg%s)", FUNC_NAME, to_void(this), getLocalTag().c_str(), a_leg ? "A" : "B");

    if (a_leg) {
        if (call_ctx) {
            with_cdr_for_read
            {
                cdr_list.onSessionFinalize(cdr);
            }
        }
    }
    AmB2BSession::finalize();
}

UACAuthCred *SBCCallLeg::getCredentials()
{
    if (a_leg)
        return &call_profile.auth_aleg_credentials;
    else
        return &call_profile.auth_credentials;
}

static bool is_hold_state_change_requested(const AmSdp &local_sdp, const AmSdp &remote_sdp)
{
    auto remote_media_it = remote_sdp.media.cbegin();
    while (remote_media_it != remote_sdp.media.cend() && remote_media_it->type != MT_AUDIO)
        ++remote_media_it;

    for (auto const &local_media : local_sdp.media) {
        if (remote_media_it == remote_sdp.media.cend())
            break;

        if (local_media.type != MT_AUDIO)
            continue;

        const auto &remote_media = *remote_media_it;

        std::optional<bool> local_send, local_recv, remote_send, remote_recv;

        if (remote_media.has_mode_attribute) {
            remote_send = remote_media.send;
            remote_recv = remote_media.recv;
        }
        if (local_media.has_mode_attribute) {
            local_send = local_media.send;
            local_recv = local_media.recv;
        }

        if ((local_recv.value_or(local_sdp.recv) != remote_send.value_or(remote_sdp.send)) ||
            (local_send.value_or(local_sdp.send) != remote_recv.value_or(remote_sdp.recv)))
        {
            return true;
        }

        ++remote_media_it;
        while (remote_media_it != remote_sdp.media.cend() && remote_media_it->type != MT_AUDIO)
            ++remote_media_it;
    }

    return false;
}

void SBCCallLeg::onSipRequest(const AmSipRequest &req)
{
    // AmB2BSession does not call AmSession::onSipRequest for
    // forwarded requests - so lets call event handlers here
    // todo: this is a hack, replace this by calling proper session
    // event handler in AmB2BSession
    bool fwd = sip_relay_only && (req.method != SIP_METH_CANCEL);
    if (fwd) {
        CALL_EVENT_H(onSipRequest, req);
    }

    do {
        DBG("onInDialogRequest(%p|%s,leg%s) '%s'", to_void(this), getLocalTag().c_str(), a_leg ? "A" : "B",
            req.method.c_str());

        getCtx_chained;
        if (!call_ctx->initial_invite)
            break;

        if (req.method == SIP_METH_OPTIONS &&
            ((a_leg && !call_profile.aleg_relay_options) || (!a_leg && !call_profile.bleg_relay_options)))
        {
            dlg->reply(req, 200, "OK", nullptr, "", SIP_FLAGS_VERBATIM);
            return;
        } else if (req.method == SIP_METH_UPDATE && ((a_leg && !call_profile.aleg_relay_update) ||
                                                     (!a_leg && !call_profile.bleg_relay_update)
                                                     // disable relay in early dialog
                                                     || dlg->getStatus() != AmBasicSipDialog::Connected))
        {
            const AmMimeBody *sdp_body = req.body.hasContentType(SIP_APPLICATION_SDP);
            if (!sdp_body) {
                DBG("got UPDATE without body. local processing enabled. generate 200OK without SDP");
                AmSipRequest upd_req(req);
                processLocalRequest(upd_req);
                return;
            }

            AmSdp sdp;
            int   res = sdp.parse(reinterpret_cast<const char *>(sdp_body->getPayload()));
            if (0 != res) {
                DBG("SDP parsing failed: %d. respond with 488", res);
                dlg->reply(req, 488, "Not Acceptable Here");
                return;
            }

            AmSipRequest upd_req(req);
            try {
                int res = processSdpOffer(
                    this, call_profile, upd_req.body, upd_req.method, call_ctx->get_self_negotiated_media(a_leg),
                    a_leg ? call_profile.static_codecs_aleg_id : call_profile.static_codecs_bleg_id, true,
                    a_leg ? call_profile.aleg_single_codec : call_profile.bleg_single_codec);
                if (res != 0) {
                    dlg->reply(req, 488, "Not Acceptable Here");
                    return;
                }
            } catch (InternalException &e) {
                dlg->reply(req, e.response_code, e.response_reason);
                return;
            }

            processLocalRequest(upd_req);
            return;
        } else if (req.method == SIP_METH_PRACK &&
                   ((a_leg && !call_profile.aleg_relay_prack) || (!a_leg && !call_profile.bleg_relay_prack)))
        {
            dlg->reply(req, 200, "OK", nullptr, "", SIP_FLAGS_VERBATIM);
            return;
        } else if (req.method == SIP_METH_INVITE) {
            if ((a_leg && call_profile.aleg_relay_reinvite) || (!a_leg && call_profile.bleg_relay_reinvite)) {
                DBG("skip local processing. relay");
                break;
            }

            bool relay_hold = a_leg ? call_profile.aleg_relay_hold : call_profile.bleg_relay_hold;

            const AmMimeBody *sdp_body = req.body.hasContentType(SIP_APPLICATION_SDP);
            if (!sdp_body) {
                /* consider reINVITEs without SDP as Unhold requests if has remote hold
                 *   https://www.rfc-editor.org/rfc/rfc6337.html#section-5.3
                 *    If it had not previously
                 *    initiated "hold", then it should offer "a=sendrecv" attribute, even
                 *    if it had previously been forced to answer something else.  Without
                 *    this behavior it is possible to get "stuck on hold" in some cases,
                 *    especially when a 3pcc is involved.
                 */
                if (relay_hold && getMediaSession() && isRemoteOnHold()) {
                    // later offer and remote is on hold. relay request
                    DBG("relay request without SDP while remote is on hold");
                    break;
                }

                DBG("got reINVITE without body. local processing enabled. generate 200OK with SDP offer");
                DBG("replying 100 Trying to INVITE to be processed locally");
                dlg->reply(req, 100, SIP_REPLY_TRYING);
                AmSipRequest inv_req(req);
                processLocalRequest(inv_req);
                return;
            }

            AmSdp sdp;
            int   res = sdp.parse(reinterpret_cast<const char *>(sdp_body->getPayload()));
            if (0 != res) {
                DBG("replying 100 Trying to INVITE to be processed locally");
                dlg->reply(req, 100, SIP_REPLY_TRYING);
                DBG("SDP parsing failed: %d. respond with 488", res);
                dlg->reply(req, 488, "Not Acceptable Here");
                return;
            }

            // check for hold/unhold request to pass them transparently
            if (auto m = getMediaSession(); m && m->haveLocalSdp(a_leg)) {
                const AmSdp &local_sdp = m->getLocalSdp(a_leg);
                bool         changed   = is_hold_state_change_requested(local_sdp, sdp);
                DBG("hold state change requested: %d, relay_hold: %d", changed, relay_hold);
                if (relay_hold && is_hold_state_change_requested(local_sdp, sdp)) {
                    // local/remote hold state is requested to be changed. relay request
                    break;
                }
            } else {
                /* no media session (rtprelay_enabled:false)
                 * failover to the old approach with hold state tracking in CallCtx */
                HoldMethod method;
                if (isHoldRequest(sdp, method)) {
                    DBG("hold request matched. relay_hold = %d", relay_hold);
                    if (relay_hold) {
                        ERROR("skip local processing for the hold request");
                        call_ctx->on_hold = true;
                        break;
                    }
                } else if (call_ctx->on_hold) {
                    DBG("we are in the hold state. skip local processing for the unhold request");
                    call_ctx->on_hold = false;
                    break;
                }
            }

            DBG("replying 100 Trying to INVITE to be processed locally");
            dlg->reply(req, 100, SIP_REPLY_TRYING);

            AmSipRequest inv_req(req);
            try {
                int res = processSdpOffer(
                    this, call_profile, inv_req.body, inv_req.method, call_ctx->get_self_negotiated_media(a_leg),
                    a_leg ? call_profile.static_codecs_aleg_id : call_profile.static_codecs_bleg_id, true,
                    a_leg ? call_profile.aleg_single_codec : call_profile.bleg_single_codec);
                if (res != 0) {
                    dlg->reply(req, 488, "Not Acceptable Here");
                    return;
                }
            } catch (InternalException &e) {
                dlg->reply(req, e.response_code, e.response_reason);
                return;
            }

            processLocalRequest(inv_req);
            return;
        } else if (req.method == SIP_METH_REFER) {
            if (a_leg) {
                dlg->reply(req, 603, "Refer is not allowed for Aleg");
                return;
            }
            if (getOtherId().empty()) {
                dlg->reply(req, 603, "Refer is not possible at this stage");
                return;
            }

            if (call_profile.bleg_max_transfers <= 0) {
                dlg->reply(req, 603, "Refer is not allowed");
                return;
            }
            string refer_to = getHeader(req.hdrs, SIP_HDR_REFER_TO, SIP_HDR_REFER_TO_COMPACT, true);

            if (refer_to.empty()) {
                dlg->reply(req, 400, "Refer-To header missing");
                return;
            }

            DBG("xfer. Refer-To: %s", refer_to.c_str());

            sip_nameaddr refer_to_nameaddr;
            const char  *refer_to_ptr = refer_to.c_str();
            if (0 != parse_nameaddr_uri(&refer_to_nameaddr, &refer_to_ptr, static_cast<int>(refer_to.length()))) {
                DBG("failed to parse Refer-To header: %s", refer_to.c_str());
                dlg->reply(req, 400, "Invalid Refer-To header");
                return;
            }

            unique_ptr<B2BReferEvent> refer_event;

            if (refer_to_nameaddr.uri.scheme == sip_uri::TEL) {
                if (refer_to_nameaddr.uri.user.isEmpty()) {
                    DBG("empty number. reject tel URI xfer: %s", refer_to.c_str());
                    dlg->reply(req, 400, "Empty number in tel: URI");
                    return;
                }
                auto profile               = *call_ctx->getCurrentProfile();
                auto legb_gw_cache_id      = profile.legb_gw_cache_id;
                auto tel_redirect_data_ret = yeti.gateways_cache.get_redirect_data(legb_gw_cache_id);
                if (!tel_redirect_data_ret) {
                    DBG("no gateway cache data for legb_gw_cache_id:%s. reject tel URI xfer: %s", legb_gw_cache_id,
                        refer_to.c_str());
                    dlg->reply(req, 603, "Unconfigured xfer for tel URIs");
                    return;
                }
                auto &tel_redirect_data = tel_redirect_data_ret.value();
                if (tel_redirect_data.transfer_tel_uri_host.empty()) {
                    DBG("empty transfer_tel_uri_host for gateway %d. reject tel URI xfer: %s", legb_gw_cache_id,
                        refer_to.c_str());
                    dlg->reply(req, 603, "Unconfigured xfer for tel URIs");
                    return;
                }

                refer_to =
                    format("sip:{}@{}", c2stlstr(refer_to_nameaddr.uri.user), tel_redirect_data.transfer_tel_uri_host);

                refer_event.reset(new B2BReferEvent(getLocalTag(), refer_to));
                refer_event->append_headers = tel_redirect_data.transfer_append_headers_req;
            } else {
                refer_to = c2stlstr(refer_to_nameaddr.addr);
                refer_event.reset(new B2BReferEvent(getLocalTag(), refer_to));
            }

            DBG("xfer to the: %s", refer_event->referred_to.c_str());

            if (!subs->onRequestIn(req))
                return;

            last_refer_cseq = int2str(req.cseq); // memorize cseq to send NOTIFY

            dlg->reply(req, 202, "Accepted");

            setTimer(YETI_REFER_TIMEOUT_TIMER, DEFAULT_B_TIMER / 1000);

            call_ctx->references--;
            if (!call_ctx->references) {
                ERROR("Bleg held last reference to call_ctx. possible ctx leak");
            }
            call_ctx = nullptr; // forget about ctx

            CallLeg::relayEvent(refer_event.release()); // notify Aleg about Refer
            clearRtpReceiverRelay();                    // disconnect B2BMedia
            AmB2BSession::clear_other();                // forget about Aleg

            return;
        }

        if (a_leg && req.method == SIP_METH_CANCEL) {
            with_cdr_for_read
            {
                cdr->update_internal_reason(DisconnectByORG, "Request terminated (Cancel)", 487, 0);
                cdr->update_reasons_with_sip_request(req, true);
            }
        }
    } while (0);

    if (fwd && req.method == SIP_METH_INVITE) {
        DBG("replying 100 Trying to INVITE to be fwd'ed");
        dlg->reply(req, 100, SIP_REPLY_TRYING);
    }

    CallLeg::onSipRequest(req);
}

void SBCCallLeg::setOtherId(const AmSipReply &reply)
{
    DBG("setting other_id to '%s'", reply.from_tag.c_str());
    setOtherId(reply.from_tag);
}

void SBCCallLeg::onInitialReply(B2BSipReplyEvent *e)
{
    CallLeg::onInitialReply(e);
}

void SBCCallLeg::onSipReply(const AmSipRequest &req, const AmSipReply &reply, AmBasicSipDialog::Status old_dlg_status)
{
    TransMap::iterator t   = relayed_req.find(static_cast<int>(reply.cseq));
    bool               fwd = t != relayed_req.end();

    DBG("onSipReply: %i %s (fwd=%i)", reply.code, reply.reason.c_str(), fwd);
    DBG("onSipReply: content-type = %s", reply.body.getCTStr().c_str());
    if (fwd) {
        CALL_EVENT_H(onSipReply, req, reply, old_dlg_status);
    }

    if (nullptr != auth) {
        // only for SIP authenticated
        unsigned int cseq_before = dlg->cseq;
        if (auth->onSipReply(req, reply, old_dlg_status)) {
            if (cseq_before != dlg->cseq) {
                DBG("uac_auth consumed reply with cseq %d and resent with cseq %d; "
                    "updating relayed_req map\n",
                    reply.cseq, cseq_before);
                updateUACTransCSeq(reply.cseq, cseq_before);
                // don't relay to other leg, process in AmSession
                AmSession::onSipReply(req, reply, old_dlg_status);
                // skip presenting reply to ext_cc modules, too
                return;
            }
        }
    }

    if (!a_leg && call_ctx) {
        if (reply.code >= 200 && reply.cseq_method == SIP_METH_INVITE) {
            auto &gw_id = call_ctx->getCurrentProfile()->legb_gw_cache_id;
            if (gw_id)
                yeti.gateways_cache.update_reply_stats(gw_id, reply);
        }

        if (call_ctx->transfer_intermediate_state && reply.cseq_method == SIP_METH_INVITE) {
            if (reply.code >= 200 && reply.code < 300) {
                dlg->send_200_ack(reply.cseq);
            }
        } else {
            with_cdr_for_read cdr->update_with_bleg_sip_reply(reply);
        }
    }

    CallLeg::onSipReply(req, reply, old_dlg_status);
}

void SBCCallLeg::onSendRequest(AmSipRequest &req, int &flags)
{
    DBG("Yeti::onSendRequest(%p|%s) a_leg = %d", to_void(this), getLocalTag().c_str(), a_leg);

    if (call_ctx && !a_leg && call_ctx->referrer_session.empty() && req.method == SIP_METH_INVITE) {
        with_cdr_for_read cdr->update_with_action(BLegInvite);
    }

    if (a_leg) {
        if (!call_profile.aleg_append_headers_req.empty()) {
            size_t start_pos = 0;
            while (start_pos < call_profile.aleg_append_headers_req.length()) {
                int    res;
                size_t name_end, val_begin, val_end, hdr_end;
                if ((res = skip_header(call_profile.aleg_append_headers_req, start_pos, name_end, val_begin, val_end,
                                       hdr_end)) != 0)
                {
                    ERROR("%s skip_header for '%s' pos: %ld, returned %d", getLocalTag().data(),
                          call_profile.aleg_append_headers_req.c_str(), start_pos, res);
                    throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
                }
                string hdr_name = call_profile.aleg_append_headers_req.substr(start_pos, name_end - start_pos);
                start_pos       = hdr_end;
                while (!getHeader(req.hdrs, hdr_name).empty()) {
                    removeHeader(req.hdrs, hdr_name);
                }
            }
            DBG("appending '%s' to outbound request (A leg)", call_profile.aleg_append_headers_req.c_str());
            req.hdrs += call_profile.aleg_append_headers_req;
        }
    } else {
        size_t start_pos = 0;
        while (start_pos < call_profile.append_headers_req.length()) {
            int    res;
            size_t name_end, val_begin, val_end, hdr_end;
            if ((res = skip_header(call_profile.append_headers_req, start_pos, name_end, val_begin, val_end,
                                   hdr_end)) != 0)
            {
                ERROR("%s skip_header for '%s' pos: %ld, return %d", getLocalTag().data(),
                      call_profile.append_headers_req.c_str(), start_pos, res);
                throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
            }
            string hdr_name = call_profile.append_headers_req.substr(start_pos, name_end - start_pos);
            start_pos       = hdr_end;
            while (!getHeader(req.hdrs, hdr_name).empty()) {
                removeHeader(req.hdrs, hdr_name);
            }
        }

        if (req.method == SIP_METH_INVITE && req.to_tag.empty()) {
            // initial INVITE on Bleg
            addIdentityHeader(req);
        }

        if (!call_profile.append_headers_req.empty()) {
            DBG("appending '%s' to outbound request (B leg)", call_profile.append_headers_req.c_str());
            req.hdrs += call_profile.append_headers_req;
        }
    }

    if (nullptr != auth) {
        DBG("auth->onSendRequest cseq = %d", req.cseq);
        auth->onSendRequest(req, flags);
    }

    CallLeg::onSendRequest(req, flags);
}

void SBCCallLeg::onRemoteDisappeared(const AmSipReply &reply)
{
    const static string reinvite_failed("reINVITE failed");

    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");

    if (call_ctx) {
        if (a_leg) {
            // trace available values
            if (call_ctx->initial_invite != nullptr) {
                AmSipRequest &req = *call_ctx->initial_invite;
                DBG("req.method = '%s'", req.method.c_str());
            } else {
                ERROR("intial_invite == NULL");
            }
            with_cdr_for_read
            {
                cdr->update_internal_reason(DisconnectByTS, reply.reason, reply.code, 0);
            }
        }
        if (getCallStatus() == CallLeg::Connected) {
            with_cdr_for_read
            {
                cdr->update_internal_reason(DisconnectByTS, reinvite_failed, 200, 0);
                cdr->update_bleg_reason("Bye", 200);
            }
        }
    }

    CallLeg::onRemoteDisappeared(reply);
}

void SBCCallLeg::onBye(const AmSipRequest &req)
{
    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");

    while (call_ctx) {
        if (a_leg && call_ctx->transfer_intermediate_state) {
            // generate local BYE reply. transferee Bleg is not connected
            with_cdr_for_read
            {
                cdr->update_aleg_reason("EarlyBye", 200);
                cdr->update_internal_reason(DisconnectByORG, "Transfer Failed: EarlyBye", 500, 0);
            }
            dlg->reply(req, 200, "OK");
            break;
        }

        with_cdr_for_read
        {
            cdr->update_reasons_with_sip_request(req, a_leg);
            if (getCallStatus() != CallLeg::Connected) {
                if (a_leg) {
                    DBG("received Bye in not connected state");
                    cdr->update_internal_reason(DisconnectByORG, "EarlyBye", 500, 0);
                    cdr->update_aleg_reason("EarlyBye", 200);
                    cdr->update_bleg_reason("Cancel", 487);
                } else {
                    DBG("generate reply for early BYE on Bleg and force leg termination");
                    cdr->update_bleg_reason("EarlyBye", 200);
                    dlg->reply(req, 200, "OK");
                    terminateLeg();
                    return;
                }
            } else {
                cdr->update_internal_reason(a_leg ? DisconnectByORG : DisconnectByDST, "Bye", 200, 0);
                cdr->update_bleg_reason("Bye", 200);
            }
        }

        break;
    }

    CallLeg::onBye(req);
}

void SBCCallLeg::onOtherBye(const AmSipRequest &req)
{
    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");
    if (call_ctx && a_leg) {
        if (getCallStatus() != CallLeg::Connected) {
            // avoid considering of bye in not connected state as succ call
            DBG("received OtherBye in not connected state");
            if (call_ctx->cdr) {
                call_ctx->cdr->update_internal_reason(DisconnectByDST, "EarlyBye", 500, 0);
                call_ctx->cdr->update_aleg_reason("Request terminated", 487);
                router.write_cdr(call_ctx->cdr, true);
            }
        }
    }
    CallLeg::onOtherBye(req);
}

void SBCCallLeg::onDtmf(AmDtmfEvent *e)
{
    DBG("received DTMF on %cleg (%i;%i;%i) source:%d", a_leg ? 'A' : 'B', e->event(), e->duration(), e->volume(),
        e->event_id);

    getCtx_void;

    int            rx_proto = 0;
    struct timeval now;

    gettimeofday(&now, nullptr);

    switch (e->event_id) {
    case Dtmf::SOURCE_SIP:    rx_proto = DTMF_RX_MODE_INFO; break;
    case Dtmf::SOURCE_RTP:    rx_proto = DTMF_RX_MODE_RFC2833; break;
    case Dtmf::SOURCE_INBAND: rx_proto = DTMF_RX_MODE_INBAND; break;
    default:                  WARN("unexpected dtmf source: %d. ignore event", e->event_id); return;
    }

    if (!(a_leg ? call_profile.aleg_dtmf_recv_modes & rx_proto : call_profile.bleg_dtmf_recv_modes & rx_proto)) {
        DBG("DTMF event for leg %p rejected", to_void(this));
        e->processed = true;
        // write with zero tx_proto
        with_cdr_for_read cdr->add_dtmf_event(a_leg, e->event(), now, rx_proto, DTMF_TX_MODE_DISABLED);
        return;
    }

    // choose outgoing method
    int send_method = a_leg ? call_profile.bleg_dtmf_send_mode_id : call_profile.aleg_dtmf_send_mode_id;

    with_cdr_for_read cdr->add_dtmf_event(a_leg, e->event(), now, rx_proto, send_method);

    switch (send_method) {
    case DTMF_TX_MODE_DISABLED: DBG("dtmf sending is disabled"); break;
    case DTMF_TX_MODE_RFC2833:
    {
        DBG("send mode RFC2833 choosen for dtmf event for leg %p", to_void(this));
        AmB2BMedia *ms = getMediaSession();
        if (ms) {
            DBG("sending DTMF (%i;%i)", e->event(), e->duration());
            ms->sendDtmf(!a_leg, e->event(), static_cast<unsigned int>(e->duration()), e->volume());
        }
    } break;
    case DTMF_TX_MODE_INFO_DTMF_RELAY:
        DBG("send mode INFO/application/dtmf-relay choosen for dtmf event for leg %p", to_void(this));
        relayEvent(new yeti_dtmf::DtmfInfoSendEventDtmfRelay(e));
        break;
    case DTMF_TX_MODE_INFO_DTMF:
        DBG("send mode INFO/application/dtmf choosen for dtmf event for leg %p", to_void(this));
        relayEvent(new yeti_dtmf::DtmfInfoSendEventDtmf(e));
        break;
    default: ERROR("unsupported dtmf send method %d. stop processing", send_method); break;
    }
}

void SBCCallLeg::updateLocalSdp(AmSdp &sdp, const string &sip_msg_method, unsigned int sip_msg_cseq)
{
    if (sdp.media.empty()) {
        throw InternalException(DC_REPLY_SDP_EMPTY_ANSWER, call_ctx->getOverrideId(a_leg));
    }

    normalizeSDP(sdp);
    anonymizeSDP(sdp);

    // remember transcodable payload IDs
    // if (call_profile.transcoder.isActive()) savePayloadIDs(sdp);
    DBG("updateLocalSdp: transport: %s", transport_p_2_str(sdp.media.begin()->transport).data());
    CallLeg::updateLocalSdp(sdp, sip_msg_method, sip_msg_cseq);
}

void SBCCallLeg::onControlCmd(string &cmd, AmArg &params)
{
    if (cmd == "teardown") {
        if (a_leg) {
            // was for caller:
            DBG("teardown requested from control cmd");
            stopCall("ctrl-cmd");
            // FIXME: don't we want to relay the controll event as well?
        } else {
            // was for callee:
            DBG("relaying teardown control cmd to A leg");
            getCtx_void;
            relayEvent(new SBCControlEvent(cmd, params));
            // FIXME: don't we want to stopCall as well?
        }
        return;
    }
    DBG("ignoring unknown control cmd : '%s'", cmd.c_str());
}


void SBCCallLeg::process(AmEvent *ev)
{
    DBG("%s(%p|%s,leg%s)", FUNC_NAME, to_void(this), getLocalTag().c_str(), a_leg ? "A" : "B");

    if (auto cert_cache_event = dynamic_cast<CertCacheResponseEvent *>(ev)) {
        onCertCacheReply(*cert_cache_event);
        return;
    }

    if (auto http_event = dynamic_cast<HttpPostResponseEvent *>(ev)) {
        onHttpPostResponse(*http_event);
        return;
    }

    if (auto plugin_event = dynamic_cast<AmPluginEvent *>(ev)) {
        DBG("%s plugin_event. name = %s, event_id = %d", FUNC_NAME, plugin_event->name.c_str(), plugin_event->event_id);

        if (plugin_event->name == "timer_timeout") {
            if (onTimerEvent(plugin_event->data.get(0).asInt()))
                return;
        }
    }

    do {
        getCtx_chained


            if (auto pg_event = dynamic_cast<PGEvent *>(ev))
        {
            switch (pg_event->event_id) {
            case PGEvent::Result:
                if (auto e = dynamic_cast<PGResponse *>(pg_event))
                    onPostgresResponse(*e);
                return;
            case PGEvent::ResultError:
                if (auto e = dynamic_cast<PGResponseError *>(pg_event))
                    onPostgresResponseError(*e);
                return;
            case PGEvent::Timeout:
                if (auto e = dynamic_cast<PGTimeout *>(pg_event))
                    onPostgresTimeout(*e);
                return;
            default: break;
            }

            ERROR("unexpected pg event: %d", pg_event->event_id);
            return;
        }

        JsonRpcRequestEvent *jsonrpc_event = dynamic_cast<JsonRpcRequestEvent *>(ev);
        if (jsonrpc_event) {
            onJsonRpcRequest(*jsonrpc_event);
            return;
        }

        RadiusReplyEvent *radius_event = dynamic_cast<RadiusReplyEvent *>(ev);
        if (radius_event) {
            onRadiusReply(*radius_event);
            return;
        }

        if (SipRegistrarResolveResponseEvent *reg_event = dynamic_cast<SipRegistrarResolveResponseEvent *>(ev)) {
            onSipRegistrarResolveResponse(*reg_event);
            return;
        }

        AmRtpTimeoutEvent *rtp_event = dynamic_cast<AmRtpTimeoutEvent *>(ev);
        if (rtp_event) {
            DBG("rtp event id: %d", rtp_event->event_id);
            onRtpTimeoutOverride(*rtp_event);
            return;
        }

        AmSipRequestEvent *request_event = dynamic_cast<AmSipRequestEvent *>(ev);
        if (request_event) {
            AmSipRequest &req = request_event->req;
            DBG("request event method: %s", req.method.c_str());
        }

        AmSipReplyEvent *reply_event = dynamic_cast<AmSipReplyEvent *>(ev);
        if (reply_event) {
            AmSipReply &reply = reply_event->reply;
            DBG("reply event  code: %d, reason:'%s'", reply.code, reply.reason.c_str());
            //! TODO: find appropiate way to avoid hangup in disconnected state
            if (reply.code == 408 && getCallStatus() == CallLeg::Disconnected) {
                DBG("received 408 in disconnected state. a_leg = %d, local_tag: %s", a_leg, getLocalTag().c_str());
                throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
            }
        }

        AmSipRedirect *redirect_event = dynamic_cast<AmSipRedirect *>(ev);
        if (redirect_event) {
            if (call_ctx) {
                with_cdr_for_read cdr->is_redirected = true;
            }
            return;
        }

        SBCControlEvent *sbc_event = dynamic_cast<SBCControlEvent *>(ev);
        if (sbc_event) {
            DBG("sbc event id: %d, cmd: %s", sbc_event->event_id, sbc_event->cmd.c_str());
            onControlEvent(sbc_event);
        }

        B2BEvent *b2b_e = dynamic_cast<B2BEvent *>(ev);
        if (b2b_e) {
            if (b2b_e->event_id == B2BSipReply) {
                B2BSipReplyEvent *b2b_reply_e = dynamic_cast<B2BSipReplyEvent *>(b2b_e);
                if (dlg->checkReply100rel(b2b_reply_e->reply)) {
                    DBG("[%s] reply event (%d %s) postponed by 100rel extension", getLocalTag().c_str(),
                        b2b_reply_e->reply.code, b2b_reply_e->reply.reason.c_str());
                    postponed_replies.emplace(new B2BSipReplyEvent(*b2b_reply_e));
                    return;
                }
            }
            if (b2b_e->event_id == B2BTerminateLeg) {
                DBG("onEvent(%p|%s) terminate leg event", to_void(this), getLocalTag().c_str());
            }
        }

        if (ev->event_id == E_SYSTEM) {
            AmSystemEvent *sys_ev = dynamic_cast<AmSystemEvent *>(ev);
            if (sys_ev) {
                DBG("sys event type: %d", sys_ev->sys_event);
                onSystemEventOverride(sys_ev);
            }
        }

        yeti_dtmf::DtmfInfoSendEvent *dtmf = dynamic_cast<yeti_dtmf::DtmfInfoSendEvent *>(ev);
        if (dtmf) {
            DBG("onEvent dmtf(%d:%d)", dtmf->event(), dtmf->duration());
            dtmf->send(dlg);
            ev->processed = true;
            return;
        }
    } while (0);

    if (a_leg) {
        // was for caller (SBCDialog):
        AmPluginEvent *plugin_event = dynamic_cast<AmPluginEvent *>(ev);
        if (plugin_event && plugin_event->name == "timer_timeout") {
            int timer_id = plugin_event->data.get(0).asInt();
            if (timer_id >= SBC_TIMER_ID_CALL_TIMERS_START && timer_id <= SBC_TIMER_ID_CALL_TIMERS_END) {
                DBG("timer %d timeout, stopping call", timer_id);
                stopCall("timer");
                ev->processed = true;
            }
        }

        SBCCallTimerEvent *ct_event;
        if (ev->event_id == SBCCallTimerEvent_ID && (ct_event = dynamic_cast<SBCCallTimerEvent *>(ev)) != nullptr) {
            switch (m_state) {
            case BB_Connected:
                switch (ct_event->timer_action) {
                case SBCCallTimerEvent::Remove:
                    DBG("removing timer %d on call timer request", ct_event->timer_id);
                    removeTimer(ct_event->timer_id);
                    return;
                case SBCCallTimerEvent::Set:
                    DBG("setting timer %d to %f on call timer request", ct_event->timer_id, ct_event->timeout);
                    setTimer(ct_event->timer_id, ct_event->timeout);
                    return;
                case SBCCallTimerEvent::Reset:
                    DBG("resetting timer %d to %f on call timer request", ct_event->timer_id, ct_event->timeout);
                    removeTimer(ct_event->timer_id);
                    setTimer(ct_event->timer_id, ct_event->timeout);
                    return;
                }
                ERROR("unknown timer_action %d in sbc call timer event", ct_event->timer_action);
                return;
            case BB_Init:
            case BB_Dialing:
                switch (ct_event->timer_action) {
                case SBCCallTimerEvent::Remove: clearCallTimer(ct_event->timer_id); return;
                case SBCCallTimerEvent::Set:
                case SBCCallTimerEvent::Reset:  saveCallTimer(ct_event->timer_id, ct_event->timeout); return;
                }
                ERROR("unknown timer_action %d in sbc call timer event", ct_event->timer_action);
                return;
            default: break;
            }
        }
    }

    SBCControlEvent *ctl_event;
    if (ev->event_id == SBCControlEvent_ID && (ctl_event = dynamic_cast<SBCControlEvent *>(ev)) != nullptr) {
        onControlCmd(ctl_event->cmd, ctl_event->params);
        return;
    }

    SBCOtherLegExceptionEvent *exception_event;
    if (ev->event_id == SBCExceptionEvent_ID &&
        (exception_event = dynamic_cast<SBCOtherLegExceptionEvent *>(ev)) != nullptr)
    {
        onOtherException(exception_event->code, exception_event->reason);
    }

    if (dynamic_cast<ProvisionalReplyConfirmedEvent *>(ev)) {
        if (!postponed_replies.empty()) {
            DBG("we have %ld postponed replies on ProvisionalReplyConfirmedEvent. "
                "process first of them",
                postponed_replies.size());
            // replace ProvisionalReplyConfirmedEvent with B2BSipReplyEvent
            ev = postponed_replies.front().release();
            postponed_replies.pop();
        }
    }

    if (B2BEvent *b2b_e = dynamic_cast<B2BEvent *>(ev)) {
        switch (b2b_e->event_id) {
        case B2BRefer:
        {
            B2BReferEvent *refer = dynamic_cast<B2BReferEvent *>(b2b_e);
            if (refer)
                onOtherRefer(*refer);
            return;
        }
        case B2BNotify:
        {
            B2BNotifyEvent *notify = dynamic_cast<B2BNotifyEvent *>(b2b_e);
            if (notify) {
                sendReferNotify(notify->code, notify->reason);
                // TODO: set timer here for final code
            }
            return;
        }
        default: break;
        }
    }

    CallLeg::process(ev);
}


//////////////////////////////////////////////////////////////////////////////////////////
// was for caller only (SBCDialog)
// FIXME: move the stuff related to CC interface outside of this class?


#define REPLACE_VALS req, app_param, ruri_parser, from_parser, to_parser

void SBCCallLeg::onInvite(const AmSipRequest &req)
{
    DBG("processing initial INVITE %s", req.r_uri.c_str());

    gettimeofday(&call_start_time, nullptr);

    uac_req = req;

    // process Identity headers
    if (yeti.config.identity_enabled && ip_auth_data.require_identity_parsing) {
        static string identity_header_name("identity");
        size_t        start_pos = 0;
        while (start_pos < req.hdrs.length()) {
            size_t name_end, val_begin, val_end, hdr_end;
            if (skip_header(req.hdrs, start_pos, name_end, val_begin, val_end, hdr_end)) {
                ERROR("failed to parse headers: %s", req.hdrs.data());
                AmSipDialog::reply_error(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
                dlg->drop();
                dlg->dropTransactions();
                setStopped();
                return;
            }
            string hdr_name = req.hdrs.substr(start_pos, name_end - start_pos);
            std::transform(hdr_name.begin(), hdr_name.end(), hdr_name.begin(), ::tolower);
            if (hdr_name == identity_header_name) {
                string hdr_value = req.hdrs.substr(val_begin, val_end - val_begin);
                if (hdr_value.find(',') != string::npos) {
                    auto values = explode(hdr_value, ",", false);
                    for (auto const &v : values) {
                        addIdentityHdr(trim(v, " \n"));
                    }
                } else {
                    addIdentityHdr(trim(hdr_value, " \n"));
                }
            }
            start_pos = hdr_end;
        }

        if (awaited_identity_certs.empty())
            onIdentityReady();
    } else {
        onIdentityReady();
    }
}

void SBCCallLeg::addIdentityHdr(const string &header_value)
{
    auto &e = identity_headers.emplace_back();

    e.raw_header_value = header_value;
    e.parsed           = e.identity.parse(header_value);

    if (!e.parsed) {
        yeti.counters.identity_failed_parse.inc();
        string last_error;
        auto   last_errcode = e.identity.get_last_error(last_error);
        ERROR("[%s] failed to parse identity header: '%s', error:%d(%s)", getLocalTag().data(),
              e.raw_header_value.data(), last_errcode, last_error.data());
        return;
    }

    auto &cert_url = e.identity.get_x5u_url();
    if (cert_url.empty()) {
        yeti.counters.identity_failed_parse.inc();
        ERROR("[%s] empty x5u in identity header: '%s'", getLocalTag().data(), e.raw_header_value.data());
        return;
    }

    if (!yeti.cert_cache.checkAndFetch(cert_url, getLocalTag())) {
        DBG("awaited_identity_certs add '%s'", cert_url.data());
        awaited_identity_certs.emplace(cert_url);
    } else {
        DBG("cert for '%s' has already in cache or not available", cert_url.data());
    }
}

void SBCCallLeg::onIdentityReady()
{
    AmArg *identity_data_ptr = nullptr;
    if (yeti.config.identity_enabled) {
        string error_reason;
        identity_data.assertArray();
        // verify parsed identity headers
        for (auto &e : identity_headers) {
            identity_data.push(AmArg());
            AmArg &a = identity_data.back();

            a["parsed"] = e.parsed;

            if (!e.parsed) {
                a["parsed"]       = false;
                a["error_code"]   = e.identity.get_last_error(error_reason);
                a["error_reason"] = error_reason;
                a["verified"]     = false;
                a["raw"]          = e.raw_header_value;
                continue;
            }

            a["header"]  = e.identity.get_header();
            a["payload"] = e.identity.get_payload();

            bool cert_is_valid;
            auto key(yeti.cert_cache.getPubKey(e.identity.get_x5u_url(), a, cert_is_valid));
            if (key.get()) {
                if (cert_is_valid) {
                    bool verified = e.identity.verify(key.get(), yeti.cert_cache.getExpires());
                    if (!verified) {
                        auto error_code = e.identity.get_last_error(error_reason);
                        switch (error_code) {
                        case ERR_EXPIRE_TIMEOUT: yeti.counters.identity_failed_verify_expired.inc(); break;
                        case ERR_VERIFICATION:   yeti.counters.identity_failed_verify_signature.inc(); break;
                        }
                        a["error_code"]   = error_code;
                        a["error_reason"] = error_reason;
                        ERROR("[%s] identity '%s' verification failed: %d/%s", getLocalTag().data(),
                              e.raw_header_value.data(), error_code, error_reason.data());
                    } else {
                        yeti.counters.identity_success.inc();
                    }
                    a["verified"] = verified;
                } else {
                    yeti.counters.identity_failed_cert_invalid.inc();
                    a["error_code"]   = -1;
                    a["error_reason"] = "certificate is not valid";
                    a["verified"]     = false;
                }
            } else if (!yeti.cert_cache.isTrustedRepository(e.identity.get_x5u_url())) {
                yeti.counters.identity_failed_x5u_not_trusted.inc();
                a["error_code"]   = -1;
                a["error_reason"] = "x5u is not in trusted repositories";
                a["verified"]     = false;
            } else {
                yeti.counters.identity_failed_cert_not_available.inc();
                a["error_code"]   = -1;
                a["error_reason"] = "certificate is not available";
                a["verified"]     = false;
            }
        } // for(auto &e : identity_headers)

        // DBG("identity_json: %s", arg2json(identity_data).data());
        identity_data_ptr = &identity_data;
    }

    call_ctx = new CallCtx(router);
    call_ctx->references++;

    gettimeofday(&profile_request_start_time, nullptr);
    try {
        router.db_async_get_profiles(getLocalTag(), uac_req, auth_result_id, identity_data_ptr);
    } catch (GetProfileException &e) {
        DBG("GetProfile exception on %s thread: fatal = %d code  = '%d'", e.fatal, e.code);
        ERROR("SQL cant get profiles. Drop request");

        call_ctx->profiles.clear();
        call_ctx->profiles.emplace_back();
        call_ctx->profiles.back().disconnect_code_id = e.code;
        call_ctx->SQLexception                       = true;

        onProfilesReady();
    }
}

void SBCCallLeg::onRoutingReady()
{
    /*call_profile.sst_aleg_enabled = ctx.replaceParameters(
        call_profile.sst_aleg_enabled,
        "enable_aleg_session_timer", aleg_modified_req);

    call_profile.sst_enabled = ctx.replaceParameters(
        call_profile.sst_enabled,
        "enable_session_timer", aleg_modified_req);*/

    if (call_profile.sst_aleg_enabled) {
        call_profile.eval_sst_config(ctx, aleg_modified_req, call_profile.sst_a_cfg);
        if (applySSTCfg(call_profile.sst_a_cfg, &aleg_modified_req) < 0) {
            ERROR("%s SST apply error", getLocalTag().data());
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
    }

    unique_ptr<AmSipDialog> callee_dlg(new AmSipDialog());

    if (!call_profile.evaluate_routing(ctx, aleg_modified_req, *callee_dlg)) {
        ERROR("%s call profile routing evaluation failed", getLocalTag().data());
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    if (!call_profile.evaluate(ctx, aleg_modified_req)) {
        ERROR("%s call profile evaluation failed", getLocalTag().data());
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    /* moved to SBCCallProfile::evaluate_routing()
        AmUriParser uac_ruri;
        uac_ruri.uri = uac_req.r_uri;
        if(!uac_ruri.parse_uri()) {
            DBG("Error parsing request R-URI '%s'",uac_ruri.uri.c_str());
            throw AmSession::Exception(400,"Failed to parse R-URI");
        }

        ruri = call_profile.ruri.empty() ? uac_req.r_uri : call_profile.ruri;
        ctx.ruri_parser.uri = ruri;
        if(!ctx.ruri_parser.parse_uri()) {
            ERROR("Error parsing R-URI '%s'", ruri.data());
            throw AmSession::Exception(500,SIP_REPLY_SERVER_INTERNAL_ERROR);
        }

        if(!call_profile.ruri_host.empty()) {
            ctx.ruri_parser.uri_port.clear();
            ctx.ruri_parser.uri_host = call_profile.ruri_host;
            ruri = ctx.ruri_parser.uri_str();
        }
    */
    ruri = ctx.ruri_parser.uri; // set by SBCCallProfile::evaluate_routing()
    from = call_profile.from.empty() ? aleg_modified_req.from : call_profile.from;
    to   = call_profile.to.empty() ? aleg_modified_req.to : call_profile.to;

    AmUriParser from_uri, to_uri;
    if (!from_uri.parse_nameaddr(from)) {
        DBG("Error parsing From-URI '%s'", from.c_str());
        throw AmSession::Exception(400, "Failed to parse From-URI");
    }

    if (!to_uri.parse_nameaddr(to)) {
        DBG("Error parsing To-URI '%s'", to.c_str());
        throw AmSession::Exception(400, "Failed to parse To-URI");
    }

    if (to_uri.uri_host.empty()) {
        to_uri.uri_host = ctx.ruri_parser.uri_host;
        WARN("onRoutingReady: empty To domain. set to RURI domain: '%s'", ctx.ruri_parser.uri_host.data());
    }

    from = from_uri.nameaddr_str();
    to   = to_uri.nameaddr_str();

    applyAProfile();
    call_profile.apply_a_routing(ctx, aleg_modified_req, *dlg);

    m_state = BB_Dialing;

    // prepare request to relay to the B leg(s)

    if (a_leg && call_profile.keep_vias)
        modified_req.hdrs = modified_req.vias + modified_req.hdrs;

    est_invite_cseq = uac_req.cseq;

    removeHeader(modified_req.hdrs, PARAM_HDR);
    removeHeader(modified_req.hdrs, "P-App-Name");

    if (call_profile.sst_enabled) {
        removeHeader(modified_req.hdrs, SIP_HDR_SESSION_EXPIRES);
        removeHeader(modified_req.hdrs, SIP_HDR_MIN_SE);
    }

    size_t start_pos = 0;
    while (start_pos < call_profile.append_headers.length()) {
        int    res;
        size_t name_end, val_begin, val_end, hdr_end;
        if ((res = skip_header(call_profile.append_headers, start_pos, name_end, val_begin, val_end, hdr_end)) != 0) {
            ERROR("%s skip_header for '%s' pos: %ld, return %d", getLocalTag().data(),
                  call_profile.append_headers.c_str(), start_pos, res);
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
        string hdr_name = call_profile.append_headers.substr(start_pos, name_end - start_pos);
        while (!getHeader(modified_req.hdrs, hdr_name).empty()) {
            removeHeader(modified_req.hdrs, hdr_name);
        }
        start_pos = hdr_end;
    }

    inplaceHeaderPatternFilter(modified_req.hdrs, call_profile.headerfilter_a2b);

    if (call_profile.append_headers.size() > 2) {
        string append_headers = call_profile.append_headers;
        assertEndCRLF(append_headers);
        modified_req.hdrs += append_headers;
    }

#undef REPLACE_VALS

    DBG("SBC: connecting to '%s'", ruri.c_str());
    DBG("     From:  '%s'", from.c_str());
    DBG("     To:  '%s'", to.c_str());

    // we evaluated the settings, now we can initialize internals (like RTP relay)
    // we have to use original request (not the altered one) because for example
    // codecs filtered out might be used in direction to caller
    CallLeg::onInvite(aleg_modified_req);

    if (getCallStatus() == Disconnected) {
        // no CC module connected a callee yet
        // connect to the B leg(s) using modified request
        connectCallee(to, ruri, from, aleg_modified_req, modified_req, callee_dlg.release());
    }
}

void SBCCallLeg::onFailure()
{
    DBG("%s(%p,leg%s)", FUNC_NAME, this, a_leg ? "A" : "B");

    static int    code   = 503;
    static string reason = "Generic Failure";

    if (a_leg) {
        if (call_ctx) {
            with_cdr_for_read
            {
                cdr->update_internal_reason(DisconnectByTS, reason, code, 0);
                if (cdr->local_tag.empty()) {
                    cdr->update_init_aleg(getLocalTag(), global_tag, getCallID());
                }
            }
        }
    }

    relayEvent(new SBCOtherLegExceptionEvent(code, reason));
    terminateLeg();
}

void SBCCallLeg::onInviteException(int code, string reason, bool no_reply)
{
    DBG("%s(%p,leg%s) %d:'%s' no_reply = %d", FUNC_NAME, to_void(this), a_leg ? "A" : "B", code, reason.c_str(),
        no_reply);

    getCtx_void;

    with_cdr_for_read
    {
        cdr->disconnect_initiator = DisconnectByTS;
        if (cdr->disconnect_internal_code == 0) { // update only if not previously was setted
            cdr->disconnect_internal_code   = code;
            cdr->disconnect_internal_reason = reason;
        }
        if (!no_reply) {
            cdr->disconnect_rewrited_code   = code;
            cdr->disconnect_rewrited_reason = reason;
        }
    }
}

bool SBCCallLeg::onException(int code, const string &reason) noexcept
{
    DBG("%s(%p,leg%s) %d:'%s'", FUNC_NAME, to_void(this), a_leg ? "A" : "B", code, reason.c_str());

    do {
        if (!call_ctx)
            return false;
        with_cdr_for_read
        {
            cdr->update_internal_reason(DisconnectByTS, reason, static_cast<unsigned int>(code), 0);
            if (!a_leg) {
                switch (dlg->getStatus()) {
                case AmBasicSipDialog::Connected:
                case AmBasicSipDialog::Disconnecting: cdr->update_bleg_reason("Bye", 200); break;
                case AmBasicSipDialog::Early:         cdr->update_bleg_reason("Request terminated", 487); break;
                default:                              break;
                }
            } else {
                switch (dlg->getStatus()) {
                case AmBasicSipDialog::Connected:
                case AmBasicSipDialog::Disconnecting: cdr->update_aleg_reason("Bye", 200); break;
                case AmBasicSipDialog::Early:         cdr->update_aleg_reason("Request terminated", 487); break;
                default:                              break;
                }
            }
        }
    } while (false);

    if (a_leg && Disconnected == getCallStatus()) {
        if (auto req = dlg->getUASPendingInv(); req) {
            dlg->reply(*req, code, reason);
        }
    }

    relayEvent(new SBCOtherLegExceptionEvent(code, reason));
    terminateLeg();
    return false; // stop processing
}

void SBCCallLeg::onOtherException(int code, const string &reason) noexcept
{
    DBG("%s(%p,leg%s) %d:'%s'", FUNC_NAME, to_void(this), a_leg ? "A" : "B", code, reason.c_str());

    do {
        getCtx_void with_cdr_for_read
        {
            if (!a_leg) {
                switch (dlg->getStatus()) {
                case AmBasicSipDialog::Connected:
                case AmBasicSipDialog::Disconnecting: cdr->update_bleg_reason("Bye", 200); break;
                case AmBasicSipDialog::Early:         cdr->update_bleg_reason("Request terminated", 487); break;
                default:                              break;
                }
            } else {
                switch (dlg->getStatus()) {
                case AmBasicSipDialog::Connected:
                case AmBasicSipDialog::Disconnecting: cdr->update_aleg_reason("Bye", 200); break;
                case AmBasicSipDialog::Early:         cdr->update_aleg_reason("Request terminated", 487); break;
                default:                              break;
                }
            }
        }
    } while (false);

    terminateLeg();
    postEvent(new AmEvent(0)); // force wakeup
}

void SBCCallLeg::onEarlyEventException(unsigned int code, const string &reason)
{
    setStopped();
    onInviteException(static_cast<int>(code), reason, false);
    if (code < 300) {
        ERROR("%i is not final code. replace it with 500", code);
        code = 500;
    }
    dlg->reply(uac_req, code, reason);
}

void SBCCallLeg::normalizeSdpVersion(uint64_t &sdp_session_version_in, unsigned int cseq, bool offer)
{
    auto &sdp_session_last_cseq = offer ? sdp_session_offer_last_cseq : sdp_session_answer_last_cseq;
    if (has_sdp_session_version) {
        if (sdp_session_last_cseq != cseq) {
            sdp_session_last_cseq = cseq;
            sdp_session_version++;
        }
    } else {
        sdp_session_last_cseq   = cseq;
        sdp_session_version     = sdp_session_version_in;
        has_sdp_session_version = true;
    }

    DBG("%s[%p]leg%s(%lu, %u,%d) -> %u", FUNC_NAME, this, a_leg ? "A" : "B", sdp_session_version_in, cseq, offer,
        sdp_session_version);

    sdp_session_version_in = sdp_session_version;
}

void SBCCallLeg::connectCallee(const string &remote_party, const string &remote_uri, const string &from,
                               const AmSipRequest &, const AmSipRequest &invite, AmSipDialog *p_dlg)
{
    with_cdr_for_read
    {
        cdr->update_with_bleg_sip_request(invite);
    }

    SBCCallLeg *callee_session = SBCFactory::instance()->getCallLegCreator()->create(this, p_dlg);

    callee_session->setLocalParty(from, from);
    callee_session->setRemoteParty(remote_party, remote_uri);
    callee_session->dlg->setAllowedMethods(yeti.config.allowed_methods);
    callee_session->dlg->setMaxForwards(invite.max_forwards);

    if (!callee_session->a_leg)
        callee_session->applyBProfile();

    DBG("Created B2BUA callee leg, From: %s", from.c_str());

    // FIXME: inconsistent with other filtering stuff - here goes the INVITE
    // already filtered so need not to be catched (can not) in relayEvent because
    // it is sent other way
    addCallee(callee_session, invite);

    // we could start in SIP relay mode from the beginning if only one B leg, but
    // serial fork might mess it
    // set_sip_relay_only(true);
}

void SBCCallLeg::onCallConnected(const AmSipReply &)
{
    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");

    {
        if (call_ctx) {
            if (!call_ctx->transfer_intermediate_state) {
                with_cdr_for_read
                {
                    if (a_leg) {
                        cdr->update_with_action(Connect);
                    } else {
                        cdr->update_with_action(BlegConnect);
                    }
                    radius_accounting_start(this, *cdr, call_profile);
                    if (a_leg) {
                        httpCallConnectedHook();
                    }
                    radius_accounting_start_post_event_set_timers(this, call_profile);
                }
            } else if (!a_leg) {
                // we got final positive reply for Bleg. clear xfer intermediate state
                call_ctx->transfer_intermediate_state = false;
            }
        }
    }

    if (a_leg) { // FIXME: really?
        m_state = BB_Connected;
        if (!startCallTimers())
            return;
    }
}

void SBCCallLeg::onStop()
{
    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");

    if (a_leg && m_state == BB_Connected) { // m_state might be valid for A leg only
        stopCallTimers();
    }

    m_state = BB_Teardown;
}

void SBCCallLeg::saveCallTimer(int timer, double timeout)
{
    call_timers[timer] = timeout;
}

void SBCCallLeg::clearCallTimer(int timer)
{
    call_timers.erase(timer);
}

void SBCCallLeg::clearCallTimers()
{
    call_timers.clear();
}

/** @return whether successful */
bool SBCCallLeg::startCallTimers()
{
    for (map<int, double>::iterator it = call_timers.begin(); it != call_timers.end(); it++) {
        DBG("SBC: starting call timer %i of %f seconds", it->first, it->second);
        setTimer(it->first, it->second);
    }

    return true;
}

void SBCCallLeg::stopCallTimers()
{
    for (map<int, double>::iterator it = call_timers.begin(); it != call_timers.end(); it++) {
        DBG("SBC: removing call timer %i", it->first);
        removeTimer(it->first);
    }
}

void SBCCallLeg::onCallStatusChange(const StatusChangeCause &cause)
{
    string reason;

    SBCCallLeg::CallStatus status                   = getCallStatus();
    int                    internal_disconnect_code = 0;

    DBG("Yeti::onStateChange(%p|%s) a_leg = %d", to_void(this), getLocalTag().c_str(), a_leg);

    {
        switch (status) {
        case CallLeg::Ringing:
        {
            if (!a_leg) {
                if (call_profile.ringing_timeout > 0) {
                    setTimer(YETI_RINGING_TIMEOUT_TIMER, call_profile.ringing_timeout);
                }
            } else {
                if (call_profile.fake_ringing_timeout)
                    removeTimer(YETI_FAKE_RINGING_TIMER);

                if (call_profile.force_one_way_early_media && call_ctx) {
                    DBG("force one-way audio for early media (mute legB)");
                    AmB2BMedia *m = getMediaSession();
                    if (m) {
                        call_ctx->bleg_early_media_muted = true;
                        m->mute(false);
                    }
                }
            }
        } break;
        case CallLeg::Connected:
            if (!a_leg) {
                removeTimer(YETI_RINGING_TIMEOUT_TIMER);
            } else {
                if (call_profile.fake_ringing_timeout)
                    removeTimer(YETI_FAKE_RINGING_TIMER);

                if (call_ctx && call_ctx->bleg_early_media_muted) {
                    AmB2BMedia *m = getMediaSession();
                    if (m) {
                        m->unmute(false);
                    }
                }
            }
            break;
        case CallLeg::Disconnected:
            removeTimer(YETI_RADIUS_INTERIM_TIMER);
            if (a_leg && call_profile.fake_ringing_timeout) {
                removeTimer(YETI_FAKE_RINGING_TIMER);
            }
            break;
        default: break;
        }
    }

    getCtx_void;

    switch (cause.reason) {
    case CallLeg::StatusChangeCause::SipReply:
        if (cause.param.reply != nullptr) {
            reason = "SipReply. code = " + int2str(cause.param.reply->code);
            switch (cause.param.reply->code) {
            case 408:
                if (cause.param.reply->local_reply) {
                    internal_disconnect_code = DC_TRANSACTION_TIMEOUT;
                }
                break;
            case 487:
                if (call_ctx->isRingingTimeout()) {
                    internal_disconnect_code = DC_RINGING_TIMEOUT;
                }
                break;
            }
        } else
            reason = "SipReply. empty reply";
        break;
    case CallLeg::StatusChangeCause::SipRequest:
        if (cause.param.request != nullptr) {
            reason = "SipRequest. method = " + cause.param.request->method;
        } else
            reason = "SipRequest. empty request";
        break;
    case CallLeg::StatusChangeCause::Canceled: reason = "Canceled"; break;
    case CallLeg::StatusChangeCause::NoAck:
        reason                   = "NoAck";
        internal_disconnect_code = DC_NO_ACK;
        break;
    case CallLeg::StatusChangeCause::NoPrack:
        reason                   = "NoPrack";
        internal_disconnect_code = DC_NO_PRACK;
        break;
    case CallLeg::StatusChangeCause::RtpTimeout: reason = "RtpTimeout"; break;
    case CallLeg::StatusChangeCause::SessionTimeout:
        reason                   = "SessionTimeout";
        internal_disconnect_code = DC_SESSION_TIMEOUT;
        break;
    case CallLeg::StatusChangeCause::InternalError:
        reason                   = "InternalError";
        internal_disconnect_code = DC_INTERNAL_ERROR;
        break;
    case CallLeg::StatusChangeCause::Other: break;
    }

    if (status == CallLeg::Disconnected) {
        with_cdr_for_read
        {
            if (internal_disconnect_code) {
                unsigned int internal_code, response_code;
                string       internal_reason, response_reason;

                CodesTranslator::instance()->translate_db_code(static_cast<unsigned int>(internal_disconnect_code),
                                                               internal_code, internal_reason, response_code,
                                                               response_reason, call_ctx->getOverrideId(a_leg));
                cdr->update_internal_reason(DisconnectByTS, internal_reason, internal_code, internal_disconnect_code);
            }
            radius_accounting_stop(this, *cdr);
            radius_accounting_stop_post_event(this);
            if (a_leg) {
                httpCallDisconnectedHook();
            }
        }
    }

    DBG("%s(%p,leg%s,state = %s, cause = %s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B", callStatus2str(status),
        reason.c_str());
}

void SBCCallLeg::onBLegRefused(AmSipReply &reply)
{
    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");

    if (!a_leg)
        return;

    if (getOtherId().size() && reply.from_tag != getOtherId()) {
        DBG("ignore onBLegRefused not from current peer");
        return;
    }

    removeTimer(YETI_FAKE_RINGING_TIMER);
    clearCallTimer(YETI_CALL_DURATION_TIMER);

    if (!call_ctx)
        return;

    Cdr &cdr = *call_ctx->cdr.get();

    cdr.update_with_bleg_sip_reply(reply);
    cdr.update_bleg_reason(reply.reason, static_cast<int>(reply.code));

    // save original destination reply code for stop_hunting lookup
    auto destination_reply_code = reply.code;

    CodesTranslator *ct = CodesTranslator::instance();
    unsigned int     intermediate_code;
    string           intermediate_reason;

    ct->rewrite_response(reply.code, reply.reason, intermediate_code, intermediate_reason,
                         call_ctx->getOverrideId(false)); // bleg_override_id
    ct->rewrite_response(intermediate_code, intermediate_reason, reply.code, reply.reason,
                         call_ctx->getOverrideId(true)); // aleg_override_id
    cdr.update_internal_reason(reply.local_reply ? DisconnectByTS : DisconnectByDST, intermediate_reason,
                               intermediate_code, 0);
    cdr.update_aleg_reason(reply.reason, static_cast<int>(reply.code));

    if (ct->stop_hunting(destination_reply_code, call_ctx->getOverrideId(false))) {
        DBG("stop hunting");
        return;
    }

    DBG("continue hunting");
    // put current resources
    rctl.put(call_ctx->getResourceHandler(*call_ctx->getCurrentProfile()));

    if (call_ctx->initial_invite == nullptr) {
        ERROR("%s() intial_invite == NULL", FUNC_NAME);
        return;
    }

    if (!chooseNextProfile()) {
        DBG("%s() no new profile, just finish as usual", FUNC_NAME);
        return;
    }

    auto profile = call_ctx->getCurrentProfile();
    if (profile->time_limit) {
        DBG("%s() save timer %d with timeout %d", FUNC_NAME, YETI_CALL_DURATION_TIMER, profile->time_limit);
        saveCallTimer(YETI_CALL_DURATION_TIMER, profile->time_limit);
    }

    DBG("%s() has new profile, so create new callee", FUNC_NAME);
    AmSipRequest req = *call_ctx->initial_invite;

    try {
        connectCalleeRequest(req);
    } catch (InternalException &e) {
        if (call_ctx && call_ctx->cdr) {
            call_ctx->cdr->update_internal_reason(DisconnectByTS, e.internal_reason, e.internal_code, e.icode);
        }
        throw AmSession::Exception(static_cast<int>(e.response_code), e.response_reason);
    }
}

void SBCCallLeg::onCallFailed(CallFailureReason, const AmSipReply *) {}

bool SBCCallLeg::onBeforeRTPRelay(AmRtpPacket *p, sockaddr_storage *)
{
    if (rtp_relay_rate_limit.get() && rtp_relay_rate_limit->limit(p->getBufferSize()))
        return false; // drop
    return true;      // relay
}

void SBCCallLeg::onAfterRTPRelay(AmRtpPacket *p, sockaddr_storage *)
{
    for (list<::atomic_int *>::iterator it = rtp_pegs.begin(); it != rtp_pegs.end(); ++it) {
        (*it)->inc(p->getBufferSize());
    }
}

void SBCCallLeg::onRTPStreamDestroy(AmRtpStream *stream)
{
    if (gettid() != thread_id) {
        ERROR("called from the thread(%d) while owned by the thread(%d). ignore", gettid(), thread_id);
        log_demangled_stacktrace(L_ERR);
        return;
    }

    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");

    if (!call_ctx)
        return;
    AmRtpStream::MediaStats stats;
    stream->getMediaStats(stats);
    if (!timerisset(&stats.time_start))
        return;

    with_cdr_for_read
    {
        if (cdr->writed)
            return;
        if (a_leg) {
            if (cdr->aleg_media_stats.size() < MAX_STREAM_STATS)
                cdr->aleg_media_stats.push_back(stats);
        } else {
            if (cdr->bleg_media_stats.size() < MAX_STREAM_STATS)
                cdr->bleg_media_stats.push_back(stats);
        }
    }
}

bool SBCCallLeg::reinvite(const AmSdp &sdp, unsigned &request_cseq)
{
    request_cseq = 0;

    AmMimeBody  body;
    AmMimeBody *sdp_body = body.addPart(SIP_APPLICATION_SDP);
    if (!sdp_body)
        return false;

    string body_str;
    sdp.print(body_str);
    sdp_body->parse(SIP_APPLICATION_SDP, reinterpret_cast<const unsigned char *>(body_str.c_str()),
                    static_cast<unsigned int>(body_str.length()));

    if (dlg->reinvite("", &body, SIP_FLAGS_VERBATIM) != 0)
        return false;
    request_cseq = dlg->cseq - 1;
    return true;
}

void SBCCallLeg::holdRequested()
{
    TRACE("%s: hold requested\n", getLocalTag().c_str());
    CallLeg::holdRequested();
}

void SBCCallLeg::holdAccepted()
{
    TRACE("%s: hold accepted\n", getLocalTag().c_str());
    CallLeg::holdAccepted();
}

void SBCCallLeg::holdRejected()
{
    TRACE("%s: hold rejected\n", getLocalTag().c_str());
    CallLeg::holdRejected();
}

void SBCCallLeg::resumeRequested()
{
    TRACE("%s: resume requested\n", getLocalTag().c_str());
    CallLeg::resumeRequested();
}

void SBCCallLeg::resumeAccepted()
{
    TRACE("%s: resume accepted\n", getLocalTag().c_str());
    CallLeg::resumeAccepted();
}

void SBCCallLeg::resumeRejected()
{
    TRACE("%s: resume rejected\n", getLocalTag().c_str());
    CallLeg::resumeRejected();
}

static void zerifySdpConnectionAddress(SdpConnection &c)
{
    static const string zero_ipv4("0.0.0.0");
    static const string zero_ipv6("::");

    if (c.address.empty())
        return;

    switch (c.addrType) {
    case AT_V4: c.address = zero_ipv4; break;
    case AT_V6: c.address = zero_ipv6; break;
    default:    break;
    }
}

static void alterHoldRequest(AmSdp &sdp, SBCCallProfile::HoldSettings::Activity a,
                             bool zerify_connection_address = false)
{
    if (zerify_connection_address)
        zerifySdpConnectionAddress(sdp.conn);

    for (auto &m : sdp.media) {
        if (zerify_connection_address)
            zerifySdpConnectionAddress(m.conn);

        m.recv = (a == SBCCallProfile::HoldSettings::sendrecv || a == SBCCallProfile::HoldSettings::recvonly);

        m.send = (a == SBCCallProfile::HoldSettings::sendrecv || a == SBCCallProfile::HoldSettings::sendonly);
    }
}

void SBCCallLeg::alterHoldRequestImpl(AmSdp &sdp)
{
    ::alterHoldRequest(sdp, call_profile.hold_settings.activity(a_leg),
                       call_profile.hold_settings.mark_zero_connection(a_leg));
}

void SBCCallLeg::alterHoldRequest(AmSdp &sdp)
{
    TRACE("altering B2B hold request(%s, %s, %s)\n",
          call_profile.hold_settings.alter_b2b(a_leg) ? "alter B2B" : "do not alter B2B",
          call_profile.hold_settings.mark_zero_connection(a_leg) ? "0.0.0.0" : "own IP",
          call_profile.hold_settings.activity_str(a_leg).c_str());

    if (!call_profile.hold_settings.alter_b2b(a_leg))
        return;

    alterHoldRequestImpl(sdp);
}

void SBCCallLeg::processLocalRequest(AmSipRequest &req)
{
    DBG("%s() local_tag = %s", FUNC_NAME, getLocalTag().c_str());
    updateLocalBody(req.body, req.method, req.cseq);
    dlg->reply(req, 200, "OK", &req.body, "", SIP_FLAGS_VERBATIM);
}

void SBCCallLeg::createHoldRequest(AmSdp &sdp)
{
    // hack: we need to have other side SDP (if the stream is hold already
    // it should be marked as inactive)
    // FIXME: fix SDP versioning! (remember generated versions and increase the
    // version number in every SDP passing through?)

    AmMimeBody *s = established_body.hasContentType(SIP_APPLICATION_SDP);
    if (s)
        sdp.parse(reinterpret_cast<const char *>(s->getPayload()));
    if (sdp.media.empty()) {
        // established SDP is not valid! generate complete fake
        sdp.version       = 0;
        sdp.origin.user   = AmConfig.sdp_origin;
        sdp.sessionName   = AmConfig.sdp_session_name;
        sdp.conn.network  = NT_IN;
        sdp.conn.addrType = AT_V4;
        sdp.conn.address  = "0.0.0.0";

        sdp.media.push_back(SdpMedia());
        SdpMedia &m = sdp.media.back();
        m.type      = MT_AUDIO;
        m.transport = TP_RTPAVP;
        m.send      = false;
        m.recv      = false;
        m.payloads.push_back(SdpPayload(0));
    }

    AmB2BMedia *ms = getMediaSession();
    if (ms)
        ms->replaceOffer(sdp, a_leg);

    alterHoldRequestImpl(sdp);
}

void SBCCallLeg::setMediaSession(AmB2BMedia *new_session)
{
    if (new_session) {
        if (call_profile.log_rtp && !memory_logger_enabled) {
            new_session->setRtpLogger(logger);
        } else {
            new_session->setRtpLogger(nullptr);
        }

        if (a_leg) {
            if (call_profile.aleg_sensor_level_id & LOG_RTP_MASK) {
                new_session->setRtpASensor(sensor);
            } else {
                new_session->setRtpASensor(nullptr);
            }
        } else {
            if (call_profile.bleg_sensor_level_id & LOG_RTP_MASK) {
                new_session->setRtpBSensor(sensor);
            } else {
                new_session->setRtpBSensor(nullptr);
            }
        }
    }
    CallLeg::setMediaSession(new_session);
}

bool SBCCallLeg::openLogger(const std::string &path)
{
    file_msg_logger *log = new pcap_logger();

    if (log->open(path.c_str()) != 0) {
        // open error
        delete log;
        return false;
    }

    // opened successfully
    setLogger(log);
    return true;
}

void SBCCallLeg::setLogger(msg_logger *_logger)
{
    if (logger)
        dec_ref(logger); // release the old one

    logger = _logger;
    if (logger)
        inc_ref(logger);

    if (call_profile.log_sip || memory_logger_enabled)
        dlg->setMsgLogger(logger);
    else
        dlg->setMsgLogger(nullptr);

    AmB2BMedia *m = getMediaSession();
    if (m) {
        if (call_profile.log_rtp && !memory_logger_enabled)
            m->setRtpLogger(logger);
        else
            m->setRtpLogger(nullptr);
    }
}

void SBCCallLeg::setSensor(msg_sensor *_sensor)
{
    DBG3("SBCCallLeg[%p]: %cleg. change sensor to %p", to_void(this), a_leg ? 'A' : 'B', to_void(_sensor));
    if (sensor)
        dec_ref(sensor);
    sensor = _sensor;
    if (sensor)
        inc_ref(sensor);

    if ((a_leg && (call_profile.aleg_sensor_level_id & LOG_SIP_MASK)) ||
        (!a_leg && (call_profile.bleg_sensor_level_id & LOG_SIP_MASK)))
    {
        dlg->setMsgSensor(sensor);
    } else {
        dlg->setMsgSensor(nullptr);
    }

    AmB2BMedia *m = getMediaSession();
    if (m) {
        if (a_leg) {
            if (call_profile.aleg_sensor_level_id & LOG_RTP_MASK)
                m->setRtpASensor(sensor);
            else
                m->setRtpASensor(nullptr);
        } else {
            if (call_profile.bleg_sensor_level_id & LOG_RTP_MASK)
                m->setRtpBSensor(sensor);
            else
                m->setRtpBSensor(nullptr);
        }
    } else {
        DBG3("SBCCallLeg: no media session");
    }
}

void SBCCallLeg::computeRelayMask(const SdpMedia &m, bool &enable, PayloadMask &mask, PayloadRelayMap &map)
{
    if (call_profile.force_transcoding) {
        enable = false;
        mask.clear();
        map.clear();
        return;
    }

    CallLeg::computeRelayMask(m, enable, mask, map);

    if (call_profile.force_relay_CN) {
        mask.set(COMFORT_NOISE_PAYLOAD_TYPE);
        TRACE("mark payload 13(CN) for relay");
    }
}

int SBCCallLeg::onSdpCompleted(const AmSdp &local, const AmSdp &remote, bool sdp_offer_owner)
{
    DBG("%s(%p,leg%s)", FUNC_NAME, to_void(this), a_leg ? "A" : "B");

    DBG("rtp_relay_mode = %d", rtp_relay_mode);
    if (rtp_relay_mode == RTP_Direct)
        return 0;

    AmSdp offer(local), answer(remote);

    const SqlCallProfile *sql_call_profile = call_ctx->getCurrentProfile();
    if (sql_call_profile) {
        cutNoAudioStreams(offer, sql_call_profile->filter_noaudio_streams);
        cutNoAudioStreams(answer, sql_call_profile->filter_noaudio_streams);
    }

    dump_SdpMedia(offer.media, "offer");
    dump_SdpMedia(answer.media, "answer");

    int ret = CallLeg::onSdpCompleted(offer, answer, sdp_offer_owner);

    if (0 == ret) {
        with_cdr_for_read
        {
            cdr->setSdpCompleted(a_leg);
        }
    }

    if (!a_leg)
        return ret;

    AmB2BMedia *m = getMediaSession();
    if (!m)
        return ret;

    m->updateStreams(false /* recompute relay and other parameters in direction A -> B*/, this, sdp_offer_owner);

    // disable RTP timeout monitoring for early media
    m->setMonitorRtpTimeout(AmBasicSipDialog::Connected == dlg->getStatus());

    return ret;
}

bool SBCCallLeg::getSdpOffer(AmSdp &offer)
{
    DBG("%s(%p)", FUNC_NAME, to_void(this));

    if (!call_ctx) {
        DBG("getSdpOffer[%s] missed call context", getLocalTag().c_str());
        return CallLeg::getSdpOffer(offer);
    }

    AmB2BMedia *m = getMediaSession();
    if (!m) {
        DBG("getSdpOffer[%s] missed media session", getLocalTag().c_str());
        return CallLeg::getSdpOffer(offer);
    }
    if (!m->haveLocalSdp(a_leg)) {
        DBG("getSdpOffer[%s] have no local sdp", getLocalTag().c_str());
        return CallLeg::getSdpOffer(offer);
    }

    const AmSdp &local_sdp = m->getLocalSdp(a_leg);
    if (a_leg || getCallStatus() == Connected) {
        DBG("use last offer from dialog as offer for legA and connected legB");
        offer = local_sdp;
    } else {
        DBG("provide saved initial offer for connecting legB");
        offer          = call_ctx->bleg_initial_offer;
        auto addr_type = dlg->getOutboundAddrType();
        m->replaceConnectionAddress(offer, a_leg, addr_type);
    }

    offer.origin.sessV = local_sdp.origin.sessV + 1; // increase session version. rfc4566 5.2 <sess-version>
    return true;
}

void SBCCallLeg::b2bInitial1xx(AmSipReply &reply, bool forward)
{
    if (a_leg) {
        if (reply.code == 100) {
            if (call_profile.fake_ringing_timeout) {
                setTimer(YETI_FAKE_RINGING_TIMER, call_profile.fake_ringing_timeout);
            }
        } else {
            if (call_ctx) {
                call_ctx->ringing_sent = true;
            }
        }
    }
    return CallLeg::b2bInitial1xx(reply, forward);
}

void SBCCallLeg::b2bConnectedErr(AmSipReply &reply)
{
    const static string xfer_failed("Transfer Failed: ");

    if (a_leg) {
        if (!call_ctx)
            return;
        if (!call_ctx->transfer_intermediate_state)
            return;

        DBG("got %d/%s for xfer INVITE. force CDR reasons", reply.code, reply.reason.c_str());

        with_cdr_for_read
        {
            cdr->update_with_action(End);
            cdr->disconnect_initiator       = DisconnectByTS;
            cdr->disconnect_internal_code   = 200;
            cdr->disconnect_internal_reason = xfer_failed + int2str(reply.code) + "/" + reply.reason;
            cdr->update_aleg_reason("Bye", 200);
            cdr->update_bleg_reason("Bye", 200);
        }
    }

    terminateLeg();
}

void SBCCallLeg::onOtherRefer(const B2BReferEvent &refer)
{
    DBG("%s(%p) to: %s", FUNC_NAME, to_void(this), refer.referred_to.c_str());

    removeOtherLeg(refer.referrer_session);

    if (!call_ctx)
        return;

    with_cdr_for_read
    {
        // TODO: use separate field to indicate refer
        cdr->is_redirected = true;
    }

    call_ctx->referrer_session            = refer.referrer_session;
    call_ctx->transfer_intermediate_state = true;

    call_profile.bleg_max_transfers--;

    DBG("patch RURI: '%s' -> '%s'", ruri.c_str(), refer.referred_to.c_str());
    ruri = refer.referred_to;

    DBG("patch To: '%s' -> '%s'", to.c_str(), refer.referred_to.c_str());
    to = refer.referred_to;

    unique_ptr<AmSipDialog> callee_dlg(new AmSipDialog());

    if (!call_profile.apply_b_routing(ruri, *callee_dlg)) {
        ERROR("%s failed to apply B routing after REFER", getLocalTag().data());
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    for (const auto &hdr : refer.append_headers)
        modified_req.hdrs += hdr + CRLF;

    connectCallee(to, ruri, from, aleg_modified_req, modified_req, callee_dlg.release());
}

void SBCCallLeg::sendReferNotify(int code, string &reason)
{
    DBG("%s(%p) %d %s", FUNC_NAME, to_void(this), code, reason.c_str());
    if (last_refer_cseq.empty())
        return;
    string body = "SIP/2.0 " + int2str(code) + " " + reason + CRLF;

    bool terminate_subscription = (code >= 200);

    subs->sendReferNotify(dlg, last_refer_cseq, body, terminate_subscription);

    if (terminate_subscription) {
        setTimer(YETI_REFER_TIMEOUT_TIMER, 3);
    }
}

void SBCCallLeg::httpCallStartedHook()
{
    if (yeti.config.http_events_destination.empty())
        return;

    {
        with_cdr_for_read
        {
            serialized_http_data["type"]      = "started";
            serialized_http_data["local_tag"] = cdr->local_tag;
            cdr->serialize_for_http_common(serialized_http_data["data"], router.getDynFields());
        }
    }

    yeti.http_sequencer.processHook(HttpSequencer::CallStarted, getLocalTag(), serialized_http_data);
}

void SBCCallLeg::httpCallConnectedHook()
{
    if (yeti.config.http_events_destination.empty())
        return;

    {
        with_cdr_for_read
        {
            serialized_http_data["type"] = "connected";
            cdr->serialize_for_http_connected(serialized_http_data["data"]);
        }
    }

    yeti.http_sequencer.processHook(HttpSequencer::CallConnected, getLocalTag(), serialized_http_data);
}

void SBCCallLeg::httpCallDisconnectedHook()
{
    if (yeti.config.http_events_destination.empty())
        return;

    {
        with_cdr_for_read
        {
            serialized_http_data["type"] = "disconnected";
            cdr->serialize_for_http_disconnected(serialized_http_data["data"]);
        }
    }

    yeti.http_sequencer.processHook(HttpSequencer::CallDisconnected, getLocalTag(), serialized_http_data);
}

void SBCCallLeg::send_and_log_auth_challenge(const AmSipRequest &req, const string &internal_reason, bool post_auth_log,
                                             int auth_feedback_code)
{
    string hdrs;
    if (yeti.config.auth_feedback && auth_feedback_code) {
        hdrs = yeti_auth_feedback_header + int2str(auth_feedback_code) + CRLF;
    }
    router.send_and_log_auth_challenge(req, ip_auth_data, internal_reason, hdrs, post_auth_log);
}

void SBCCallLeg::setRejectCdr(int disconnect_code_id)
{
    if (call_ctx->setRejectCdr(disconnect_code_id)) {
        auto &cdr = *call_ctx->cdr;

        cdr.update_init_aleg(getLocalTag(), getLocalTag(), uac_req.callid);
        cdr.update_with_aleg_sip_request(uac_req);

        cdr.set_start_time(call_start_time);
        cdr.update_with_action(End);

        if (!isArgUndef(identity_data)) {
            cdr.identity_data = identity_data;
        }
    }
}
