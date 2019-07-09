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

#include "sip/pcap_logger.h"
#include "sip/sip_parser.h"
#include "sip/sip_trans.h"
#include "sip/parse_nameaddr.h"

#include "HeaderFilter.h"
#include "ParamReplacer.h"
#include "SDPFilter.h"

#include <algorithm>

#include "AmAudioFileRecorder.h"
#include "radius_hooks.h"
#include "Sensors.h"
#include "RedisConnection.h"

#include "sdp_filter.h"
#include "ampi/RadiusClientAPI.h"
#include "dtmf_sip_info.h"

using namespace std;

#define TRACE DBG

#define FILE_RECORDER_COMPRESSED_EXT ".mp3"
#define FILE_RECORDER_RAW_EXT        ".wav"

inline void replace(string& s, const string& from, const string& to)
{
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != string::npos) {
        s.replace(pos, from.length(), to);
        pos += s.length();
    }
}

static const char *callStatus2str(const CallLeg::CallStatus state)
{
    static const char *disconnected = "Disconnected";
    static const char *disconnecting = "Disconnecting";
    static const char *noreply = "NoReply";
    static const char *ringing = "Ringing";
    static const char *connected = "Connected";
    static const char *unknown = "???";

    switch (state) {
        case CallLeg::Disconnected: return disconnected;
        case CallLeg::Disconnecting: return disconnecting;
        case CallLeg::NoReply: return noreply;
        case CallLeg::Ringing: return ringing;
        case CallLeg::Connected: return connected;
    }

    return unknown;
}

#define getCtx_void \
    if(NULL==call_ctx) {\
        return;\
    }

#define getCtx_chained \
    if(NULL==call_ctx) {\
        break;\
    }

#define with_cdr_for_read \
    Cdr *cdr = call_ctx->getCdrSafeRead();\
    if(cdr)

#define with_cdr_for_write \
    Cdr *cdr = call_ctx->getCdrSafeWrite();\
    if(cdr)

///////////////////////////////////////////////////////////////////////////////////////////

// map stream index and transcoder payload index (two dimensions) into one under
// presumption that there will be less than 128 payloads for transcoding
// (might be handy to remember mapping only for dynamic ones (96-127)
#define MAP_INDEXES(stream_idx, payload_idx) ((stream_idx) * 128 + payload_idx)

void PayloadIdMapping::map(int stream_index, int payload_index, int payload_id)
{
    mapping[MAP_INDEXES(stream_index, payload_index)] = payload_id;
}

int PayloadIdMapping::get(int stream_index, int payload_index)
{
    std::map<int, int>::iterator i = mapping.find(MAP_INDEXES(stream_index, payload_index));
    if (i != mapping.end()) return i->second;
    else return -1;
}

void PayloadIdMapping::reset()
{
    mapping.clear();
}

#undef MAP_INDEXES

///////////////////////////////////////////////////////////////////////////////////////////

// A leg constructor (from SBCDialog)
SBCCallLeg::SBCCallLeg(
    CallCtx *call_ctx,
    AmSipDialog* p_dlg,
    AmSipSubscription* p_subs)
  : CallLeg(p_dlg,p_subs),
    m_state(BB_Init),
    yeti(Yeti::instance()),
    call_ctx(call_ctx),
    auth(nullptr),
    call_profile(*call_ctx->getCurrentProfile()),
    placeholders_hash(call_profile.placeholders_hash),
    logger(nullptr),
    sensor(nullptr),
    router(yeti.router),
    cdr_list(yeti.cdr_list),
    rctl(yeti.rctl)
{
    DBG("SBCCallLeg[%p](ctx %p,%p,%p)",
        to_void(this),to_void(call_ctx),to_void(p_dlg),to_void(p_subs));

    set_sip_relay_only(false);
    if(call_profile.aleg_rel100_mode_id!=-1) {
        dlg->setRel100State(static_cast<Am100rel::State>(call_profile.aleg_rel100_mode_id));
    } else {
        dlg->setRel100State(Am100rel::REL100_IGNORED);
    }

    if(call_profile.rtprelay_bw_limit_rate > 0
       && call_profile.rtprelay_bw_limit_peak > 0)
    {
        RateLimit* limit = new RateLimit(
            static_cast<unsigned int>(call_profile.rtprelay_bw_limit_rate),
            static_cast<unsigned int>(call_profile.rtprelay_bw_limit_peak),
            1000);
        rtp_relay_rate_limit.reset(limit);
    }

    if(call_profile.global_tag.empty()) {
        global_tag = getLocalTag();
    } else {
        global_tag = call_profile.global_tag;
    }
}

// B leg constructor (from SBCCalleeSession)
SBCCallLeg::SBCCallLeg(
    SBCCallLeg* caller,
    AmSipDialog* p_dlg,
    AmSipSubscription* p_subs)
  : CallLeg(caller,p_dlg,p_subs),
    yeti(Yeti::instance()),
    global_tag(caller->getGlobalTag()),
    call_ctx(caller->getCallCtx()),
    auth(nullptr),
    call_profile(caller->getCallProfile()),
    placeholders_hash(caller->getPlaceholders()),
    logger(nullptr),
    sensor(nullptr),
    router(yeti.router),
    cdr_list(yeti.cdr_list),
    rctl(yeti.rctl)
{
    DBG("SBCCallLeg[%p](caller %p,%p,%p)",
        to_void(this),to_void(caller),to_void(p_dlg),to_void(p_subs));

    if(call_profile.bleg_rel100_mode_id!=-1) {
      dlg->setRel100State(static_cast<Am100rel::State>(call_profile.bleg_rel100_mode_id));
    } else {
      dlg->setRel100State(Am100rel::REL100_IGNORED);
    }

    // copy RTP rate limit from caller leg
    if(caller->rtp_relay_rate_limit.get()) {
        rtp_relay_rate_limit.reset(new RateLimit(*caller->rtp_relay_rate_limit.get()));
    }

    init();

    setLogger(caller->getLogger());
}

SBCCallLeg::SBCCallLeg(AmSipDialog* p_dlg, AmSipSubscription* p_subs)
  : CallLeg(p_dlg,p_subs),
    m_state(BB_Init),
    yeti(Yeti::instance()),
    auth(nullptr),
    logger(nullptr),
    sensor(nullptr),
    router(yeti.router),
    cdr_list(yeti.cdr_list),
    rctl(yeti.rctl)
{
    DBG("SBCCallLeg[%p](%p,%p)",
        to_void(this),to_void(p_dlg),to_void(p_subs));
}

void SBCCallLeg::init()
{
    call_ctx->inc();

    Cdr *cdr = call_ctx->cdr;

    if(a_leg) {
        ostringstream ss;
        ss << yeti.config.msg_logger_dir << '/' <<
              getLocalTag() << "_" <<
              int2str(yeti.config.node_id) << ".pcap";
        call_profile.set_logger_path(ss.str());

        cdr->update_sbc(call_profile);
        setSensor(Sensors::instance()->getSensor(call_profile.aleg_sensor_id));
        cdr->update_init_aleg(getLocalTag(),
                              global_tag,
                              getCallID());
    } else {
        if(!call_profile.callid.empty()){
            string id = AmSession::getNewId();
            replace(call_profile.callid,"%uuid",id);
        }
        setSensor(Sensors::instance()->getSensor(call_profile.bleg_sensor_id));
        cdr->update_init_bleg(
            call_profile.callid.empty()? getCallID() : call_profile.callid,
            getLocalTag());
    }

    if(call_profile.record_audio){
        ostringstream ss;
        ss  << yeti.config.audio_recorder_dir << '/'
            << global_tag << "_"
            << int2str(yeti.config.node_id) <<  "_leg"
            << (a_leg ? "a" : "b")
            << (yeti.config.audio_recorder_compress ?
                FILE_RECORDER_COMPRESSED_EXT :
                FILE_RECORDER_RAW_EXT);
        call_profile.audio_record_path = ss.str();

        AmAudioFileRecorderProcessor::instance()->addRecorder(
            getLocalTag(),
            call_profile.audio_record_path);
        setRecordAudio(true);
    }
}

void SBCCallLeg::terminateLegOnReplyException(const AmSipReply& reply,const InternalException &e)
{
    getCtx_void

    if(!getOtherId().empty()) { //ignore not connected B legs
        with_cdr_for_read {
            cdr->update_internal_reason(DisconnectByTS, e.internal_reason, e.internal_code);
            cdr->update(reply);
        }
    }

    relayError(reply.cseq_method,reply.cseq,true,
               static_cast<int>(e.response_code),
               e.response_reason.c_str());

    if(getCallStatus()==Connected) {
        DBG("if(getCallStatus()==Connected) {");
        stopCall(CallLeg::StatusChangeCause::InternalError);
    } else {
        DBG("if(getCallStatus()==Connected) { else");
        terminateLeg();
    }
}

void SBCCallLeg::processAorResolving()
{
    DBG("%s(%p,leg%s)",FUNC_NAME,static_cast<void *>(this),a_leg?"A":"B");

    //check for registered_aor_id in profiles
    std::set<int> aor_ids;
    for(const auto &p : call_ctx->profiles) {
        if(0==p->disconnect_code_id && 0!=p->registered_aor_id) {
            aor_ids.emplace(p->registered_aor_id);
        }
    }

    if(aor_ids.empty()) {
        //no aor resolving requested. continue as usual
        processResourcesAndSdp();
        return;
    }

    if(!yeti.config.registrar_enabled) {
        ERROR("registrar feature disabled for node, but routing returned profiles with registered_aor_id set");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    size_t aors_count = aor_ids.size();
    string str_size = long2str(static_cast<long>(aor_ids.size()));
    DBG("got %s AoR ids to resolve", str_size.c_str());

    if(yeti_aor_lookup.hash.empty()) {
        ERROR("empty yeti_aor_lookup.hash. lua scripting error");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    char *cmd = static_cast<char *>(malloc(128));
    char *s = cmd;

    s += sprintf(cmd, "*%lu\r\n$7\r\nEVALSHA\r\n$40\r\n%s\r\n$%u\r\n%lu\r\n",
        aors_count+3,
        yeti_aor_lookup.hash.data(),
        len_in_chars(aors_count), aors_count);

    for(const auto &id : aor_ids) {
        s += sprintf(s, "$%u\r\n%d\r\n",
            len_in_chars(id), id);
    }

    //send request to redis
    if(false==postRedisRequest(
        getLocalTag(),
        cmd,static_cast<size_t>(s-cmd)))
    {
        ERROR("failed to post auti_id resolve request");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }
}

void SBCCallLeg::processResourcesAndSdp()
{
    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");

    SqlCallProfile *profile = nullptr;

    ResourceCtlResponse rctl_ret;
    ResourceList::iterator ri;
    ResourceConfig resource_config;
    /*string refuse_reason;
    int refuse_code;*/
    int attempt = 0;

    Cdr *cdr = call_ctx->cdr;

    PROF_START(func);

    try {

    PROF_START(rchk);
    do {
        DBG("%s() check resources for profile. attempt %d",FUNC_NAME,attempt);
        rctl_ret = rctl.get(call_ctx->getCurrentResourceList(),
                            call_ctx->getCurrentProfile()->resource_handler,
                            getLocalTag(),
                            resource_config,ri);

        if(rctl_ret == RES_CTL_OK){
            DBG("%s() check resources succ",FUNC_NAME);
            break;
        } else if(	rctl_ret ==  RES_CTL_REJECT ||
                    rctl_ret ==  RES_CTL_ERROR)
        {
            DBG("%s() check resources failed with code %d. internal code: %d",FUNC_NAME,
                rctl_ret,resource_config.internal_code_id);
            if(rctl_ret == RES_CTL_REJECT) {
                cdr->update_failed_resource(*ri);
            }
            break;
        } else if(	rctl_ret == RES_CTL_NEXT){
            DBG("%s() check resources failed with code %d. internal code: %d",FUNC_NAME,
                rctl_ret,resource_config.internal_code_id);
            profile = call_ctx->getNextProfile(true);

            if(nullptr==profile){
                cdr->update_failed_resource(*ri);
                DBG("%s() there are no profiles more",FUNC_NAME);
                throw AmSession::Exception(503,"no more profiles");
            }

            DBG("%s() choosed next profile",FUNC_NAME);

            /* show resource disconnect reason instead of
             * refuse_profile if refuse_profile follows failed resource with
             * failover to next */
            if(profile->disconnect_code_id!=0) {
                unsigned int internal_code, response_code;
                string internal_reason, response_reason;

                cdr->update_failed_resource(*ri);

                CodesTranslator::instance()->translate_db_code(
                    static_cast<unsigned int>(resource_config.internal_code_id),
                    internal_code,internal_reason,
                    response_code,response_reason,
                    call_ctx->getOverrideId(a_leg));

                rctl.replace(internal_reason, *ri, resource_config);
                rctl.replace(response_reason, *ri, resource_config);

                cdr->update_internal_reason(DisconnectByTS, internal_reason, internal_code);

                throw AmSession::Exception(
                    static_cast<int>(response_code),response_reason);
            }

            ParamReplacerCtx rctx(profile);
            if(router.check_and_refuse(profile,cdr,aleg_modified_req,rctx)){
                throw AmSession::Exception(cdr->disconnect_rewrited_code,
                                           cdr->disconnect_rewrited_reason);
            }
        }
        attempt++;
    } while(rctl_ret != RES_CTL_OK);

    if(rctl_ret != RES_CTL_OK) {
        //throw AmSession::Exception(refuse_code,refuse_reason);
        unsigned int internal_code, response_code;
        string internal_reason, response_reason;

        CodesTranslator::instance()->translate_db_code(
            static_cast<unsigned int>(resource_config.internal_code_id),
            internal_code,internal_reason,
            response_code,response_reason,
            call_ctx->getOverrideId(a_leg));

        rctl.replace(internal_reason, *ri, resource_config);
        rctl.replace(response_reason, *ri, resource_config);

        cdr->update_internal_reason(DisconnectByTS,internal_reason, internal_code);

        throw AmSession::Exception(
            static_cast<int>(response_code),response_reason);
    }

    PROF_END(rchk);
    PROF_PRINT("check and grab resources",rchk);

    profile = call_ctx->getCurrentProfile();
    cdr->update(profile->rl);
    updateCallProfile(*profile);

    PROF_START(sdp_processing);

    //filterSDP
    int res = processSdpOffer(call_profile,
                              aleg_modified_req.body, aleg_modified_req.method,
                              call_ctx->aleg_negotiated_media,
                              call_profile.static_codecs_aleg_id);
    if(res < 0){
        INFO("%s() Not acceptable codecs",FUNC_NAME);
        throw InternalException(FC_CODECS_NOT_MATCHED, call_ctx->getOverrideId());
    }

    //next we should filter request for legB
    res = filterSdpOffer(this,
                         call_profile,
                         modified_req.body,modified_req.method,
                         call_profile.static_codecs_bleg_id,
                         &call_ctx->bleg_initial_offer);
    if(res < 0){
        INFO("%s() Not acceptable codecs for legB",FUNC_NAME);
        throw AmSession::Exception(488, SIP_REPLY_NOT_ACCEPTABLE_HERE);
    }
    PROF_END(sdp_processing);
    PROF_PRINT("initial sdp processing",sdp_processing);

    call_ctx->bleg_negotiated_media = call_ctx->bleg_initial_offer.media;

    if(cdr->time_limit){
        DBG("%s() save timer %d with timeout %d",FUNC_NAME,
            YETI_CALL_DURATION_TIMER,
            cdr->time_limit);
        saveCallTimer(YETI_CALL_DURATION_TIMER,cdr->time_limit);
    }

    if(!call_profile.append_headers.empty()){
        replace(call_profile.append_headers,"%global_tag",getGlobalTag());
    }

    onRoutingReady();

    } catch(InternalException &e) {
        DBG("%s() catched InternalException(%d)",FUNC_NAME,
            e.icode);
        rctl.put(call_profile.resource_handler);
        cdr->update_internal_reason(DisconnectByTS,e.internal_reason,e.internal_code);
        throw AmSession::Exception(
            static_cast<int>(e.response_code),e.response_reason);
    } catch(AmSession::Exception &e) {
        DBG("%s() catched AmSession::Exception(%d,%s)",FUNC_NAME,
            e.code,e.reason.c_str());
        rctl.put(call_profile.resource_handler);
        cdr->update_internal_reason(DisconnectByTS,
            e.reason,static_cast<unsigned int>(e.code));
        throw e;
    }

    PROF_END(func);
    PROF_PRINT("yeti processResourcesAndSdp()",func);
    return;
}

bool SBCCallLeg::chooseNextProfile(){
    DBG("%s()",FUNC_NAME);

    /*string refuse_reason;
    int refuse_code;*/
    ResourceConfig resource_config;
    Cdr *cdr;
    SqlCallProfile *profile = nullptr;
    ResourceCtlResponse rctl_ret;
    ResourceList::iterator ri;
    bool has_profile = false;

    cdr = call_ctx->cdr;
    profile = call_ctx->getNextProfile(false);

    if(nullptr==profile){
        //pretend that nothing happen. we were never called
        DBG("%s() no more profiles or refuse profile on serial fork. ignore it",FUNC_NAME);
        return false;
    }

    //write cdr and replace ctx pointer with new
    cdr_list.remove(cdr);
    router.write_cdr(cdr,false);
    cdr = call_ctx->cdr;

    do {
        DBG("%s() choosed next profile. check it for refuse",FUNC_NAME);

        ParamReplacerCtx rctx(profile);
        if(router.check_and_refuse(profile,cdr,*call_ctx->initial_invite,rctx)){
            DBG("%s() profile contains refuse code",FUNC_NAME);
            break;
        }

        DBG("%s() no refuse field. check it for resources",FUNC_NAME);
        ResourceList &rl = profile->rl;
        if(rl.empty()){
            rctl_ret = RES_CTL_OK;
        } else {
            rctl_ret = rctl.get(rl,
                                profile->resource_handler,
                                getLocalTag(),
                                resource_config,ri);
        }

        if(rctl_ret == RES_CTL_OK){
            DBG("%s() check resources  successed",FUNC_NAME);
            has_profile = true;
            break;
        } else {
            DBG("%s() check resources failed with code %d. internal code: %d",FUNC_NAME,
                rctl_ret,resource_config.internal_code_id);
            if(rctl_ret ==  RES_CTL_ERROR) {
                break;
            } else if(rctl_ret ==  RES_CTL_REJECT) {
                cdr->update_failed_resource(*ri);
                break;
            } else if(	rctl_ret == RES_CTL_NEXT){
                profile = call_ctx->getNextProfile(false,true);
                if(nullptr==profile){
                    cdr->update_failed_resource(*ri);
                    DBG("%s() there are no profiles more",FUNC_NAME);
                    break;
                }
                if(profile->disconnect_code_id!=0){
                    cdr->update_failed_resource(*ri);
                    DBG("%s() failovered to refusing profile %d",FUNC_NAME,
                        profile->disconnect_code_id);
                    break;
                }
            }
        }
    } while(rctl_ret != RES_CTL_OK);

    if(!has_profile) {

        unsigned int internal_code, response_code;
        string internal_reason, response_reason;

        CodesTranslator::instance()->translate_db_code(
            static_cast<unsigned int>(resource_config.internal_code_id),
            internal_code,internal_reason,
            response_code,response_reason,
            call_ctx->getOverrideId(a_leg));

        rctl.replace(internal_reason, *ri, resource_config);
        rctl.replace(response_reason, *ri, resource_config);

        cdr->update_internal_reason(DisconnectByTS, response_reason, response_code);

        return false;
    } else {
        DBG("%s() update call profile for legA",FUNC_NAME);
        cdr->update(profile->rl);
        updateCallProfile(*profile);
        return true;
    }
}

bool SBCCallLeg::connectCallee(const AmSipRequest &orig_req)
{
    ParamReplacerCtx ctx(&call_profile);
    ctx.app_param = getHeader(orig_req.hdrs, PARAM_HDR, true);

    AmSipRequest uac_req(orig_req);
    AmUriParser uac_ruri;

    uac_ruri.uri = uac_req.r_uri;
    if(!uac_ruri.parse_uri()) {
        DBG("Error parsing R-URI '%s'\n",uac_ruri.uri.c_str());
        throw AmSession::Exception(400,"Failed to parse R-URI");
    }

    if (!call_profile.evaluate(ctx, orig_req)) {
        ERROR("call profile evaluation failed\n");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }
    if(!call_profile.append_headers.empty()){
        replace(call_profile.append_headers,"%global_tag",getGlobalTag());
    }

    string ruri, to, from;

    ruri = call_profile.ruri.empty() ? uac_req.r_uri : call_profile.ruri;
    if(!call_profile.ruri_host.empty()){
        ctx.ruri_parser.uri = ruri;
        if(!ctx.ruri_parser.parse_uri()) {
            WARN("Error parsing R-URI '%s'\n", ruri.c_str());
        } else {
            ctx.ruri_parser.uri_port.clear();
            ctx.ruri_parser.uri_host = call_profile.ruri_host;
            ruri = ctx.ruri_parser.uri_str();
        }
    }

    AmUriParser from_uri, to_uri;

    from = call_profile.from.empty() ? orig_req.from : call_profile.from;
    //from_uri.uri = call_profile.from.empty() ? orig_req.from : call_profile.from;
    if(!from_uri.parse_nameaddr(from)) {
        DBG("Error parsing From-URI '%s'\n",from.c_str());
        throw AmSession::Exception(400,"Failed to parse From-URI");
    }

    to = call_profile.to.empty() ? orig_req.to : call_profile.to;
    if(!to_uri.parse_nameaddr(to)) {
        DBG("Error parsing To-URI '%s'\n",to.c_str());
        throw AmSession::Exception(400,"Failed to parse To-URI");
    }

    from = from_uri.nameaddr_str();
    to = to_uri.nameaddr_str();

    applyAProfile();
    call_profile.apply_a_routing(ctx,orig_req,*dlg);

    AmSipRequest invite_req(orig_req);

    removeHeader(invite_req.hdrs,PARAM_HDR);
    removeHeader(invite_req.hdrs,"P-App-Name");

    if (call_profile.sst_enabled_value) {
        removeHeader(invite_req.hdrs,SIP_HDR_SESSION_EXPIRES);
        removeHeader(invite_req.hdrs,SIP_HDR_MIN_SE);
    }

    size_t start_pos = 0;
    while (start_pos<call_profile.append_headers.length()) {
        int res;
        size_t name_end, val_begin, val_end, hdr_end;
        if ((res = skip_header(call_profile.append_headers, start_pos, name_end, val_begin,
                val_end, hdr_end)) != 0) {
            ERROR("skip_header for '%s' pos: %ld, return %d",
                    call_profile.append_headers.c_str(),start_pos,res);
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
        string hdr_name = call_profile.append_headers.substr(start_pos, name_end-start_pos);
        while(!getHeader(invite_req.hdrs,hdr_name).empty()){
            removeHeader(invite_req.hdrs,hdr_name);
        }
        start_pos = hdr_end;
    }

    inplaceHeaderPatternFilter(invite_req.hdrs, call_profile.headerfilter_a2b);

    if (call_profile.append_headers.size() > 2) {
        string append_headers = call_profile.append_headers;
        assertEndCRLF(append_headers);
        invite_req.hdrs+=append_headers;
    }

    int res = filterSdpOffer(this,
                             call_profile,
                             invite_req.body,invite_req.method,
                             call_profile.static_codecs_bleg_id,
                             &call_ctx->bleg_initial_offer);
    if(res < 0){
        INFO("onInitialInvite() Not acceptable codecs for legB");
        throw AmSession::Exception(488, SIP_REPLY_NOT_ACCEPTABLE_HERE);
    }

    connectCallee(to, ruri, from, orig_req, invite_req);

    return false;
}

void SBCCallLeg::onRadiusReply(const RadiusReplyEvent &ev)
{
    DBG("got radius reply for %s",getLocalTag().c_str());

    if(AmBasicSipDialog::Cancelling==dlg->getStatus()) {
        DBG("[%s] ignore radius reply in Cancelling state",getLocalTag().c_str());
        return;
    }
    getCtx_void
    try {
        switch(ev.result){
        case RadiusReplyEvent::Accepted:
            processAorResolving();
            break;
        case RadiusReplyEvent::Rejected:
            throw InternalException(RADIUS_RESPONSE_REJECT, call_ctx->getOverrideId(a_leg));
        case RadiusReplyEvent::Error:
            if(ev.reject_on_error){
                ERROR("[%s] radius error %d. reject",
                    getLocalTag().c_str(),ev.error_code);
                throw InternalException(
                    static_cast<unsigned int>(ev.error_code),
                    call_ctx->getOverrideId(a_leg));
            } else {
                ERROR("[%s] radius error %d, but radius profile configured to ignore errors.",
                    getLocalTag().c_str(),ev.error_code);
                processAorResolving();
            }
            break;
        }
    } catch(AmSession::Exception &e) {
        onEarlyEventException(static_cast<unsigned int>(e.code),e.reason);
    } catch(InternalException &e){
        onEarlyEventException(e.response_code,e.response_reason);
    }
}

struct aor_lookup_reply {
    /* reply layout:
     * [
     *   auth_id1,
     *   [
     *     contact1,
     *     path1,
     *     contact2,
     *     path2
     *   ],
     *   auth_id2,
     *   [
     *     contact3,
     *     path3,
     *   ],
     * ]
     */

    struct aor_data {
        string contact;
        string path;
        aor_data(const char *contact, const char *path)
          : contact(contact),
            path(path)
        {}
    };

    std::map<int, std::list<aor_data> > aors;

    //return false on errors
    bool parse(const RedisReplyEvent &e)
    {
        if(RedisReplyEvent::SuccessReply!=e.result) {
            ERROR("error reply from redis %d %s",
                e.result,
                AmArg::print(e.data).c_str());
            return false;
        }
        if(!isArgArray(e.data) || e.data.size()%2!=0) {
            ERROR("unexpected redis reply layout: %s", AmArg::print(e.data).data());
            return false;
        }
        int n = static_cast<int>(e.data.size())-1;
        for(int i = 0; i < n; i+=2) {
            AmArg &id_arg = e.data[i];
            if(!isArgLongLong(id_arg)) {
                ERROR("unexpected auth_id type. skip entry");
                continue;
            }
            int auth_id = static_cast<int>(id_arg.asLongLong());

            AmArg &aor_data_arg = e.data[i+1];
            if(!isArgArray(aor_data_arg) || aor_data_arg.size()%2!=0) {
                ERROR("unexpected aor_data_arg layout. skip entry");
                continue;
            }

            int m = static_cast<int>(aor_data_arg.size())-1;
            for(int j = 0; j < m; j+=2) {
                AmArg &contact_arg = aor_data_arg[j];
                AmArg &path_arg = aor_data_arg[j+1];
                if(!isArgCStr(contact_arg) || !isArgCStr(path_arg)) {
                    ERROR("unexpected contact_arg||path_arg type. skip entry");
                    continue;
                }

                auto it = aors.find(auth_id);
                if(it == aors.end()) {
                    it = aors.insert(aors.begin(),
                        std::pair<int, std::list<aor_data> >(auth_id,  std::list<aor_data>()));
                }
                it->second.emplace_back(contact_arg.asCStr(), path_arg.asCStr());
            }
        }
        return true;
    }
};

void SBCCallLeg::onRedisReply(const RedisReplyEvent &e)
{
    DBG("%s onRedisReply",getLocalTag().c_str());
    //DBG("data: %s",AmArg::print(e.data).data());

    //preprocess redis reply data
    aor_lookup_reply r;
    if(!r.parse(e)) {
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    //resolve ruri in profiles
    auto &profiles = call_ctx->profiles;

    DBG("profiles before processing: %lu", profiles.size());

    for(auto it = profiles.begin(); it != profiles.end();) {
        SqlCallProfile &p = *(*it);
        if(p.disconnect_code_id != 0 || p.registered_aor_id==0) {
            ++it;
            continue;
        }

        auto a = r.aors.find(p.registered_aor_id);
        if(a == r.aors.end()) {
            p.skip_code_id = SC_NOT_REGISTERED;
            ++it;
            continue;
        }

        auto &aors_list  = a->second;

        auto aor_it = aors_list.begin();
        //replace ruri in profile
        p.ruri = aor_it->contact;
        if(!aor_it->path.empty()) {
            p.outbound_proxy = aor_it->path;
        }

        ++aor_it;
        while(aor_it != aors_list.end()) {
            SqlCallProfile *cloned_p = p.copy();

            ++it;
            it = profiles.insert(it, cloned_p);

            cloned_p->ruri = aor_it->contact;
            if(!aor_it->path.empty()) {
                cloned_p->outbound_proxy = aor_it->path;
            }

            ++aor_it;
        }

        ++it;
    }

    DBG("profiles count after processing: %lu", profiles.size());

    //at this stage rejecting profile can not be the first one

    auto next_profile = call_ctx->current_profile;
    int attempt_counter = call_ctx->cdr->attempt_num;
    if((*next_profile)->skip_code_id != 0) {
        unsigned int internal_code,response_code;
        string internal_reason,response_reason;

        //skip profiles with skip_code_id writing CDRs
        do {
            SqlCallProfile &p = *(*next_profile);
            //skip_cdr = nullptr;
            DBG("process profile with skip_code_id: %d",p.skip_code_id);

            bool write_cdr = CodesTranslator::instance()->translate_db_code(
                        p.skip_code_id,
                        internal_code,internal_reason,
                        response_code,response_reason,
                        p.aleg_override_id);

            if(write_cdr) {
                with_cdr_for_read {
                    cdr->update_internal_reason(DisconnectByTS,internal_reason,internal_code);
                    cdr->update_aleg_reason(response_reason,response_code);
                }
            }

            ++next_profile;

            if(next_profile == profiles.end() ||
               (*next_profile)->disconnect_code_id != 0)
            {
                DBG("no more profiles or reject profile after the skipped profile. terminate leg");
                router.write_cdr(call_ctx->cdr, true);
                AmSipDialog::reply_error(aleg_modified_req, response_code, response_reason);
                terminateLeg();
                return;
            }

            call_ctx->current_profile = next_profile;
            with_cdr_for_write {
                call_ctx->cdr = new Cdr(*cdr,**next_profile);
                router.write_cdr(cdr, false);
            }

        } while((*next_profile)->skip_code_id != 0);
    }

    processResourcesAndSdp();
}

void SBCCallLeg::onRtpTimeoutOverride(const AmRtpTimeoutEvent &)
{
    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");
    unsigned int internal_code,response_code;
    string internal_reason,response_reason;

    getCtx_void

    if(getCallStatus()!=CallLeg::Connected){
        WARN("%s: module catched RtpTimeout in no Connected state. ignore it",
             getLocalTag().c_str());
        return;
    }

    CodesTranslator::instance()->translate_db_code(
        DC_RTP_TIMEOUT,
        internal_code,internal_reason,
        response_code,response_reason,
        call_ctx->getOverrideId(a_leg));
    with_cdr_for_read {
        cdr->update_internal_reason(DisconnectByTS,internal_reason,internal_code);
        cdr->update_aleg_reason("Bye",200);
        cdr->update_bleg_reason("Bye",200);
    }
    SBCCallLeg::onRtpTimeout();
}

bool SBCCallLeg::onTimerEvent(int timer_id)
{
    DBG("%s(%p,%d,leg%s)",FUNC_NAME,to_void(this),timer_id,a_leg?"A":"B");
    with_cdr_for_read {
        switch(timer_id){
        case YETI_CALL_DURATION_TIMER:
            cdr->update_internal_reason(DisconnectByTS,"Call duration limit reached",200);
            cdr->update_aleg_reason("Bye",200);
            cdr->update_bleg_reason("Bye",200);
            stopCall("Call duration limit reached");
            return true;
        case YETI_RINGING_TIMEOUT_TIMER:
            call_ctx->setRingingTimeout();
            dlg->cancel();
            return true;
        case YETI_RADIUS_INTERIM_TIMER:
            onInterimRadiusTimer();
            return true;
        case YETI_FAKE_RINGING_TIMER:
            onFakeRingingTimer();
            return true;
        default:
            return false;
        }
    }
    return false;
}

void SBCCallLeg::onInterimRadiusTimer()
{
    DBG("interim accounting timer fired for %s",getLocalTag().c_str());
    getCtx_void
    with_cdr_for_read {
        radius_accounting_interim(this,*cdr);
    }
}

void SBCCallLeg::onFakeRingingTimer()
{
    DBG("fake ringing timer fired for %s",getLocalTag().c_str());
    getCtx_void
    if(!call_ctx->ringing_sent) {
        dlg->reply(*call_ctx->initial_invite,180,SIP_REPLY_RINGING);
        call_ctx->ringing_sent = true;
    }
}

void SBCCallLeg::onControlEvent(SBCControlEvent *event)
{
    DBG("%s(%p,leg%s) cmd = %s, event_id = %d",FUNC_NAME,to_void(this),a_leg?"A":"B",
        event->cmd.c_str(),event->event_id);
    if(event->cmd=="teardown"){
        onTearDown();
    }
}

void SBCCallLeg::onTearDown()
{
    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");
    getCtx_void
    with_cdr_for_read {
        cdr->update_internal_reason(DisconnectByTS,"Teardown",200);
        cdr->update_aleg_reason("Bye",200);
        cdr->update_bleg_reason("Bye",200);
    }
}

void SBCCallLeg::onSystemEventOverride(AmSystemEvent* event)
{
    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");
    if (event->sys_event == AmSystemEvent::ServerShutdown) {
        onServerShutdown();
    }
}

void SBCCallLeg::onServerShutdown()
{
    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");
    getCtx_void
    with_cdr_for_read {
        cdr->update_internal_reason(DisconnectByTS,"ServerShutdown",200);
    }
    //may never reach onDestroy callback so free resources here
    rctl.put(call_profile.resource_handler);
}

void SBCCallLeg::onStart()
{
    // this should be the first thing called in session's thread
    CallLeg::onStart();
    if (!a_leg) applyBProfile(); // A leg needs to evaluate profile first
    else if (!getOtherId().empty()) {
        // A leg but we already have a peer, what means that this call leg was
        // created as an A leg for already existing B leg (for example call
        // transfer)
        // we need to apply a profile, we use B profile and understand it as an
        // "outbound" profile though we are in A leg
        applyBProfile();
    }
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

    if (call_profile.rtprelay_enabled || call_profile.transcoder.isActive()) {
        DBG("Enabling RTP relay mode for SBC call\n");

        setRtpRelayForceSymmetricRtp(call_profile.aleg_force_symmetric_rtp_value);
        DBG("%s\n",getRtpRelayForceSymmetricRtp() ?
            "forcing symmetric RTP (passive mode)":
            "disabled symmetric RTP (normal mode)");
        setRtpEndlessSymmetricRtp(call_profile.bleg_symmetric_rtp_nonstop);
        setRtpSymmetricRtpIgnoreRTCP(call_profile.bleg_symmetric_rtp_ignore_rtcp);

        if (call_profile.aleg_rtprelay_interface_value >= 0) {
            setRtpInterface(call_profile.aleg_rtprelay_interface_value);
            DBG("using RTP interface %i for A leg\n", rtp_interface);
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

        if(call_profile.transcoder.isActive()) {
            setRtpRelayMode(RTP_Transcoding);
            switch(call_profile.transcoder.dtmf_mode) {
            case SBCCallProfile::TranscoderSettings::DTMFAlways:
                enable_dtmf_transcoding = true; break;
            case SBCCallProfile::TranscoderSettings::DTMFNever:
                enable_dtmf_transcoding = false; break;
            };
        } else {
            setRtpRelayMode(RTP_Relay);
        }
        // copy stats counters
        rtp_pegs = call_profile.aleg_rtp_counters;
    }

    if(!call_profile.dlg_contact_params.empty())
        dlg->setContactParams(call_profile.dlg_contact_params);
}

int SBCCallLeg::applySSTCfg(AmConfigReader& sst_cfg, const AmSipRequest *p_req)
{
    DBG("Enabling SIP Session Timers\n");
    if (nullptr == SBCFactory::instance()->session_timer_fact) {
        ERROR("session_timer module not loaded - "
              "unable to create call with SST\n");
        return -1;
    }

    if (p_req && !SBCFactory::instance()->session_timer_fact->
        onInvite(*p_req, sst_cfg)) {
        return -1;
    }

    AmSessionEventHandler* h = SBCFactory::instance()->session_timer_fact->getHandler(this);
    if (!h) {
        ERROR("could not get a session timer event handler\n");
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
        if(p_req) h->onSipRequest(*p_req);
    }

    return 0;
}

void SBCCallLeg::applyBProfile()
{
    // TODO: fix this!!! (see d85ed5c7e6b8d4c24e7e5b61c732c2e1ddd31784)
    // if (!call_profile.contact.empty()) {
    //   dlg->contact_uri = SIP_HDR_COLSP(SIP_HDR_CONTACT) + call_profile.contact + CRLF;
    // }

    setAllow1xxWithoutToTag(call_profile.allow_1xx_without_to_tag);

    redirects_allowed = call_profile.bleg_max_30x_redirects;

    if (call_profile.auth_enabled) {
        // adding auth handler
        AmSessionEventHandlerFactory* uac_auth_f =
            AmPlugIn::instance()->getFactory4Seh("uac_auth");
        if (nullptr == uac_auth_f)  {
            INFO("uac_auth module not loaded. uac auth NOT enabled.\n");
        } else {
            AmSessionEventHandler* h = uac_auth_f->getHandler(this);

            // we cannot use the generic AmSessi(onEvent)Handler hooks,
            // because the hooks don't work in AmB2BSession
            setAuthHandler(h);
            DBG("uac auth enabled for callee session.\n");
        }
    }

    if (call_profile.sst_enabled_value) {
        if(applySSTCfg(call_profile.sst_b_cfg,nullptr) < 0) {
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
    }

    if (!call_profile.outbound_proxy.empty()) {
        dlg->outbound_proxy = call_profile.outbound_proxy;
        dlg->force_outbound_proxy = call_profile.force_outbound_proxy;
    }

    if (!call_profile.next_hop.empty()) {
        DBG("set next hop to '%s' (1st_req=%s,fixed=%s)\n",
            call_profile.next_hop.c_str(), call_profile.next_hop_1st_req?"true":"false",
            call_profile.next_hop_fixed?"true":"false");
        dlg->setNextHop(call_profile.next_hop);
        dlg->setNextHop1stReq(call_profile.next_hop_1st_req);
        dlg->setNextHopFixed(call_profile.next_hop_fixed);
    }

    DBG("patch_ruri_next_hop = %i",call_profile.patch_ruri_next_hop);
    dlg->setPatchRURINextHop(call_profile.patch_ruri_next_hop);

    // was read from caller but reading directly from profile now
    if (call_profile.outbound_interface_value >= 0) {
        dlg->setOutboundInterface(call_profile.outbound_interface_value);
        dlg->setOutboundAddrType(AT_V4);
        dlg->setOutboundProtoId(0);
    }

    // was read from caller but reading directly from profile now
    if (call_profile.rtprelay_enabled || call_profile.transcoder.isActive()) {

        if (call_profile.rtprelay_interface_value >= 0)
            setRtpInterface(call_profile.rtprelay_interface_value);

        setRtpRelayForceSymmetricRtp(call_profile.force_symmetric_rtp_value);
        DBG("%s\n",getRtpRelayForceSymmetricRtp() ?
            "forcing symmetric RTP (passive mode)":
            "disabled symmetric RTP (normal mode)");
        setRtpEndlessSymmetricRtp(call_profile.bleg_symmetric_rtp_nonstop);
        setRtpSymmetricRtpIgnoreRTCP(call_profile.bleg_symmetric_rtp_ignore_rtcp);

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

        // copy stats counters
        rtp_pegs = call_profile.bleg_rtp_counters;
    }

    // was read from caller but reading directly from profile now
    if (!call_profile.callid.empty())
        dlg->setCallid(call_profile.callid);

    if(!call_profile.bleg_dlg_contact_params.empty())
        dlg->setContactParams(call_profile.bleg_dlg_contact_params);

    dlg->setResolvePriority(static_cast<int>(call_profile.bleg_protocol_priority_id));

    setInviteTransactionTimeout(call_profile.inv_transaction_timeout);
    setInviteRetransmitTimeout(call_profile.inv_srv_failover_timeout);
}

int SBCCallLeg::relayEvent(AmEvent* ev)
{
    if(nullptr==call_ctx) {
        if(ev->event_id==B2BSipRequest && getOtherId().empty()) {
            B2BSipRequestEvent* req_ev = dynamic_cast<B2BSipRequestEvent*>(ev);
            assert(req_ev);
            AmSipRequest &req = req_ev->req;
            if(req.method==SIP_METH_BYE) {
                DBG("relayEvent(%p) reply 200 OK for leg without call_ctx and other_id",to_void(this));
                dlg->reply(req,200,"OK");
                delete ev;
                return 0;
            }
        }
        DBG("relayEvent(%p) zero ctx. ignore event",to_void(this));
        return -1;
    }

    AmOfferAnswer::OAState dlg_oa_state = dlg->getOAState();

    switch (ev->event_id) {
    case B2BSipRequest: {
        B2BSipRequestEvent* req_ev = dynamic_cast<B2BSipRequestEvent*>(ev);
        assert(req_ev);

        AmSipRequest &req = req_ev->req;

        DBG("Yeti::relayEvent(%p) filtering request '%s' (c/t '%s') oa_state = %d\n",
            to_void(this),req.method.c_str(), req.body.getCTStr().c_str(),
            dlg_oa_state);

        try {
            int res;
            if(req.method==SIP_METH_ACK){
                //ACK can contain only answer
                dump_SdpMedia(call_ctx->bleg_negotiated_media,"bleg_negotiated media_pre");
                dump_SdpMedia(call_ctx->aleg_negotiated_media,"aleg_negotiated media_pre");

                res = processSdpAnswer(
                    this,
                    req.body, req.method,
                    call_ctx->get_other_negotiated_media(a_leg),
                    a_leg ? call_profile.bleg_single_codec : call_profile.aleg_single_codec,
                    call_profile.filter_noaudio_streams,
                    //ACK request MUST contain SDP answer if we sent offer in reply
                    dlg_oa_state==AmOfferAnswer::OA_OfferSent
                );

                dump_SdpMedia(call_ctx->bleg_negotiated_media,"bleg_negotiated media_post");
                dump_SdpMedia(call_ctx->aleg_negotiated_media,"aleg_negotiated media_post");

            } else {
                res = processSdpOffer(
                    call_profile,
                    req.body, req.method,
                    call_ctx->get_self_negotiated_media(a_leg),
                    a_leg ? call_profile.static_codecs_aleg_id : call_profile.static_codecs_bleg_id
                );
                if(res>=0){
                    res = filterSdpOffer(
                        this,
                        call_profile,
                        req.body, req.method,
                        a_leg ? call_profile.static_codecs_bleg_id : call_profile.static_codecs_aleg_id
                    );
                }
            }
            if (res < 0) {
                delete ev;
                return res;
            }
        } catch(InternalException &exception){
            DBG("got internal exception %d on request processing",exception.icode);
            delete ev;
            return -448;
        }

        inplaceHeaderPatternFilter(
            req.hdrs,
            a_leg ? call_profile.headerfilter_a2b : call_profile.headerfilter_b2a);

        if((a_leg && call_profile.keep_vias)
            || (!a_leg && call_profile.bleg_keep_vias))
        {
            req.hdrs = req.vias +req.hdrs;
        }
    } break;
    case B2BSipReply: {
        B2BSipReplyEvent* reply_ev = dynamic_cast<B2BSipReplyEvent*>(ev);
        assert(reply_ev);

        AmSipReply &reply = reply_ev->reply;

        reply.rseq = 0;

        if(call_ctx->transfer_intermediate_state &&
           reply.cseq_method==SIP_METH_INVITE)
        {
            if(!call_ctx->referrer_session.empty()) {
                DBG("generate Notfy event %d/%s for referrer leg: %s",
                    reply.code,reply.reason.c_str(),
                    call_ctx->referrer_session.c_str());
                if(!AmSessionContainer::instance()->postEvent(
                    call_ctx->referrer_session,
                    new B2BNotifyEvent(
                        static_cast<int>(reply.code),reply.reason)))
                {
                    call_ctx->referrer_session.clear();
                }
                if(reply.code >= 200) {
                    call_ctx->referrer_session.clear();
                }
            }
        }

        DBG("Yeti::relayEvent(%p) filtering body for reply %d cseq.method '%s' (c/t '%s') oa_state = %d\n",
            to_void(this),reply.code,reply_ev->trans_method.c_str(), reply.body.getCTStr().c_str(),
            dlg_oa_state);

        //append headers for 200 OK reply in direction B -> A
        inplaceHeaderPatternFilter(
            reply.hdrs,
            a_leg ? call_profile.headerfilter_a2b : call_profile.headerfilter_b2a
        );

        do {
            if(!a_leg){
                if(!call_profile.aleg_append_headers_reply.empty() &&
                   (reply.code==200 || (reply.code >=180 && reply.code < 190)))
                {
                    size_t start_pos = 0;
                    while (start_pos<call_profile.aleg_append_headers_reply.length()) {
                        int res;
                        size_t name_end, val_begin, val_end, hdr_end;
                        if ((res = skip_header(call_profile.aleg_append_headers_reply, start_pos, name_end, val_begin,
                                val_end, hdr_end)) != 0) {
                            ERROR("skip_header for '%s' pos: %ld, return %d",
                                    call_profile.aleg_append_headers_reply.c_str(),start_pos,res);
                            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
                        }
                        string hdr_name = call_profile.aleg_append_headers_reply.substr(start_pos, name_end-start_pos);
                        start_pos = hdr_end;
                        while(!getHeader(reply.hdrs,hdr_name).empty()){
                            removeHeader(reply.hdrs,hdr_name);
                        }
                    }
                    assertEndCRLF(call_profile.aleg_append_headers_reply);
                    reply.hdrs+=call_profile.aleg_append_headers_reply;
                }

                if(call_profile.suppress_early_media
                    && reply.code>=180
                    && reply.code < 190)
                {
                    DBG("convert B->A reply %d %s to %d %s and clear body",
                        reply.code,reply.reason.c_str(),
                        180,SIP_REPLY_RINGING);

                    //patch code and reason
                    reply.code = 180;
                    reply.reason = SIP_REPLY_RINGING;
                    //сlear body
                    reply.body.clear();
                    break;
                }
            }

            try {
                int res;
                if(dlg_oa_state==AmOfferAnswer::OA_OfferRecved){
                    DBG("relayEvent(): process offer in reply");
                    res = processSdpOffer(
                        call_profile,
                        reply.body, reply.cseq_method,
                        call_ctx->get_self_negotiated_media(a_leg),
                        a_leg ? call_profile.static_codecs_aleg_id : call_profile.static_codecs_bleg_id,
                        false,
                        a_leg ? call_profile.aleg_single_codec : call_profile.bleg_single_codec
                    );
                    if(res>=0){
                        res = filterSdpOffer(
                            this,
                            call_profile,
                            reply.body, reply.cseq_method,
                            a_leg ? call_profile.static_codecs_bleg_id : call_profile.static_codecs_aleg_id
                        );
                    }
                } else {
                    DBG("relayEvent(): process asnwer in reply");
                    res = processSdpAnswer(
                        this,
                        reply.body, reply.cseq_method,
                        call_ctx->get_other_negotiated_media(a_leg),
                        a_leg ? call_profile.bleg_single_codec : call_profile.aleg_single_codec,
                        call_profile.filter_noaudio_streams,
                        //final positive reply MUST contain SDP answer if we sent offer
                        (dlg_oa_state==AmOfferAnswer::OA_OfferSent
                            && reply.code >= 200 && reply.code < 300)
                    );
                }

                if(res<0){
                    terminateLegOnReplyException(
                        reply,
                        InternalException(DC_REPLY_SDP_GENERIC_EXCEPTION,
                                          call_ctx->getOverrideId(a_leg)));
                    delete ev;
                    return -488;
                }
            } catch(InternalException &exception){
                DBG("got internal exception %d on reply processing",exception.icode);
                terminateLegOnReplyException(reply,exception);
                delete ev;
                return -488;
            }
        } while(0);

    } break;
    } //switch (ev->event_id)
    return CallLeg::relayEvent(ev);
}

SBCCallLeg::~SBCCallLeg()
{
    DBG("~SBCCallLeg[%p]",to_void(this));

    if (auth)
        delete auth;
    if (logger) dec_ref(logger);
    if(sensor) dec_ref(sensor);
}

void SBCCallLeg::onBeforeDestroy()
{
    DBG("%s(%p|%s,leg%s)",FUNC_NAME,
        to_void(this),getLocalTag().c_str(),a_leg?"A":"B");

    if(call_profile.record_audio) {
        AmAudioFileRecorderProcessor::instance()->removeRecorder(getLocalTag());
    }

    if(!call_ctx) return;

    call_ctx->lock();

    if(call_ctx->dec_and_test()) {
        DBG("last leg destroy");
        SqlCallProfile *p = call_ctx->getCurrentProfile();
        if(nullptr!=p) rctl.put(p->resource_handler);
        Cdr *cdr = call_ctx->cdr;
        if(cdr) {
            cdr_list.remove(cdr);
            router.write_cdr(cdr,true);
        }
        call_ctx->unlock();
        delete call_ctx;
    } else {
        call_ctx->unlock();
    }
    call_ctx = nullptr;
}

UACAuthCred* SBCCallLeg::getCredentials()
{
    if (a_leg) return &call_profile.auth_aleg_credentials;
    else return &call_profile.auth_credentials;
}

void SBCCallLeg::onSipRequest(const AmSipRequest& req)
{
    // AmB2BSession does not call AmSession::onSipRequest for
    // forwarded requests - so lets call event handlers here
    // todo: this is a hack, replace this by calling proper session
    // event handler in AmB2BSession
    bool fwd = sip_relay_only && (req.method != SIP_METH_CANCEL);
    if (fwd) {
        CALL_EVENT_H(onSipRequest,req);
    }

    do {
        DBG("onInDialogRequest(%p|%s,leg%s) '%s'",to_void(this),getLocalTag().c_str(),a_leg?"A":"B",req.method.c_str());

        if(!call_ctx || !call_ctx->initial_invite)
            break;

        if(req.method == SIP_METH_OPTIONS
            && ((a_leg && !call_profile.aleg_relay_options)
                || (!a_leg && !call_profile.bleg_relay_options)))
        {
            dlg->reply(req, 200, "OK", nullptr, "", SIP_FLAGS_VERBATIM);
            return;
        } else if(req.method == SIP_METH_UPDATE
                  && ((a_leg && !call_profile.aleg_relay_update)
                      || (!a_leg && !call_profile.bleg_relay_update)))
        {
            getCtx_chained;

            const AmMimeBody* sdp_body = req.body.hasContentType(SIP_APPLICATION_SDP);
            if(!sdp_body){
                DBG("got UPDATE without body. local processing enabled. generate 200OK without SDP");
                AmSipRequest upd_req(req);
                processLocalRequest(upd_req);
                return;
            }

            AmSdp sdp;
            int res = sdp.parse(reinterpret_cast<const char *>(sdp_body->getPayload()));
            if(0 != res) {
                DBG("SDP parsing failed: %d. respond with 488\n",res);
                dlg->reply(req,488,"Not Acceptable Here");
                return;
            }

            AmSipRequest upd_req(req);
            try {
                int res = processSdpOffer(
                    call_profile,
                    upd_req.body, upd_req.method,
                    call_ctx->get_self_negotiated_media(a_leg),
                    a_leg ? call_profile.static_codecs_aleg_id : call_profile.static_codecs_bleg_id,
                    true,
                    a_leg ? call_profile.aleg_single_codec : call_profile.bleg_single_codec
                );
                if (res < 0) {
                    dlg->reply(req,488,"Not Acceptable Here");
                    return;
                }
            } catch(InternalException &e){
                dlg->reply(req,e.response_code,e.response_reason);
                return;
            }

            processLocalRequest(upd_req);
            return;
        } else if(req.method == SIP_METH_PRACK
                  && ((a_leg && !call_profile.aleg_relay_prack)
                      || (!a_leg && !call_profile.bleg_relay_prack)))
        {
            dlg->reply(req,200, "OK", nullptr, "", SIP_FLAGS_VERBATIM);
            return;
        } else if(req.method == SIP_METH_INVITE)
        {
            getCtx_chained;

            if((a_leg && call_profile.aleg_relay_reinvite)
                || (!a_leg && call_profile.bleg_relay_reinvite))
            {
                DBG("skip local processing. relay");
                break;
            }

            const AmMimeBody* sdp_body = req.body.hasContentType(SIP_APPLICATION_SDP);
            if(!sdp_body){
                DBG("got reINVITE without body. local processing enabled. generate 200OK with SDP offer");
                DBG("replying 100 Trying to INVITE to be processed locally");
                dlg->reply(req, 100, SIP_REPLY_TRYING);
                AmSipRequest inv_req(req);
                processLocalRequest(inv_req);
                return;
            }

            AmSdp sdp;
            int res = sdp.parse(reinterpret_cast<const char *>(sdp_body->getPayload()));
            if(0 != res) {
                DBG("replying 100 Trying to INVITE to be processed locally");
                dlg->reply(req, 100, SIP_REPLY_TRYING);
                DBG("SDP parsing failed: %d. respond with 488\n",res);
                dlg->reply(req,488,"Not Acceptable Here");
                return;
            }

            //check for hold/unhold request to pass them transparently
            HoldMethod method;
            if(isHoldRequest(sdp,method)){
                DBG("hold request matched. relay_hold = %d",
                    a_leg?call_profile.aleg_relay_hold:call_profile.bleg_relay_hold);

                if((a_leg && call_profile.aleg_relay_hold)
                    || (!a_leg && call_profile.bleg_relay_hold))
                {
                    DBG("skip local processing for hold request");
                    call_ctx->on_hold = true;
                    break;
                }
            } else if(call_ctx->on_hold){
                DBG("we in hold state. skip local processing for unhold request");
                call_ctx->on_hold = false;
                break;
            }

            DBG("replying 100 Trying to INVITE to be processed locally");
            dlg->reply(req, 100, SIP_REPLY_TRYING);

            AmSipRequest inv_req(req);
            try {
                int res = processSdpOffer(
                    call_profile,
                    inv_req.body, inv_req.method,
                    call_ctx->get_self_negotiated_media(a_leg),
                    a_leg ? call_profile.static_codecs_aleg_id : call_profile.static_codecs_bleg_id,
                    true,
                    a_leg ? call_profile.aleg_single_codec : call_profile.bleg_single_codec
                );
                if (res < 0) {
                    dlg->reply(req,488,"Not Acceptable Here");
                    return;
                }
            } catch(InternalException &e){
                dlg->reply(req,e.response_code,e.response_reason);
                return;
            }

            processLocalRequest(inv_req);
            return;
        } else if(req.method==SIP_METH_REFER) {
            if(a_leg) {
                dlg->reply(req,603,"Refer is not allowed for Aleg");
                return;
            }
            if(getOtherId().empty()) {
                dlg->reply(req,603,"Refer is not possible at this stage");
                return;
            }

            if(call_profile.bleg_max_transfers <= 0) {
                dlg->reply(req,603,"Refer is not allowed");
                return;
            }
            string refer_to = getHeader(
                req.hdrs,
                SIP_HDR_REFER_TO,SIP_HDR_REFER_TO_COMPACT,
                true);

            if(refer_to.empty()) {
                dlg->reply(req,400,"Refer-To header missing");
                return;
            }

            sip_nameaddr refer_to_nameaddr;
            const char *refer_to_ptr = refer_to.c_str();
            if(0!=parse_nameaddr(&refer_to_nameaddr,
                &refer_to_ptr,static_cast<int>(refer_to.length())))
            {
                DBG("failed to parse Refer-To header: %s",refer_to.c_str());
                dlg->reply(req,400,"Invalid Refer-To header");
                return;
            }
            refer_to = c2stlstr(refer_to_nameaddr.addr);

            if(!subs->onRequestIn(req))
                return;

            last_refer_cseq = int2str(req.cseq); //memorize cseq to send NOTIFY

            dlg->reply(req,202,"Accepted");

            relayEvent(new B2BReferEvent(getLocalTag(),refer_to)); //notify Aleg about Refer
            clearRtpReceiverRelay(); //disconnect B2BMedia
            AmB2BSession::clear_other(); //forget about Aleg

            call_ctx->dec(); //release ctx reference
            call_ctx = nullptr; //forget about ctx

            return;
        }

        if(a_leg){
            if(req.method==SIP_METH_CANCEL){
                getCtx_chained;
                with_cdr_for_read {
                    cdr->update_internal_reason(DisconnectByORG,"Request terminated (Cancel)",487);
                }
            }
        }
    } while(0);

    if (fwd && req.method == SIP_METH_INVITE) {
        DBG("replying 100 Trying to INVITE to be fwd'ed\n");
        dlg->reply(req, 100, SIP_REPLY_TRYING);
    }

    CallLeg::onSipRequest(req);
}

void SBCCallLeg::setOtherId(const AmSipReply& reply)
{
    DBG("setting other_id to '%s'",reply.from_tag.c_str());
    setOtherId(reply.from_tag);
}

void SBCCallLeg::onInitialReply(B2BSipReplyEvent *e)
{
    CallLeg::onInitialReply(e);
}

void SBCCallLeg::onSipReply(const AmSipRequest& req, const AmSipReply& reply,
			   AmBasicSipDialog::Status old_dlg_status)
{
    TransMap::iterator t = relayed_req.find(static_cast<int>(reply.cseq));
    bool fwd = t != relayed_req.end();

    DBG("onSipReply: %i %s (fwd=%i)\n",reply.code,reply.reason.c_str(),fwd);
    DBG("onSipReply: content-type = %s\n",reply.body.getCTStr().c_str());
    if (fwd) {
        CALL_EVENT_H(onSipReply, req, reply, old_dlg_status);
    }

    if (nullptr != auth) {
        // only for SIP authenticated
        unsigned int cseq_before = dlg->cseq;
        if (auth->onSipReply(req, reply, old_dlg_status)) {
            if (cseq_before != dlg->cseq) {
                DBG("uac_auth consumed reply with cseq %d and resent with cseq %d; "
                    "updating relayed_req map\n", reply.cseq, cseq_before);
                updateUACTransCSeq(reply.cseq, cseq_before);
                // don't relay to other leg, process in AmSession
                AmSession::onSipReply(req, reply, old_dlg_status);
                // skip presenting reply to ext_cc modules, too
                return;
            }
        }
    }

    if(!a_leg && call_ctx) {
        if(call_ctx->transfer_intermediate_state &&
           reply.cseq_method==SIP_METH_INVITE)
        {
            if(reply.code >= 200 && reply.code < 300) {
                dlg->send_200_ack(reply.cseq);
            }
        } else {
            with_cdr_for_read
                cdr->update(reply);
        }
    }

    CallLeg::onSipReply(req, reply, old_dlg_status);
}

void SBCCallLeg::onSendRequest(AmSipRequest& req, int &flags)
{
    DBG("Yeti::onSendRequest(%p|%s) a_leg = %d",
        to_void(this),getLocalTag().c_str(),a_leg);

    if(call_ctx &&
       !a_leg &&
       call_ctx->referrer_session.empty() &&
        req.method==SIP_METH_INVITE)
    {
        with_cdr_for_read cdr->update(BLegInvite);
    }

    if(a_leg) {
        if (!call_profile.aleg_append_headers_req.empty()) {
            size_t start_pos = 0;
            while (start_pos<call_profile.aleg_append_headers_req.length()) {
                int res;
                size_t name_end, val_begin, val_end, hdr_end;
                if ((res = skip_header(call_profile.aleg_append_headers_req, start_pos, name_end, val_begin,
                     val_end, hdr_end)) != 0)
                {
                    ERROR("skip_header for '%s' pos: %ld, return %d",
                        call_profile.aleg_append_headers_req.c_str(),start_pos,res);
                    throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
                }
                string hdr_name = call_profile.aleg_append_headers_req.substr(start_pos, name_end-start_pos);
                start_pos = hdr_end;
                while(!getHeader(req.hdrs,hdr_name).empty()){
                    removeHeader(req.hdrs,hdr_name);
                }
            }
            DBG("appending '%s' to outbound request (A leg)\n",
            call_profile.aleg_append_headers_req.c_str());
            req.hdrs+=call_profile.aleg_append_headers_req;
        }
    } else {
        size_t start_pos = 0;
        while (start_pos<call_profile.append_headers_req.length()) {
            int res;
            size_t name_end, val_begin, val_end, hdr_end;
            if ((res = skip_header(call_profile.append_headers_req, start_pos, name_end, val_begin,
                 val_end, hdr_end)) != 0)
            {
                ERROR("skip_header for '%s' pos: %ld, return %d",
                    call_profile.append_headers_req.c_str(),start_pos,res);
                throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
            }
            string hdr_name = call_profile.append_headers_req.substr(start_pos, name_end-start_pos);
            start_pos = hdr_end;
            while(!getHeader(req.hdrs,hdr_name).empty()){
                removeHeader(req.hdrs,hdr_name);
            }
        }
        if (!call_profile.append_headers_req.empty()) {
            DBG("appending '%s' to outbound request (B leg)\n",
                call_profile.append_headers_req.c_str());
            req.hdrs+=call_profile.append_headers_req;
        }
    }

    if (nullptr != auth) {
        DBG("auth->onSendRequest cseq = %d\n", req.cseq);
        auth->onSendRequest(req, flags);
    }

    CallLeg::onSendRequest(req, flags);
}

void SBCCallLeg::onRemoteDisappeared(const AmSipReply& reply)
{
    const static string reinvite_failed("reINVITE failed");

    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");

    if(call_ctx) {
        if(a_leg){
            //trace available values
            if(call_ctx->initial_invite!=nullptr) {
                AmSipRequest &req = *call_ctx->initial_invite;
                DBG("req.method = '%s'",req.method.c_str());
            } else {
                ERROR("intial_invite == NULL");
            }
            with_cdr_for_read {
                cdr->update_internal_reason(DisconnectByTS,reply.reason,reply.code);
            }
        }
        if(getCallStatus()==CallLeg::Connected) {
            with_cdr_for_read {
                cdr->update_internal_reason(
                    DisconnectByTS,
                    reinvite_failed, 200
                );
                cdr->update_bleg_reason("Bye",200);
            }
        }
    }
    CallLeg::onRemoteDisappeared(reply);
}

void SBCCallLeg::onBye(const AmSipRequest& req)
{
    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");
    if(!call_ctx) return;
    with_cdr_for_read {
        if(getCallStatus()!=CallLeg::Connected) {
            if(a_leg) {
                DBG("received Bye in not connected state");
                cdr->update_internal_reason(DisconnectByORG,"EarlyBye",500);
                cdr->update_aleg_reason("EarlyBye",200);
                cdr->update_bleg_reason("Cancel",487);
            } else {
                DBG("generate reply for early BYE on Bleg and force leg termination");
                cdr->update_bleg_reason("EarlyBye",200);
                dlg->reply(req,200,"OK");
                terminateLeg();
                return;
            }
        } else {
            cdr->update_internal_reason(a_leg ? DisconnectByORG : DisconnectByDST,"Bye",200);
            cdr->update_bleg_reason("Bye",200);
        }
    }
    CallLeg::onBye(req);
}

void SBCCallLeg::onOtherBye(const AmSipRequest& req)
{
    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");
    if(call_ctx && a_leg) {
        if(getCallStatus()!=CallLeg::Connected) {
            //avoid considering of bye in not connected state as succ call
            DBG("received OtherBye in not connected state");
            with_cdr_for_write {
                cdr->update_internal_reason(DisconnectByDST,"EarlyBye",500);
                cdr->update_aleg_reason("Request terminated",487);
                cdr_list.remove(cdr);
                router.write_cdr(cdr,true);
            }
        }
    }
    CallLeg::onOtherBye(req);
}

void SBCCallLeg::onDtmf(AmDtmfEvent* e)
{
    DBG("received DTMF on %cleg (%i;%i) source:%d",
        a_leg ? 'A': 'B',
        e->event(), e->duration(), e->event_id);

    int rx_proto = 0;
    struct timeval now;

    gettimeofday(&now, nullptr);

    switch(e->event_id) {
    case Dtmf::SOURCE_SIP:
        rx_proto = DTMF_RX_MODE_INFO;
        break;
    case Dtmf::SOURCE_RTP:
        rx_proto = DTMF_RX_MODE_RFC2833;
        break;
    case Dtmf::SOURCE_INBAND:
        rx_proto = DTMF_RX_MODE_INBAND;
        break;
    default:
        WARN("unexpected dtmf source: %d. ignore event",e->event_id);
        return;
    }

    if(!(a_leg ?
        call_profile.aleg_dtmf_recv_modes&rx_proto :
        call_profile.bleg_dtmf_recv_modes&rx_proto))
    {
        DBG("DTMF event for leg %p rejected",to_void(this));
        e->processed = true;
        //write with zero tx_proto
        with_cdr_for_read cdr->add_dtmf_event(a_leg,e->event(),now,rx_proto,DTMF_TX_MODE_DISABLED);
        return;
    }

    //choose outgoing method
    int send_method = a_leg ?
                        call_profile.bleg_dtmf_send_mode_id :
                        call_profile.aleg_dtmf_send_mode_id;

    with_cdr_for_read cdr->add_dtmf_event(a_leg,e->event(),now,rx_proto,send_method);

    switch(send_method){
    case DTMF_TX_MODE_DISABLED:
        DBG("dtmf sending is disabled");
        break;
    case DTMF_TX_MODE_RFC2833: {
        DBG("send mode RFC2833 choosen for dtmf event for leg %p",to_void(this));
        AmB2BMedia *ms = getMediaSession();
        if(ms) {
            DBG("sending DTMF (%i;%i)\n", e->event(), e->duration());
            ms->sendDtmf(!a_leg,
                e->event(),static_cast<unsigned int>(e->duration()));
        }
    } break;
    case DTMF_TX_MODE_INFO_DTMF_RELAY:
        DBG("send mode INFO/application/dtmf-relay choosen for dtmf event for leg %p",
            to_void(this));
        relayEvent(new yeti_dtmf::DtmfInfoSendEventDtmfRelay(e));
        break;
    case DTMF_TX_MODE_INFO_DTMF:
        DBG("send mode INFO/application/dtmf choosen for dtmf event for leg %p",
            to_void(this));
        relayEvent(new yeti_dtmf::DtmfInfoSendEventDtmf(e));
        break;
    default:
        ERROR("unsupported dtmf send method %d. stop processing",send_method);
        break;
    }
}

void SBCCallLeg::updateLocalSdp(AmSdp &sdp)
{
    // anonymize SDP if configured to do so (we need to have our local media IP,
    // not the media IP of our peer leg there)
    normalizeSDP(sdp, true, advertisedIP());

    // remember transcodable payload IDs
    //if (call_profile.transcoder.isActive()) savePayloadIDs(sdp);
    CallLeg::updateLocalSdp(sdp);
}

void SBCCallLeg::onControlCmd(string& cmd, AmArg& params)
{
    if (cmd == "teardown") {
        if (a_leg) {
            // was for caller:
            DBG("teardown requested from control cmd\n");
            stopCall("ctrl-cmd");
            // FIXME: don't we want to relay the controll event as well?
        } else {
            // was for callee:
            DBG("relaying teardown control cmd to A leg\n");
            relayEvent(new SBCControlEvent(cmd, params));
            // FIXME: don't we want to stopCall as well?
        }
        return;
    }
    DBG("ignoring unknown control cmd : '%s'\n", cmd.c_str());
}


void SBCCallLeg::process(AmEvent* ev)
{
    DBG("%s(%p|%s,leg%s)",FUNC_NAME,to_void(this),
        getLocalTag().c_str(),a_leg?"A":"B");

    do {
        getCtx_chained
        RadiusReplyEvent *radius_event = dynamic_cast<RadiusReplyEvent*>(ev);
        if(radius_event){
            onRadiusReply(*radius_event);
            return;
        }

        if(RedisReplyEvent *redis_event = dynamic_cast<RedisReplyEvent *>(ev)) {
            onRedisReply(*redis_event);
            return;
        }

        AmRtpTimeoutEvent *rtp_event = dynamic_cast<AmRtpTimeoutEvent*>(ev);
        if(rtp_event){
            DBG("rtp event id: %d",rtp_event->event_id);
            onRtpTimeoutOverride(*rtp_event);
            return;
        }

        AmSipRequestEvent *request_event = dynamic_cast<AmSipRequestEvent*>(ev);
        if(request_event){
            AmSipRequest &req = request_event->req;
            DBG("request event method: %s",
                req.method.c_str());
        }

        AmSipReplyEvent *reply_event = dynamic_cast<AmSipReplyEvent*>(ev);
        if(reply_event){
            AmSipReply &reply = reply_event->reply;
            DBG("reply event  code: %d, reason:'%s'",
                reply.code,reply.reason.c_str());
            //!TODO: find appropiate way to avoid hangup in disconnected state
            if(reply.code==408 && getCallStatus()==CallLeg::Disconnected){
                DBG("received 408 in disconnected state. a_leg = %d, local_tag: %s",
                    a_leg, getLocalTag().c_str());
                throw AmSession::Exception(500,SIP_REPLY_SERVER_INTERNAL_ERROR);
            }
        }

        AmSipRedirect *redirect_event = dynamic_cast<AmSipRedirect*>(ev);
        if(redirect_event) {
            with_cdr_for_read
                cdr->is_redirected = true;
            return;
        }

        AmPluginEvent* plugin_event = dynamic_cast<AmPluginEvent*>(ev);
        if(plugin_event){
            DBG("%s plugin_event. name = %s, event_id = %d",FUNC_NAME,
                plugin_event->name.c_str(),
                plugin_event->event_id);
            if(plugin_event->name=="timer_timeout"){
                if(onTimerEvent(plugin_event->data.get(0).asInt()))
                    return;
            }
        }

        SBCControlEvent* sbc_event = dynamic_cast<SBCControlEvent*>(ev);
        if(sbc_event){
            DBG("sbc event id: %d, cmd: %s",sbc_event->event_id,sbc_event->cmd.c_str());
            onControlEvent(sbc_event);
        }

        B2BEvent* b2b_e = dynamic_cast<B2BEvent*>(ev);
        if(b2b_e){
            if(b2b_e->event_id == B2BSipReply){
                B2BSipReplyEvent* b2b_reply_e = dynamic_cast<B2BSipReplyEvent*>(b2b_e);
                if(dlg->checkReply100rel(b2b_reply_e->reply)) {
                    DBG("[%s] reply event (%d %s) postponed by 100rel extension",
                        getLocalTag().c_str(),
                        b2b_reply_e->reply.code,b2b_reply_e->reply.reason.c_str());
                    postponed_replies.emplace(new B2BSipReplyEvent(*b2b_reply_e));
                    return;
                }
            }
            if(b2b_e->event_id==B2BTerminateLeg){
                DBG("onEvent(%p|%s) terminate leg event",
                    to_void(this),getLocalTag().c_str());
            }
        }

        if (ev->event_id == E_SYSTEM) {
            AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev);
            if(sys_ev){
                DBG("sys event type: %d",sys_ev->sys_event);
                    onSystemEventOverride(sys_ev);
            }
        }

        yeti_dtmf::DtmfInfoSendEvent *dtmf = dynamic_cast<yeti_dtmf::DtmfInfoSendEvent*>(ev);
        if(dtmf) {
            DBG("onEvent dmtf(%d:%d)",dtmf->event(),dtmf->duration());
            dtmf->send(dlg);
            ev->processed = true;
            return;
        }
    } while(0);

    if (a_leg) {
        // was for caller (SBCDialog):
        AmPluginEvent* plugin_event = dynamic_cast<AmPluginEvent*>(ev);
        if(plugin_event && plugin_event->name == "timer_timeout") {
            int timer_id = plugin_event->data.get(0).asInt();
            if (timer_id >= SBC_TIMER_ID_CALL_TIMERS_START &&
                timer_id <= SBC_TIMER_ID_CALL_TIMERS_END)
            {
                DBG("timer %d timeout, stopping call\n", timer_id);
                stopCall("timer");
                ev->processed = true;
            }
        }

        SBCCallTimerEvent* ct_event;
        if (ev->event_id == SBCCallTimerEvent_ID &&
            (ct_event = dynamic_cast<SBCCallTimerEvent*>(ev)) != nullptr)
        {
            switch (m_state) {
            case BB_Connected:
                switch (ct_event->timer_action) {
                case SBCCallTimerEvent::Remove:
                    DBG("removing timer %d on call timer request\n", ct_event->timer_id);
                    removeTimer(ct_event->timer_id);
                    return;
                case SBCCallTimerEvent::Set:
                    DBG("setting timer %d to %f on call timer request\n",
                        ct_event->timer_id, ct_event->timeout);
                    setTimer(ct_event->timer_id, ct_event->timeout);
                    return;
                case SBCCallTimerEvent::Reset:
                    DBG("resetting timer %d to %f on call timer request\n",
                        ct_event->timer_id, ct_event->timeout);
                    removeTimer(ct_event->timer_id);
                    setTimer(ct_event->timer_id, ct_event->timeout);
                    return;
                }
                ERROR("unknown timer_action %d in sbc call timer event\n",
                      ct_event->timer_action);
                return;
            case BB_Init:
            case BB_Dialing:
                switch (ct_event->timer_action) {
                case SBCCallTimerEvent::Remove:
                    clearCallTimer(ct_event->timer_id);
                    return;
                case SBCCallTimerEvent::Set:
                case SBCCallTimerEvent::Reset:
                    saveCallTimer(ct_event->timer_id, ct_event->timeout);
                    return;
                }
                ERROR("unknown timer_action %d in sbc call timer event\n",
                      ct_event->timer_action);
                return;
            default:
                break;
            }
        }
    }

    SBCControlEvent* ctl_event;
    if (ev->event_id == SBCControlEvent_ID &&
        (ctl_event = dynamic_cast<SBCControlEvent*>(ev)) != nullptr)
    {
        onControlCmd(ctl_event->cmd, ctl_event->params);
        return;
    }

    SBCOtherLegExceptionEvent *exception_event;
    if(ev->event_id == SBCExceptionEvent_ID &&
       (exception_event = dynamic_cast<SBCOtherLegExceptionEvent*>(ev)) != nullptr)
    {
        onOtherException(exception_event->code,exception_event->reason);
    }

    if(dynamic_cast<ProvisionalReplyConfirmedEvent*>(ev)) {
        if(!postponed_replies.empty()) {
            DBG("we have %ld postponed replies on ProvisionalReplyConfirmedEvent. "
                "process first of them",
                postponed_replies.size());
            //replace ProvisionalReplyConfirmedEvent with B2BSipReplyEvent
            ev = postponed_replies.front().release();
            postponed_replies.pop();
        }
    }

    if(B2BEvent* b2b_e = dynamic_cast<B2BEvent*>(ev)) {
        switch(b2b_e->event_id) {
        case B2BRefer: {
            B2BReferEvent *refer = dynamic_cast<B2BReferEvent *>(b2b_e);
            if(refer) onOtherRefer(*refer);
            return;
        }
        case B2BNotify: {
            B2BNotifyEvent *notify = dynamic_cast<B2BNotifyEvent *>(b2b_e);
            if(notify) {
                sendReferNotify(notify->code,notify->reason);
                //TODO: set timer here for final code
            }
            return;
        }
        default:
            break;
        }
    }

    CallLeg::process(ev);
}


//////////////////////////////////////////////////////////////////////////////////////////
// was for caller only (SBCDialog)
// FIXME: move the stuff related to CC interface outside of this class?


#define REPLACE_VALS req, app_param, ruri_parser, from_parser, to_parser

void SBCCallLeg::onInvite(const AmSipRequest& req)
{
    DBG("processing initial INVITE %s\n", req.r_uri.c_str());

    ctx.call_profile = &call_profile;
    ctx.app_param = getHeader(req.hdrs, PARAM_HDR, true);

    init();

    modified_req = req;
    aleg_modified_req = req;
    uac_req = req;

    if (!logger &&
        !call_profile.get_logger_path().empty() &&
        (call_profile.log_sip || call_profile.log_rtp))
    {
        // open the logger if not already opened
        ParamReplacerCtx ctx(&call_profile);
        string log_path = ctx.replaceParameters(call_profile.get_logger_path(), "msg_logger_path",req);
        if(!openLogger(log_path)){
            WARN("can't open msg_logger_path: '%s'",log_path.c_str());
        }
    }

    req.log(call_profile.log_sip?getLogger():nullptr,
            call_profile.aleg_sensor_level_id&LOG_SIP_MASK?getSensor():nullptr);

    uac_ruri.uri = uac_req.r_uri;
    if(!uac_ruri.parse_uri()) {
        DBG("Error parsing R-URI '%s'\n",uac_ruri.uri.c_str());
        throw AmSession::Exception(400,"Failed to parse R-URI");
    }

    call_ctx->cdr->update(req);
    call_ctx->initial_invite = new AmSipRequest(aleg_modified_req);

    if(yeti.config.early_100_trying) {
        msg_logger *logger = getLogger();
        if(logger){
            call_ctx->early_trying_logger->relog(logger);
        }
    } else {
        dlg->reply(req,100,"Connecting");
    }

    if(!radius_auth(this,*call_ctx->cdr,call_profile,req)) {
        processAorResolving();
    }
}

void SBCCallLeg::onRoutingReady()
{
    Cdr *cdr = call_ctx->cdr;

    if(0!=cdr_list.insert(cdr)){
        ERROR("onInitialInvite(): double insert into active calls list. integrity threat");
        ERROR("ctx: attempt = %d, cdr.logger_path = %s",
            call_ctx->attempt_num,cdr->msg_logger_path.c_str());
        log_stacktrace(L_ERR);
        throw AmSession::Exception(500,SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    call_profile.sst_aleg_enabled = ctx.replaceParameters(
        call_profile.sst_aleg_enabled,
        "enable_aleg_session_timer", aleg_modified_req);

    call_profile.sst_enabled = ctx.replaceParameters(
        call_profile.sst_enabled,
        "enable_session_timer", aleg_modified_req);

    if (call_profile.sst_aleg_enabled == "yes") {
        call_profile.eval_sst_config(ctx,aleg_modified_req,call_profile.sst_a_cfg);
        if(applySSTCfg(call_profile.sst_a_cfg,&aleg_modified_req) < 0) {
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
    }

    if (!call_profile.evaluate(ctx, aleg_modified_req)) {
        ERROR("call profile evaluation failed\n");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    AmUriParser uac_ruri;
    uac_ruri.uri = uac_req.r_uri;
    if(!uac_ruri.parse_uri()) {
        DBG("Error parsing R-URI '%s'\n",uac_ruri.uri.c_str());
        throw AmSession::Exception(400,"Failed to parse R-URI");
    }

    ruri = call_profile.ruri.empty() ? uac_req.r_uri : call_profile.ruri;
    if(!call_profile.ruri_host.empty()) {
        ctx.ruri_parser.uri = ruri;
        if(!ctx.ruri_parser.parse_uri()) {
            WARN("Error parsing R-URI '%s'\n", ruri.c_str());
        } else {
            ctx.ruri_parser.uri_port.clear();
            ctx.ruri_parser.uri_host = call_profile.ruri_host;
            ruri = ctx.ruri_parser.uri_str();
        }
    }

    from = call_profile.from.empty() ? aleg_modified_req.from : call_profile.from;
    to = call_profile.to.empty() ? aleg_modified_req.to : call_profile.to;

    AmUriParser from_uri, to_uri;
    if(!from_uri.parse_nameaddr(from)) {
        DBG("Error parsing From-URI '%s'\n",from.c_str());
        throw AmSession::Exception(400,"Failed to parse From-URI");
    }

    if(!to_uri.parse_nameaddr(to)) {
        DBG("Error parsing To-URI '%s'\n",to.c_str());
        throw AmSession::Exception(400,"Failed to parse To-URI");
    }

    from = from_uri.nameaddr_str();
    to = to_uri.nameaddr_str();

    applyAProfile();
    call_profile.apply_a_routing(ctx,aleg_modified_req,*dlg);

    m_state = BB_Dialing;

    // prepare request to relay to the B leg(s)

    if(a_leg && call_profile.keep_vias)
        modified_req.hdrs = modified_req.vias + modified_req.hdrs;

      est_invite_cseq = uac_req.cseq;

    removeHeader(modified_req.hdrs,PARAM_HDR);
    removeHeader(modified_req.hdrs,"P-App-Name");

    if (call_profile.sst_enabled_value) {
        removeHeader(modified_req.hdrs,SIP_HDR_SESSION_EXPIRES);
        removeHeader(modified_req.hdrs,SIP_HDR_MIN_SE);
    }

    size_t start_pos = 0;
    while (start_pos<call_profile.append_headers.length()) {
        int res;
        size_t name_end, val_begin, val_end, hdr_end;
        if ((res = skip_header(call_profile.append_headers, start_pos, name_end, val_begin,
            val_end, hdr_end)) != 0)
        {
            ERROR("skip_header for '%s' pos: %ld, return %d",
                call_profile.append_headers.c_str(),start_pos,res);
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
        string hdr_name = call_profile.append_headers.substr(start_pos, name_end-start_pos);
        while(!getHeader(modified_req.hdrs,hdr_name).empty()){
            removeHeader(modified_req.hdrs,hdr_name);
        }
        start_pos = hdr_end;
    }

    inplaceHeaderPatternFilter(modified_req.hdrs, call_profile.headerfilter_a2b);

    if (call_profile.append_headers.size() > 2) {
        string append_headers = call_profile.append_headers;
        assertEndCRLF(append_headers);
        modified_req.hdrs+=append_headers;
    }

#undef REPLACE_VALS

    DBG("SBC: connecting to '%s'\n",ruri.c_str());
    DBG("     From:  '%s'\n",from.c_str());
    DBG("     To:  '%s'\n",to.c_str());

    // we evaluated the settings, now we can initialize internals (like RTP relay)
    // we have to use original request (not the altered one) because for example
    // codecs filtered out might be used in direction to caller
    CallLeg::onInvite(aleg_modified_req);

    if (getCallStatus() == Disconnected) {
        // no CC module connected a callee yet
        connectCallee(to, ruri, from, aleg_modified_req, modified_req); // connect to the B leg(s) using modified request
    }
}

void SBCCallLeg::onInviteException(int code,string reason,bool no_reply)
{
    DBG("%s(%p,leg%s) %d:'%s' no_reply = %d",FUNC_NAME,to_void(this),a_leg?"A":"B",
        code,reason.c_str(),no_reply);

    if(!call_ctx) return;

    Cdr *cdr = call_ctx->cdr;

    cdr->lock();
    cdr->disconnect_initiator = DisconnectByTS;
    if(cdr->disconnect_internal_code==0){ //update only if not previously was setted
        cdr->disconnect_internal_code = code;
        cdr->disconnect_internal_reason = reason;
    }
    if(!no_reply){
        cdr->disconnect_rewrited_code = code;
        cdr->disconnect_rewrited_reason = reason;
    }
    cdr->unlock();
}

bool SBCCallLeg::onException(int code,const string &reason) noexcept
{
    DBG("%s(%p,leg%s) %d:'%s'",FUNC_NAME,to_void(this),a_leg?"A":"B",
        code,reason.c_str());
    with_cdr_for_read {
        cdr->update_internal_reason(DisconnectByTS,
            reason,static_cast<unsigned int>(code));
        if(!a_leg) {
            switch(dlg->getStatus()) {
            case AmBasicSipDialog::Connected:
            case AmBasicSipDialog::Disconnecting:
                cdr->update_bleg_reason("Bye",200);
                break;
            case AmBasicSipDialog::Early:
                cdr->update_bleg_reason("Request terminated",487);
                break;
            default:
                break;
            }
        } else {
            switch(dlg->getStatus()) {
            case AmBasicSipDialog::Connected:
            case AmBasicSipDialog::Disconnecting:
                cdr->update_aleg_reason("Bye",200);
                break;
            case AmBasicSipDialog::Early:
                cdr->update_aleg_reason("Request terminated",487);
                break;
            default:
                break;
            }
        }
    }
    relayEvent(new SBCOtherLegExceptionEvent(code,reason));
    terminateLeg();
    return false; //stop processing
}

void SBCCallLeg::onOtherException(int code,const string &reason) noexcept
{
    DBG("%s(%p,leg%s) %d:'%s'",FUNC_NAME,to_void(this),a_leg?"A":"B",
        code,reason.c_str());
    with_cdr_for_read {
        if(!a_leg) {
            switch(dlg->getStatus()) {
            case AmBasicSipDialog::Connected:
            case AmBasicSipDialog::Disconnecting:
                cdr->update_bleg_reason("Bye",200);
                break;
            case AmBasicSipDialog::Early:
                cdr->update_bleg_reason("Request terminated",487);
                break;
            default:
                break;
            }
        } else {
            switch(dlg->getStatus()) {
            case AmBasicSipDialog::Connected:
            case AmBasicSipDialog::Disconnecting:
                cdr->update_aleg_reason("Bye",200);
                break;
            case AmBasicSipDialog::Early:
                cdr->update_aleg_reason("Request terminated",487);
                break;
            default:
                break;
            }
        }
    }
    terminateLeg();
    postEvent(new AmEvent(0)); //force wakeup
}

void SBCCallLeg::onEarlyEventException(unsigned int code,const string &reason)
{
    setStopped();
    onInviteException(static_cast<int>(code),reason,false);
    if(code < 300){
        ERROR("%i is not final code. replace it with 500",code);
        code = 500;
    }
    dlg->reply(uac_req,code,reason);
}

void SBCCallLeg::connectCallee(
    const string& remote_party,
    const string& remote_uri,
    const string &from,
    const AmSipRequest &,
    const AmSipRequest &invite)
{
    SBCCallLeg* callee_session = SBCFactory::instance()->getCallLegCreator()->create(this);

    callee_session->setLocalParty(from, from);
    callee_session->setRemoteParty(remote_party, remote_uri);

    DBG("Created B2BUA callee leg, From: %s\n", from.c_str());

    // FIXME: inconsistent with other filtering stuff - here goes the INVITE
    // already filtered so need not to be catched (can not) in relayEvent because
    // it is sent other way
    addCallee(callee_session, invite);

    // we could start in SIP relay mode from the beginning if only one B leg, but
    // serial fork might mess it
    // set_sip_relay_only(true);
}

void SBCCallLeg::onCallConnected(const AmSipReply&)
{
    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");

    if(call_ctx) {
        if(!call_ctx->transfer_intermediate_state) {
            with_cdr_for_read {
                if(a_leg) cdr->update(Connect);
                else cdr->update(BlegConnect);
                radius_accounting_start(this,*cdr,call_profile);
            }
        } else if(!a_leg) {
            //we got final positive reply for Bleg. clear xfer intermediate state
            call_ctx->transfer_intermediate_state = false;
        }
    }

    if (a_leg) { // FIXME: really?
        m_state = BB_Connected;
        AmB2BMedia *m = getMediaSession();
        if(m) m->setRtpTimeout(dead_rtp_time);
        if (!startCallTimers())
            return;
    }
}

void SBCCallLeg::onStop()
{
    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");

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
    for (map<int, double>::iterator it=call_timers.begin();
         it != call_timers.end(); it++)
    {
        DBG("SBC: starting call timer %i of %f seconds\n", it->first, it->second);
        setTimer(it->first, it->second);
    }

    return true;
}

void SBCCallLeg::stopCallTimers() {
    for (map<int, double>::iterator it=call_timers.begin();
         it != call_timers.end(); it++)
    {
        DBG("SBC: removing call timer %i\n", it->first);
        removeTimer(it->first);
    }
}

void SBCCallLeg::onCallStatusChange(const StatusChangeCause &cause)
{
    string reason;

    if(!call_ctx) return;
    SBCCallLeg::CallStatus status = getCallStatus();
    int internal_disconnect_code = 0;

    DBG("Yeti::onStateChange(%p|%s) a_leg = %d",
        to_void(this),getLocalTag().c_str(),a_leg);

    switch(status){
    case CallLeg::Ringing: {
        if(!a_leg) {
            if(call_profile.ringing_timeout > 0)
                setTimer(YETI_RINGING_TIMEOUT_TIMER,call_profile.ringing_timeout);
        } else {
            if(call_profile.fake_ringing_timeout)
                removeTimer(YETI_FAKE_RINGING_TIMER);
            if(call_profile.force_one_way_early_media) {
                DBG("force one-way audio for early media (mute legB)");
                AmB2BMedia *m = getMediaSession();
                if(m) {
                    m->mute(false);
                    call_ctx->bleg_early_media_muted = true;
                }
            }
        }
    } break;
    case CallLeg::Connected:
        if(!a_leg) {
            removeTimer(YETI_RINGING_TIMEOUT_TIMER);
        } else {
            if(call_profile.fake_ringing_timeout)
                removeTimer(YETI_FAKE_RINGING_TIMER);
            if(call_ctx->bleg_early_media_muted) {
                AmB2BMedia *m = getMediaSession();
                if(m) m->unmute(false);
            }
        }
        break;
    case CallLeg::Disconnected:
        removeTimer(YETI_RADIUS_INTERIM_TIMER);
        if(a_leg && call_profile.fake_ringing_timeout) {
            removeTimer(YETI_FAKE_RINGING_TIMER);
        }
        break;
    default:
        break;
    }

    switch(cause.reason){
        case CallLeg::StatusChangeCause::SipReply:
            if(cause.param.reply!=nullptr){
                reason = "SipReply. code = "+int2str(cause.param.reply->code);
                switch(cause.param.reply->code){
                case 408:
                    internal_disconnect_code = DC_TRANSACTION_TIMEOUT;
                    break;
                case 487:
                    if(call_ctx->isRingingTimeout()){
                        internal_disconnect_code = DC_RINGING_TIMEOUT;
                    }
                    break;
                }
            } else
                reason = "SipReply. empty reply";
            break;
        case CallLeg::StatusChangeCause::SipRequest:
            if(cause.param.request!=nullptr){
                reason = "SipRequest. method = "+cause.param.request->method;
            } else
                reason = "SipRequest. empty request";
            break;
        case CallLeg::StatusChangeCause::Canceled:
            reason = "Canceled";
            break;
        case CallLeg::StatusChangeCause::NoAck:
            reason = "NoAck";
            internal_disconnect_code = DC_NO_ACK;
            break;
        case CallLeg::StatusChangeCause::NoPrack:
            reason = "NoPrack";
            internal_disconnect_code = DC_NO_PRACK;
            break;
        case CallLeg::StatusChangeCause::RtpTimeout:
            reason = "RtpTimeout";
            break;
        case CallLeg::StatusChangeCause::SessionTimeout:
            reason = "SessionTimeout";
            internal_disconnect_code = DC_SESSION_TIMEOUT;
            break;
        case CallLeg::StatusChangeCause::InternalError:
            reason = "InternalError";
            internal_disconnect_code = DC_INTERNAL_ERROR;
            break;
        case CallLeg::StatusChangeCause::Other:
            break;
    }

    if(status==CallLeg::Disconnected) {
        with_cdr_for_read {
            if(internal_disconnect_code) {
                unsigned int internal_code,response_code;
                string internal_reason,response_reason;

                CodesTranslator::instance()->translate_db_code(
                    static_cast<unsigned int>(internal_disconnect_code),
                    internal_code,internal_reason,
                    response_code,response_reason,
                    call_ctx->getOverrideId(a_leg));
                cdr->update_internal_reason(DisconnectByTS,internal_reason,internal_code);
            }
            radius_accounting_stop(this, *cdr);
        }
    }

    DBG("%s(%p,leg%s,state = %s, cause = %s)",FUNC_NAME,to_void(this),a_leg?"A":"B",
        callStatus2str(status),
        reason.c_str());
}

void SBCCallLeg::onBLegRefused(AmSipReply& reply)
{
    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");
    if(!call_ctx) return;
    Cdr* cdr = call_ctx->cdr;
    CodesTranslator *ct = CodesTranslator::instance();
    unsigned int intermediate_code;
    string intermediate_reason;

    if(!a_leg) return;

    removeTimer(YETI_FAKE_RINGING_TIMER);

    cdr->update(reply);
    cdr->update_bleg_reason(reply.reason,static_cast<int>(reply.code));

    ct->rewrite_response(reply.code,reply.reason,
        intermediate_code,intermediate_reason,
        call_ctx->getOverrideId(false)); //bleg_override_id
    ct->rewrite_response(intermediate_code,intermediate_reason,
        reply.code,reply.reason,
        call_ctx->getOverrideId(true)); //aleg_override_id
    cdr->update_internal_reason(
        reply.local_reply ? DisconnectByTS : DisconnectByDST,
        intermediate_reason,intermediate_code);
    cdr->update_aleg_reason(reply.reason,static_cast<int>(reply.code));

    if(ct->stop_hunting(reply.code,call_ctx->getOverrideId(false))){
        DBG("stop hunting");
        return;
    }

    DBG("continue hunting");
    //put current resources
    rctl.put(call_ctx->getCurrentProfile()->resource_handler);
    if(call_ctx->initial_invite==nullptr){
        ERROR("%s() intial_invite == NULL",FUNC_NAME);
        return;
    }

    if(!chooseNextProfile()) {
        DBG("%s() no new profile, just finish as usual",FUNC_NAME);
        return;
    }

    DBG("%s() has new profile, so create new callee",FUNC_NAME);
    cdr = call_ctx->cdr;

    if(0!=cdr_list.insert(cdr)){
        ERROR("onBLegRefused(): double insert into active calls list. integrity threat");
        ERROR("ctx: attempt = %d, cdr.logger_path = %s",
            call_ctx->attempt_num,cdr->msg_logger_path.c_str());
        return;
    }

    AmSipRequest &req = *call_ctx->initial_invite;
    try {
        connectCallee(req);
    } catch(InternalException &e){
        cdr->update_internal_reason(DisconnectByTS,e.internal_reason,e.internal_code);
        throw AmSession::Exception(
            static_cast<int>(e.response_code),e.response_reason);
    }
}

void SBCCallLeg::onCallFailed(CallFailureReason , const AmSipReply *)
{ }

bool SBCCallLeg::onBeforeRTPRelay(AmRtpPacket* p, sockaddr_storage*)
{
    if(rtp_relay_rate_limit.get() && rtp_relay_rate_limit->limit(p->getBufferSize()))
        return false; // drop
    return true; // relay
}

void SBCCallLeg::onAfterRTPRelay(AmRtpPacket* p, sockaddr_storage*)
{
    for(list<::atomic_int*>::iterator it = rtp_pegs.begin();
        it != rtp_pegs.end(); ++it)
    {
        (*it)->inc(p->getBufferSize());
    }
}

void SBCCallLeg::onRTPStreamDestroy(AmRtpStream *stream) {
    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");

    if(!call_ctx) return;

    with_cdr_for_read {
        if(cdr->writed) return;
        cdr->lock();
        if(a_leg) stream->getMediaStats(cdr->aleg_media_stats);
        else stream->getMediaStats(cdr->bleg_media_stats);
        cdr->unlock();
    }
}

bool SBCCallLeg::reinvite(const AmSdp &sdp, unsigned &request_cseq)
{
    request_cseq = 0;

    AmMimeBody body;
    AmMimeBody *sdp_body = body.addPart(SIP_APPLICATION_SDP);
    if (!sdp_body) return false;

    string body_str;
    sdp.print(body_str);
    sdp_body->parse(SIP_APPLICATION_SDP,
        reinterpret_cast<const unsigned char*>(body_str.c_str()),
        static_cast<unsigned int>(body_str.length()));

    if (dlg->reinvite("", &body, SIP_FLAGS_VERBATIM) != 0) return false;
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

static void replace_address(SdpConnection &c, const string &ip)
{
    if (!c.address.empty()) {
        if (c.addrType == AT_V4) {
            c.address = ip;
            return;
        }
        // TODO: IPv6?
        DBG("unsupported address type for replacing IP");
    }
}

static void alterHoldRequest(AmSdp &sdp, SBCCallProfile::HoldSettings::Activity a, const string &ip)
{
    if (!ip.empty()) replace_address(sdp.conn, ip);
    for (vector<SdpMedia>::iterator m = sdp.media.begin(); m != sdp.media.end(); ++m)
    {
        if (!ip.empty()) replace_address(m->conn, ip);
        m->recv = (a == SBCCallProfile::HoldSettings::sendrecv || a == SBCCallProfile::HoldSettings::recvonly);
        m->send = (a == SBCCallProfile::HoldSettings::sendrecv || a == SBCCallProfile::HoldSettings::sendonly);
    }
}

void SBCCallLeg::alterHoldRequestImpl(AmSdp &sdp)
{
    if (call_profile.hold_settings.mark_zero_connection(a_leg)) {
        static const string zero("0.0.0.0");
        ::alterHoldRequest(sdp, call_profile.hold_settings.activity(a_leg), zero);
    } else {
        if (getRtpRelayMode() == RTP_Direct) {
            // we can not put our IP there if not relaying, using empty not to
            // overwrite existing addresses
            static const string empty;
            ::alterHoldRequest(sdp, call_profile.hold_settings.activity(a_leg), empty);
        } else {
            // use public IP to be put into connection addresses (overwrite 0.0.0.0
            // there)
            ::alterHoldRequest(sdp, call_profile.hold_settings.activity(a_leg), advertisedIP());
        }
    }
}

void SBCCallLeg::alterHoldRequest(AmSdp &sdp)
{
    TRACE("altering B2B hold request(%s, %s, %s)\n",
        call_profile.hold_settings.alter_b2b(a_leg) ? "alter B2B" : "do not alter B2B",
        call_profile.hold_settings.mark_zero_connection(a_leg) ? "0.0.0.0" : "own IP",
        call_profile.hold_settings.activity_str(a_leg).c_str());

    if (!call_profile.hold_settings.alter_b2b(a_leg)) return;

    alterHoldRequestImpl(sdp);
}

void SBCCallLeg::processLocalRequest(AmSipRequest &req) {
    DBG("%s() local_tag = %s",FUNC_NAME,getLocalTag().c_str());
    updateLocalBody(req.body);
    dlg->reply(req,200,"OK",&req.body,"",SIP_FLAGS_VERBATIM);
}

void SBCCallLeg::createHoldRequest(AmSdp &sdp)
{
    // hack: we need to have other side SDP (if the stream is hold already
    // it should be marked as inactive)
    // FIXME: fix SDP versioning! (remember generated versions and increase the
    // version number in every SDP passing through?)

    AmMimeBody *s = established_body.hasContentType(SIP_APPLICATION_SDP);
    if (s) sdp.parse(reinterpret_cast<const char*>(s->getPayload()));
    if (sdp.media.empty()) {
        // established SDP is not valid! generate complete fake
        sdp.version = 0;
        sdp.origin.user = "sems";
        sdp.sessionName = "sems";
        sdp.conn.network = NT_IN;
        sdp.conn.addrType = AT_V4;
        sdp.conn.address = "0.0.0.0";

        sdp.media.push_back(SdpMedia());
        SdpMedia &m = sdp.media.back();
        m.type = MT_AUDIO;
        m.transport = TP_RTPAVP;
        m.send = false;
        m.recv = false;
        m.payloads.push_back(SdpPayload(0));
    }

    AmB2BMedia *ms = getMediaSession();
    if (ms) ms->replaceOffer(sdp, a_leg);

    alterHoldRequestImpl(sdp);
}

void SBCCallLeg::setMediaSession(AmB2BMedia *new_session)
{
    if (new_session) {
        if (call_profile.log_rtp) new_session->setRtpLogger(logger);
        else new_session->setRtpLogger(nullptr);

        if(a_leg) {
            if(call_profile.aleg_sensor_level_id&LOG_RTP_MASK)
            new_session->setRtpASensor(sensor);
            else new_session->setRtpASensor(nullptr);
        } else {
            if(call_profile.bleg_sensor_level_id&LOG_RTP_MASK)
            new_session->setRtpBSensor(sensor);
            else new_session->setRtpBSensor(nullptr);
        }
    }
    CallLeg::setMediaSession(new_session);
}

bool SBCCallLeg::openLogger(const std::string &path)
{
    file_msg_logger *log = new pcap_logger();

    if(log->open(path.c_str()) != 0) {
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
    if (logger) dec_ref(logger); // release the old one

    logger = _logger;
    if (logger) inc_ref(logger);

    if (call_profile.log_sip) dlg->setMsgLogger(logger);
    else dlg->setMsgLogger(nullptr);

    AmB2BMedia *m = getMediaSession();
    if (m) {
        if (call_profile.log_rtp) m->setRtpLogger(logger);
        else m->setRtpLogger(nullptr);
    }
}

void SBCCallLeg::setSensor(msg_sensor *_sensor){
    DBG("SBCCallLeg[%p]: %cleg. change sensor to %p",
        to_void(this),a_leg?'A':'B',to_void(_sensor));
    if (sensor) dec_ref(sensor);
    sensor = _sensor;
    if (sensor) inc_ref(sensor);

    if((a_leg && (call_profile.aleg_sensor_level_id&LOG_SIP_MASK)) ||
       (!a_leg && (call_profile.bleg_sensor_level_id&LOG_SIP_MASK)))
    {
        dlg->setMsgSensor(sensor);
    } else {
        dlg->setMsgSensor(nullptr);
    }

    AmB2BMedia *m = getMediaSession();
    if(m) {
        if(a_leg) {
            if(call_profile.aleg_sensor_level_id&LOG_RTP_MASK)
            m->setRtpASensor(sensor);
            else m->setRtpASensor(nullptr);
        } else {
            if(call_profile.bleg_sensor_level_id&LOG_RTP_MASK)
            m->setRtpBSensor(sensor);
            else m->setRtpBSensor(nullptr);
        }
    } else {
        DBG("SBCCallLeg: no media session");
    }
}

void SBCCallLeg::computeRelayMask(const SdpMedia &m, bool &enable, PayloadMask &mask, PayloadRelayMap& map)
{
    if(call_profile.force_transcoding) {
        enable = false;
        mask.clear();
        map.clear();
        return;
    }

    CallLeg::computeRelayMask(m, enable, mask, map);

    if(call_profile.force_relay_CN) {
        mask.set(COMFORT_NOISE_PAYLOAD_TYPE);
        TRACE("mark payload 13(CN) for relay");
    }
}

int SBCCallLeg::onSdpCompleted(const AmSdp& local, const AmSdp& remote){
    DBG("%s(%p,leg%s)",FUNC_NAME,to_void(this),a_leg?"A":"B");

    AmSdp offer(local),answer(remote);

    const SqlCallProfile *sql_call_profile = call_ctx->getCurrentProfile();
    if(sql_call_profile) {
        cutNoAudioStreams(offer,sql_call_profile->filter_noaudio_streams);
        cutNoAudioStreams(answer,sql_call_profile->filter_noaudio_streams);
    }

    dump_SdpMedia(offer.media,"offer");
    dump_SdpMedia(answer.media,"answer");

    int ret = CallLeg::onSdpCompleted(offer, answer);

    if(0==ret) {
        with_cdr_for_read {
            cdr->setSdpCompleted(a_leg);
        }
    }

    if(!a_leg) return ret;

    AmB2BMedia *m = getMediaSession();
    if(!m) return ret;

    m->updateStreams(false /* recompute relay and other parameters in direction A -> B*/,this);

    if(CallLeg::Ringing==getCallStatus())
        m->setRtpTimeout(0);

    return ret;
}

bool SBCCallLeg::getSdpOffer(AmSdp& offer){
    DBG("%s(%p)",FUNC_NAME,to_void(this));

    if(!call_ctx) {
        DBG("getSdpOffer[%s] missed call context",getLocalTag().c_str());
        return CallLeg::getSdpOffer(offer);
    }

    AmB2BMedia *m = getMediaSession();
    if(!m){
        DBG("getSdpOffer[%s] missed media session",getLocalTag().c_str());
        return CallLeg::getSdpOffer(offer);
    }
    if(!m->haveLocalSdp(a_leg)){
        DBG("getSdpOffer[%s] have no local sdp",getLocalTag().c_str());
        return CallLeg::getSdpOffer(offer);
    }

    const AmSdp &local_sdp = m->getLocalSdp(a_leg);
    if(a_leg){
        DBG("use last offer from dialog as offer for legA");
        offer = local_sdp;
    } else {
        DBG("provide saved initial offer for legB");
        offer = call_ctx->bleg_initial_offer;
        auto addr_type = dlg->getOutboundAddrType();
        m->replaceConnectionAddress(offer,a_leg,
                                    localMediaIP(addr_type),
                                    advertisedIP(addr_type),
                                    addr_type);
    }
    offer.origin.sessV = local_sdp.origin.sessV+1; //increase session version. rfc4566 5.2 <sess-version>
    return true;
}

void SBCCallLeg::b2bInitial1xx(AmSipReply& reply, bool forward)
{
    if(a_leg) {
        if(reply.code==100) {
            if(call_profile.fake_ringing_timeout)
                setTimer(YETI_FAKE_RINGING_TIMER,call_profile.fake_ringing_timeout);
        } else {
            call_ctx->ringing_sent = true;
        }
    }
    return CallLeg::b2bInitial1xx(reply,forward);
}

void SBCCallLeg::b2bConnectedErr(AmSipReply& reply)
{
    const static string xfer_failed("Transfer Failed: ");

    if(!a_leg) return;
    if(!call_ctx) return;
    if(!call_ctx->transfer_intermediate_state) return;

    DBG("got %d/%s for xfer INVITE. force CDR reasons",
        reply.code,reply.reason.c_str());

    with_cdr_for_read {
        cdr->lock();
        cdr->disconnect_initiator = DisconnectByTS;
        cdr->disconnect_internal_code = 200;
        cdr->disconnect_internal_reason =
            xfer_failed + int2str(reply.code) + "/" + reply.reason;
        cdr->unlock();
        cdr->update_aleg_reason("Bye",200);
        cdr->update_bleg_reason("Bye",200);
    }
    terminateLeg();
}

void SBCCallLeg::onOtherRefer(const B2BReferEvent &refer)
{
    DBG("%s(%p) to: %s",FUNC_NAME,to_void(this),refer.referred_to.c_str());

    removeOtherLeg(refer.referrer_session);

    with_cdr_for_read {
        //TODO: use separate field to indicate refer
        cdr->is_redirected = true;
    }

    call_ctx->referrer_session = refer.referrer_session;
    call_ctx->transfer_intermediate_state = true;

    call_profile.bleg_max_transfers--;

    DBG("patch RURI: '%s' -> '%s'",
        ruri.c_str(),refer.referred_to.c_str());
    ruri = refer.referred_to;

    DBG("patch To: '%s' -> '%s'",
        to.c_str(),refer.referred_to.c_str());
    to = refer.referred_to;

    connectCallee(to, ruri, from, aleg_modified_req, modified_req);
}

void SBCCallLeg::sendReferNotify(int code, string &reason)
{
    DBG("%s(%p) %d %s",FUNC_NAME,to_void(this),code,reason.c_str());
    if(last_refer_cseq.empty()) return;
    string body = "SIP/2.0 " + int2str(code) + " " + reason + CRLF;
    subs->sendReferNotify(dlg,last_refer_cseq,body,code >= 200);
}
