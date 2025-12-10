#ifndef __SBCCALL_LEG_H
#define __SBCCALL_LEG_H

#include "SBC.h"
#include "CallCtx.h"
#include "sbc_events.h"
#include "RateLimit.h"
#include "ampi/RadiusClientAPI.h"
#include "ampi/IdentityValidatorApi.h"
#include "AmIdentity.h"

#include "yeti.h"

#include "SBCCallControlAPI.h"

enum stir_shaken_attest_level_id { SS_ATTEST_A = 1, SS_ATTEST_B, SS_ATTEST_C };

class in_memory_msg_logger : public msg_logger {

    struct log_entry {
        char            *buf;
        int              len;
        sockaddr_storage local_ip;
        sockaddr_storage remote_ip;
        cstring          method;
        int              reply_code;

        // timeval log_timestamp;

        log_entry(const char *buf_arg, int len_arg, sockaddr_storage *src_ip_arg, sockaddr_storage *dst_ip_arg,
                  cstring method_arg, int reply_code_arg);
        ~log_entry();
    };

    std::list<log_entry> packets;
    AmMutex              mutex;

  public:
    int  log(const char *buf, int len, sockaddr_storage *src_ip, sockaddr_storage *dst_ip, cstring method,
             int reply_code = 0);
    void feed_to_logger(msg_logger *logger);
};

class SBCCallLeg : public CallLeg, public CredentialHolder {
    enum { BB_Init = 0, BB_Dialing, BB_Connected, BB_Teardown } CallerState;

    int m_state;

    map<int, double> call_timers;

    Yeti &yeti;

    AmSipRequest aleg_modified_req;
    AmSipRequest modified_req;
    AmSipRequest uac_req;

    string           ruri, to, from;
    ParamReplacerCtx ctx;
    string           last_refer_cseq;
    uint64_t         sdp_session_version;
    bool             has_sdp_session_version;
    unsigned int     sdp_session_offer_last_cseq;
    unsigned int     sdp_session_answer_last_cseq;
    // for tests, thread id of session processor
    __pid_t thread_id;

    string global_tag;

    CallCtx *call_ctx;

    fake_logger                             *early_trying_logger;
    std::queue<unique_ptr<B2BSipReplyEvent>> postponed_replies;

    timeval call_start_time;

    OriginationPreAuth::Reply ip_auth_data;
    Auth::auth_id_type        auth_result_id;

    // auth
    AmSessionEventHandler *auth;

    SBCCallProfile   call_profile;
    PlaceholdersHash placeholders_hash;
    AmArg            identity_data;

    // Rate limiting
    unique_ptr<RateLimit> rtp_relay_rate_limit;

    // Measurements
    list<::atomic_int *> rtp_pegs;

    /** common logger for RTP/RTCP and SIP packets */
    msg_logger *logger;
    msg_sensor *sensor;
    bool        memory_logger_enabled;
    bool        waiting_for_location;

    struct timeval profile_request_start_time;

    void setLogger(msg_logger *_logger);

    /** handler called when call is stopped (see AmSession) */
    virtual void onStop() override;

    /** apply A leg configuration from call profile */
    // void applyAProfile();

    /** apply B leg configuration from call profile */
    void applyBProfile();

    void addIdentityHeader(AmSipRequest &req);

    virtual void onCallStatusChange(const StatusChangeCause &cause) override;
    virtual void onBLegRefused(AmSipReply &reply) override;

    /** handler called when the call is refused with a non-ok reply or canceled */
    virtual void onCallFailed(CallFailureReason reason, const AmSipReply *reply) override;

    /** handler called when the second leg is connected */
    virtual void onCallConnected(const AmSipReply &reply) override;

    /** Call-backs used by RTP stream(s)
     *  Note: these methods will be called from the RTP receiver thread.
     */
    virtual bool onBeforeRTPRelay(AmRtpPacket *p, sockaddr_storage *remote_addr) override;
    virtual void onAfterRTPRelay(AmRtpPacket *p, sockaddr_storage *remote_addr) override;
    virtual void onRTPStreamDestroy(AmRtpStream *stream) override;

    void alterHoldRequestImpl(AmSdp &sdp); // do the SDP update (called by alterHoldRequest)

    void init();

    void terminateLegOnReplyException(const AmSipReply &reply, const InternalException &e);

    void processAorResolving();
    void processResourcesAndSdp();

    /*! create new B leg (serial fork)*/
    /*! choose next profile, create cdr and check resources */
    bool chooseNextProfile();
    bool connectCalleeRequest(const AmSipRequest &orig_req);

    void onPostgresResponse(PGResponse &e);
    void onPostgresResponseError(PGResponseError &e);
    void onPostgresTimeout(PGTimeout &e);
    void onProfilesReady();

    void onJsonRpcRequest(JsonRpcRequestEvent &ev);
    void onRadiusReply(const RadiusReplyEvent &ev);
    void onSipRegistrarResolveResponse(const SipRegistrarResolveResponseEvent &e);
    void onValidateIdentitiesResponse(const ValidateIdentitiesResponse &e);
    void onHttpPostResponse(const HttpPostResponseEvent &e);
    void onRtpTimeoutOverride(const AmRtpTimeoutEvent &rtp_event);
    bool onTimerEvent(int timer_id);
    void onInterimRadiusTimer();
    void onFakeRingingTimer();
    void onControlEvent(SBCControlEvent *event);
    void onTearDown();
    void onSystemEventOverride(AmSystemEvent *event);
    void onServerShutdown();

    void onOtherRefer(const B2BReferEvent &refer);
    void sendReferNotify(int code, string &reason);

    AmArg serialized_http_data;
    void  httpCallStartedHook();
    void  httpCallConnectedHook();
    void  httpCallDisconnectedHook();

    void send_and_log_auth_challenge(const AmSipRequest &req, const string &internal_reason, bool post_auth_log,
                                     int auth_feedback_code = Auth::NO_AUTH);

    void setRejectCdr(int disconnect_code_id);
    void process_push_token_profile(SqlCallProfile &p);

  public:
    SqlRouter       &router;
    CdrList         &cdr_list;
    ResourceControl &rctl;

    SBCCallLeg(fake_logger *early_trying_logger, OriginationPreAuth::Reply &ip_auth_data,
               Auth::auth_id_type auth_result_id, AmSipDialog *dlg = NULL, AmSipSubscription *p_subs = NULL);
    SBCCallLeg(SBCCallLeg *caller, AmSipDialog *dlg = NULL, AmSipSubscription *p_subs = NULL);
    ~SBCCallLeg();

    void process(AmEvent *ev) override;
    void onInvite(const AmSipRequest &req) override;
    void onIdentityReady(const AmArg *identity_data_ptr = nullptr);
    void onRoutingReady();
    void onFailure() override;
    void onInviteException(int code, string reason, bool no_reply) override;
    bool onException(int code, const string &reason) noexcept override;
    void onOtherException(int code, const string &reason) noexcept;
    void onEarlyEventException(unsigned int code, const string &reason);
    void normalizeSdpVersion(uint64_t &sdp_session_version_in, unsigned int cseq, bool offer);

    void onDtmf(AmDtmfEvent *e) override;

    virtual void onStart() override;
    virtual void onBeforeDestroy() override;
    void         finalize() override;

    // int filterSdp(AmMimeBody &body, const string &method);
    void connectCallee(const string &remote_party, const string &remote_uri, const string &from,
                       const AmSipRequest &original_invite, const AmSipRequest &invite_req, AmSipDialog *p_dlg);
    void applyAProfile();
    int  applySSTCfg(AmConfigReader &sst_cfg, const AmSipRequest *p_req);

    UACAuthCred *getCredentials() override;

    void setAuthHandler(AmSessionEventHandler *h) { auth = h; }

    /** save call timer; only effective before call is connected */
    void saveCallTimer(int timer, double timeout);
    /** clear saved call timer, only effective before call is connected */
    void clearCallTimer(int timer);
    /** clear all saved call timer, only effective before call is connected */
    void clearCallTimers();

    // SBC interface usable from CC modules

    void setLocalParty(const string &party, const string &uri)
    {
        dlg->setLocalParty(party); // From
        dlg->setLocalUri(uri);     // Contact
    }

    void setRemoteParty(const string &party, const string &uri)
    {
        dlg->setRemoteParty(party); // To
        dlg->setRemoteUri(uri);     // R-URI
    }

    SBCCallProfile   &getCallProfile() { return call_profile; }
    void              updateCallProfile(const SBCCallProfile &new_profile);
    PlaceholdersHash &getPlaceholders() { return placeholders_hash; }
    CallStatus        getCallStatus() { return CallLeg::getCallStatus(); }

    AmSipRequest &getAlegModifiedReq() { return aleg_modified_req; }
    AmSipRequest &getModifiedReq() { return modified_req; }

    const string &getGlobalTag() const { return global_tag; }

    CallCtx *getCallCtx() { return call_ctx; }

    void             setRTPMeasurements(const list<::atomic_int *> &rtp_meas) { rtp_pegs = rtp_meas; }
    const RateLimit *getRTPRateLimit() { return rtp_relay_rate_limit.get(); }
    void             setRTPRateLimit(RateLimit *rl) { rtp_relay_rate_limit.reset(rl); }

    // media interface must be accessible from CC modules
    AmB2BMedia  *getMediaSession() { return AmB2BSession::getMediaSession(); }
    virtual void updateLocalSdp(AmSdp &sdp, const string &sip_msg_method, unsigned int sip_msg_cseq) override;
    // void changeRtpMode(RTPRelayMode new_mode) { CallLeg::changeRtpMode(new_mode); }

    bool reinvite(const AmSdp &sdp, unsigned &request_cseq);

    int  relayEvent(AmEvent *ev) override;
    void onSipRequest(const AmSipRequest &req) override;
    bool isALeg() { return a_leg; }

    virtual void setMediaSession(AmB2BMedia *new_session) override;
    virtual void computeRelayMask(const SdpMedia &m, bool &enable, PayloadMask &mask, PayloadRelayMap &map) override;
    virtual void processLocalRequest(AmSipRequest &req);

    void setSensor(msg_sensor *_sensor);

    msg_logger *getLogger() { return logger; }
    msg_sensor *getSensor() { return sensor; }
    bool        getMemoryLoggerEnabled() { return memory_logger_enabled; }

    void b2bInitial1xx(AmSipReply &reply, bool forward) override;
    void b2bConnectedErr(AmSipReply &reply) override;

  protected:
    void setOtherId(const AmSipReply &reply);
    void setOtherId(const string &n_other_id) override { CallLeg::setOtherId(n_other_id); }

    void onSipReply(const AmSipRequest &req, const AmSipReply &reply, AmSipDialog::Status old_dlg_status) override;
    void onSendRequest(AmSipRequest &req, int &flags) override;

    virtual void onInitialReply(B2BSipReplyEvent *e) override;

    void onRemoteDisappeared(const AmSipReply &reply) override;
    void onBye(const AmSipRequest &req) override;
    void onOtherBye(const AmSipRequest &req) override;

    void onControlCmd(string &cmd, AmArg &params);

    /* set call timer (if enabled) */
    virtual bool startCallTimers();
    /* clear call timer */
    virtual void stopCallTimers();

    const map<int, double> getCallTimers() { return call_timers; }

    void createCalleeSession();

    virtual void createHoldRequest(AmSdp &sdp) override;
    virtual void alterHoldRequest(AmSdp &sdp) override;
    virtual void holdRequested() override;
    virtual void holdAccepted() override;
    virtual void holdRejected() override;
    virtual void resumeRequested() override;
    virtual void resumeAccepted() override;
    virtual void resumeRejected() override;

    virtual int  onSdpCompleted(const AmSdp &local, const AmSdp &remote, bool sdp_offer_owner) override;
    virtual bool getSdpOffer(AmSdp &offer) override;
    // int applySSTCfg(AmConfigReader& sst_cfg, const AmSipRequest* p_req);

    bool openLogger(const std::string &path);
};

#endif
