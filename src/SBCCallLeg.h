#pragma once

#include "SBC.h"
#include "CallCtx.h"
#include "sbc_events.h"
#include "RateLimit.h"
#include "ampi/RadiusClientAPI.h"

#include "yeti.h"

#include "SBCCallControlAPI.h"

class PayloadIdMapping
{
  private:
    std::map<int, int> mapping;

  public:
    void map(int stream_index, int payload_index, int payload_id);
    int get(int stream_index, int payload_index);
    void reset();
};

class SBCCallLeg final
  : public CallLeg,
    public CredentialHolder
{
    enum {
        BB_Init = 0,
        BB_Dialing,
        BB_Connected,
        BB_Teardown
    } CallerState;

    int m_state;

    map<int, double> call_timers;

    Yeti &yeti;

    AmSipRequest aleg_modified_req;
    AmSipRequest modified_req;
    AmSipRequest uac_req;
    AmUriParser uac_ruri;
    string ruri, to, from;
    ParamReplacerCtx ctx;
    string last_refer_cseq;

    string global_tag;
    CallCtx *call_ctx;
    std::queue< unique_ptr<B2BSipReplyEvent> > postponed_replies;

    // auth
    AmSessionEventHandler* auth;

    /** Storage for remembered payload IDs from SDP offer to be put correctly into
    * SDP answer (we avoid with this parsing SDP offer again when processing the
    * answer). We can not use call_profile.transcoder.audio_codecs for storing
    * the payload IDs because they need to be remembered per media stream. */
    PayloadIdMapping transcoder_payload_mapping;

    SBCCallProfile call_profile;
    PlaceholdersHash placeholders_hash;

    // Rate limiting
    auto_ptr<RateLimit> rtp_relay_rate_limit;

    // Measurements
    list<::atomic_int*> rtp_pegs;

    /** common logger for RTP/RTCP and SIP packets */
    msg_logger *logger;
    msg_sensor *sensor;

    void setLogger(msg_logger *_logger);

    /** handler called when call is stopped (see AmSession) */
    virtual void onStop() override;

    /** apply A leg configuration from call profile */
    //void applyAProfile();

    /** apply B leg configuration from call profile */
    void applyBProfile();

    virtual void onCallStatusChange(const StatusChangeCause &cause) override;
    virtual void onBLegRefused(AmSipReply& reply) override;

    /** handler called when the call is refused with a non-ok reply or canceled */
    virtual void onCallFailed(CallFailureReason reason, const AmSipReply *reply) override;

    /** handler called when the second leg is connected */
    virtual void onCallConnected(const AmSipReply& reply) override;

    /** Call-backs used by RTP stream(s)
    *  Note: these methods will be called from the RTP receiver thread.
    */
    virtual bool onBeforeRTPRelay(AmRtpPacket* p, sockaddr_storage* remote_addr) override;
    virtual void onAfterRTPRelay(AmRtpPacket* p, sockaddr_storage* remote_addr) override;
    virtual void onRTPStreamDestroy(AmRtpStream *stream) override;

    void alterHoldRequestImpl(AmSdp &sdp); // do the SDP update (called by alterHoldRequest)

    void init();

    void terminateLegOnReplyException(const AmSipReply& reply,const InternalException &e);

    void processAorResolving();
    void processResourcesAndSdp();

    /*! create new B leg (serial fork)*/
    /*! choose next profile, create cdr and check resources */
    bool chooseNextProfile();
    bool connectCallee(const AmSipRequest &orig_req);

    void onRadiusReply(const RadiusReplyEvent &ev);
    void onRedisReply(const RedisReplyEvent &e);
    void onRtpTimeoutOverride(const AmRtpTimeoutEvent &rtp_event);
    bool onTimerEvent(int timer_id);
    void onInterimRadiusTimer();
    void onFakeRingingTimer();
    void onControlEvent(SBCControlEvent *event);
    void onTearDown();
    void onSystemEventOverride(AmSystemEvent* event);
    void onServerShutdown();

    void onOtherRefer(const B2BReferEvent &refer);
    void sendReferNotify(int code, string &reason);

 public:

    SqlRouter &router;
    CdrList &cdr_list;
    ResourceControl &rctl;

    SBCCallLeg(CallCtx *call_ctx,
        AmSipDialog* dlg = nullptr,
        AmSipSubscription* p_subs = nullptr);
    SBCCallLeg(SBCCallLeg* caller,
        AmSipDialog* dlg = nullptr,
        AmSipSubscription* p_subs = nullptr);
    SBCCallLeg(AmSipDialog* dlg = nullptr,
             AmSipSubscription* p_subs = nullptr);
    ~SBCCallLeg() override;

    void process(AmEvent* ev) override;
    void onInvite(const AmSipRequest& req) override;
    void onRoutingReady();
    void onInviteException(int code,string reason,bool no_reply) override;
    bool onException(int code,const string &reason) noexcept override;
    void onOtherException(int code,const string &reason) noexcept;
    void onEarlyEventException(unsigned int code,const string &reason);

    void onDtmf(AmDtmfEvent* e) override;

    virtual void onStart() override;
    virtual void onBeforeDestroy() override;

    //int filterSdp(AmMimeBody &body, const string &method);
    void connectCallee(const string& remote_party, const string& remote_uri,
             const string &from, const AmSipRequest &original_invite,
             const AmSipRequest &invite_req);
    void applyAProfile();
    int applySSTCfg(AmConfigReader& sst_cfg, const AmSipRequest* p_req);

    UACAuthCred* getCredentials() override;

    void setAuthHandler(AmSessionEventHandler* h) { auth = h; }

    /** save call timer; only effective before call is connected */
    void saveCallTimer(int timer, double timeout);
    /** clear saved call timer, only effective before call is connected */
    void clearCallTimer(int timer);
    /** clear all saved call timer, only effective before call is connected */
    void clearCallTimers();

    // SBC interface usable from CC modules

    void setLocalParty(const string &party, const string &uri) {
    dlg->setLocalParty(party); dlg->setLocalUri(uri);
    }

    void setRemoteParty(const string &party, const string &uri) {
    dlg->setRemoteParty(party); dlg->setRemoteUri(uri);
    }

    SBCCallProfile &getCallProfile() { return call_profile; }
    void updateCallProfile(const SBCCallProfile &new_profile);
    PlaceholdersHash &getPlaceholders() { return placeholders_hash; }
    CallStatus getCallStatus() { return CallLeg::getCallStatus(); }

    AmSipRequest &getAlegModifiedReq() { return aleg_modified_req; }
    AmSipRequest &getModifiedReq() { return modified_req; }

    PayloadIdMapping &getTranscoderMapping() { return  transcoder_payload_mapping; }

    const string &getGlobalTag() const { return global_tag; }

    CallCtx *getCallCtx() { return call_ctx; }
    void setCallCtx(CallCtx *p) { call_ctx = p; }

    void setRTPMeasurements(const list<::atomic_int*>& rtp_meas) { rtp_pegs = rtp_meas; }
    const RateLimit* getRTPRateLimit() { return rtp_relay_rate_limit.get(); }
    void setRTPRateLimit(RateLimit* rl) { rtp_relay_rate_limit.reset(rl); }

    // media interface must be accessible from CC modules
    AmB2BMedia *getMediaSession() { return AmB2BSession::getMediaSession(); }
    virtual void updateLocalSdp(AmSdp &sdp) override;
    void changeRtpMode(RTPRelayMode new_mode) { CallLeg::changeRtpMode(new_mode); }

    bool reinvite(const AmSdp &sdp, unsigned &request_cseq);

    int relayEvent(AmEvent* ev) override;
    void onSipRequest(const AmSipRequest& req) override;
    bool isALeg() { return a_leg; }

    virtual void setMediaSession(AmB2BMedia *new_session) override;
    virtual void computeRelayMask(const SdpMedia &m, bool &enable, PayloadMask &mask, PayloadRelayMap& map) override;
    virtual void processLocalRequest(AmSipRequest &req);

    void setSensor(msg_sensor *_sensor);

    msg_logger *getLogger() { return logger; }
    msg_sensor *getSensor() { return sensor; }

    void b2bInitial1xx(AmSipReply& reply, bool forward) override;
    void b2bConnectedErr(AmSipReply& reply) override;

 protected:

    void setOtherId(const AmSipReply& reply);
    void setOtherId(const string& n_other_id) override
    {
        CallLeg::setOtherId(n_other_id);
    }

    void onSipReply(const AmSipRequest& req, const AmSipReply& reply, AmSipDialog::Status old_dlg_status) override;
    void onSendRequest(AmSipRequest& req, int &flags) override;

    virtual void onInitialReply(B2BSipReplyEvent *e) override;

    void onRemoteDisappeared(const AmSipReply& reply) override;
    void onBye(const AmSipRequest& req) override;
    void onOtherBye(const AmSipRequest& req) override;

    void onControlCmd(string& cmd, AmArg& params);

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

    virtual int onSdpCompleted(const AmSdp& local, const AmSdp& remote) override;
    virtual bool getSdpOffer(AmSdp& offer) override;

    bool openLogger(const std::string &path);
};

