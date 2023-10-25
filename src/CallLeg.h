#pragma once

#include "AmB2BSession.h"
#include "AmSessionContainer.h"
#include "CallLegEvents.h"
#include <sip/sip_timers.h>
#include <queue>

struct PendingReinvite
{
    string hdrs;
    AmMimeBody body;
    unsigned r_cseq;
    bool relayed_invite;
    bool establishing;
};

/** composed AmB2BCalleeSession & AmB2BCallerSession
 * represents indepenedently A or B leg of a call,
 * old clases left for compatibility
 *
 * Notes:
 *
 *  - we use the relayEvent implementation from AmB2BSession - it can happen
 *  that we have no peer (i.e. we are a standalone call leg, for example parked
 *  one) => do not create other call leg automatically
 *
 *  - we use onSystemEvent implementation from AmB2BSession - the other leg
 *  receives and handles the same shutdown event, right?
 *
 *  - the role (A/B leg) can be changed during the CallLeg life and is
 *  understood just this way
 *
 *    "A leg is the call leg created when handling initial INVITE request"
 *
 *  It is used
 *    - as identification what part of media session is affected by operation
 *    - when CANCEL is being processed only the CANCEL of initial INVITE is
 *    important so it is explicitly verified that it is handled in A leg)
 *
 *  In other words - the B leg can create new 'b-like-legs' the same way the
 *  A leg does.
 * */
class CallLeg: public AmB2BSession
{
  public:
    /** B2B call status.
     *
     * This status need not to be related directly to SIP dialog status in
     * appropriate call legs - for example the B2B call status can be
     * "Connected" though the legs have received BYE replies. */
    enum CallStatus {
        Disconnected, //< there is no other call leg we are connected to
        NoReply,      //< there is at least one call leg we are connected to but without any response
        Ringing,      //< this leg or one of legs we are connected to rings
        Connected,    //< there is exactly one call leg we are connected to, in this case AmB2BSession::other_id holds the other leg id
        Disconnecting //< we were connected and now going to be disconnected (waiting for reINVITE reply for example)
    };

    /** reason reported in onCallFailed method */
    enum CallFailureReason {
        CallRefused, //< non-ok reply received and no more B-legs exit
        CallCanceled //< call canceled
    };

    /** reason for changing call status */
    struct StatusChangeCause
    {
        enum Reason {
            SipReply,
            SipRequest,
            Canceled,
            NoAck,
            NoPrack,
            RtpTimeout,
            SessionTimeout,
            InternalError,
            Other
        } reason;

        union {
            const AmSipReply *reply;
            const AmSipRequest *request;
            const char *desc;
        } param;

        StatusChangeCause(const AmSipReply *r): reason(SipReply) { param.reply = r; }
        StatusChangeCause(const AmSipRequest *r): reason(SipRequest) { param.request = r; }
        StatusChangeCause(): reason(Other) { param.desc = nullptr; }
        StatusChangeCause(const char *desc): reason(Other) { param.desc = desc; }
        StatusChangeCause(const Reason r): reason(r) { param.reply = nullptr; }
    };

  private:

    CallStatus call_status; //< status of the call (replaces callee's status)

    sip_timers_override inv_timers_override;

    class AmB2BMediaPtr {
        AmB2BMedia *m;
      public:
        AmB2BMediaPtr() = delete;
        AmB2BMediaPtr(AmB2BMediaPtr const &) = delete;
        AmB2BMediaPtr(AmB2BMediaPtr const &&) = delete;

        AmB2BMediaPtr(AmB2BMedia *m)
          : m(m)
        {
            if(m) m->addReference();
        }

        ~AmB2BMediaPtr() {
            if(m) m->releaseReference();
        }

        operator AmB2BMedia *() const { return m; }
    };

    bool allow_1xx_without_to_tag;

    /** List of legs which can be connected to this leg, it is valid for A leg until first
     * 2xx response which moves the A leg to Connected state and terminates all
     * other B legs.
     *
     * Please note that the A/B role may change during the call leg life. For
     * example when a B leg is parked and then 'rings back on timer' it becomes
     * A leg, i.e. it creates new B leg(s) for itself. */
    std::map<std::string, AmB2BMediaPtr> other_legs;

    bool on_hold; // remote is on hold
    AmSdp non_hold_sdp;
    enum {
        HoldRequested,
        ResumeRequested,
        PreserveHoldStatus
    } hold;

    std::queue<PendingReinvite> pending_reinvites;

    /* generate re-INVITE with given parameters (establishing means that the
     * INVITE is establishing a connection between two legs) */
    void reinvite(
        const string &hdrs, const AmMimeBody &body,
        bool relayed, unsigned r_cseq, bool establishing);

    // generate 200 reply on a pending INVITE (uses fake body)
    void acceptPendingInvite(AmSipRequest *invite);

    /** methods just for make this stuff more readable, not intended to be
     * overriden, override onB2BEvent instead! */
    void onB2BReply(B2BSipReplyEvent *e);
    void onB2BConnect(ConnectLegEvent *e);
    void b2bInitial2xx(AmSipReply& reply, bool forward);
    void b2bInitialErr(AmSipReply& reply, bool forward);

    int relaySipReply(AmSipReply &reply);

    /** choose given B leg from the list of other B legs */
    bool setOther(const string &id, bool use_initial_sdp);

    void updateCallStatus(
        CallStatus new_status,
        const StatusChangeCause &cause = StatusChangeCause());

    //////////////////////////////////////////////////////////////////////
    // callbacks (intended to be redefined in successors but should not be
    // called by them directly)

    /* handler called when call status changes */
    virtual void onCallStatusChange(
        [[maybe_unused]] const StatusChangeCause &cause)
    { }

    /** handler called when the second leg is connected (FIXME: this is a hack,
     * use this method in SBCCallLeg only) */
    virtual void onCallConnected([[maybe_unused]] const AmSipReply& reply) { }

    /** Method called if given B leg couldn't establish the call (refused with
     * failure response)
     *
     * Redefine to implement serial fork or handle redirect. */
    virtual void onBLegRefused([[maybe_unused]] AmSipReply& reply) { }

    /** handler called when all B-legs failed or the call has been canceled. 
     * The reply passed is the last final reply. */
    virtual void onCallFailed(
        [[maybe_unused]] CallFailureReason reason,
        [[maybe_unused]] const AmSipReply *reply)
    { }

    /** add newly created callee with prepared ConnectLegEvent */
    void addNewCallee(CallLeg *callee, ConnectLegEvent *e)
    {
        addNewCallee(callee, e, rtp_relay_mode);
    }

    /** add a newly created calee with prepared ConnectLegEvent and forced RTP
     * relay mode (this is a hack to work around allowed temporary changes of
     * RTP relay mode used for music on hold)
     * FIXME: throw this out once MoH will use another method than temporary RTP
     * Relay mode change */
    void addNewCallee(
        CallLeg *callee,
        ConnectLegEvent *e,
        AmB2BSession::RTPRelayMode mode);

    /** Clears other leg, eventually removes it from the list of other legs if
     * it is there. It neither updates call state nor sip_relay_only flag! */
    virtual void clear_other() override;

    // offer-answer handling
    void adjustOffer(AmSdp &sdp);

    /** offer was rejected (called just for negative replies to an request
     * carying offer (not always correct?), answer with disabled streams
     * doesn't cause calling this */
     void offerRejected();

  protected:

    unsigned int redirects_allowed;

    virtual void b2bInitial1xx(AmSipReply& reply, bool forward);
    virtual void b2bConnectedErr(AmSipReply& reply) = 0;

    void setInviteTransactionTimeout(unsigned int timeout) { inv_timers_override.stimer_b = timeout; }
    void setInviteRetransmitTimeout(unsigned int timeout) { inv_timers_override.stimer_m = timeout; }
    // functions offered to successors

    /** remove given leg from the list of other legs */
    void removeOtherLeg(const string &id);

    virtual void setCallStatus(CallStatus new_status);
    CallStatus getCallStatus() const { return call_status; }

    void queueReinvite(
        const string& hdrs, const AmMimeBody& body,
        bool establishing = false, bool relayed_invite = false,
        unsigned int r_cseq = 0);

    // @see AmSession
    virtual void onInvite(const AmSipRequest& req) override;
    virtual void onInvite2xx(const AmSipReply& reply) override;
    virtual void onCancel(const AmSipRequest& req) override;
    virtual void onBye(const AmSipRequest& req) override;
    virtual void onRemoteDisappeared(const AmSipReply& reply) override;
    virtual void onNoAck(unsigned int cseq) override;
    virtual void onNoPrack(const AmSipRequest &req, const AmSipReply &rpl) override;
    virtual void onRtpTimeout() override;
    virtual void onSessionTimeout() override;

    // @see AmB2BSession
    virtual void onOtherBye(const AmSipRequest& req) override;

    virtual void onSipRequest(const AmSipRequest& req) override;
    virtual void onSipReply(const AmSipRequest& req,
                            const AmSipReply& reply,
                            AmSipDialog::Status old_dlg_status) override;

    virtual void onInitialReply(B2BSipReplyEvent *e);

    /* called to create SDP of locally generated hold request */
    virtual void createHoldRequest(AmSdp &sdp) = 0;

    /** called to alter B2B hold request (i.e. the request from other peer) */
    virtual void alterHoldRequest([[maybe_unused]] AmSdp &sdp) { }

    /* called to create SDP of locally generated resume request */
    virtual void createResumeRequest(AmSdp &sdp);

    /** called to alter B2B hold request (i.e. the request from other peer) */
    virtual void alterResumeRequest([[maybe_unused]] AmSdp &sdp) { }

    /* hold requested (either from B2B peer leg or locally)
     * to be overridden */
    virtual void holdRequested() { }
    virtual void holdAccepted();
    virtual void holdRejected();
    virtual void resumeRequested() { }
    virtual void resumeAccepted();
    virtual void resumeRejected() { }

    virtual void terminateOtherLeg() override;
    virtual void terminateLeg() override;
    /** terminate all other B legs than the connected one (should not be used
     * directly by successors, right?) */
    void terminateNotConnectedLegs();

    virtual void updateLocalSdp(
        AmSdp &sdp,
        const string &sip_msg_method,
        unsigned int sip_msg_cseq) override;

    void setAllow1xxWithoutToTag(bool allow)
    {
        allow_1xx_without_to_tag = allow;
    }

  public:
    virtual void onB2BEvent(B2BEvent* ev) override;

    /** Terminate the whole B2B call (if there is no other leg only this one is
     * stopped). */
    virtual void stopCall(const StatusChangeCause &cause);


    /** Put remote party on hold (may change RTP relay mode!). Note that this
     * task is asynchronous so the remote is most probably NOT 'on hold' after
     * calling this method
     *
     * This method calls handleHoldReply(false) directly if an error occurs. */
    virtual void putOnHold();

    /** resume call if the remote party is on hold */
    virtual void resumeHeld(/*bool send_reinvite*/);

    virtual bool isOnHold() { return on_hold; }


    /** add given call leg as our B leg */
    void addCallee(CallLeg *callee, const AmSipRequest &relayed_invite)
    {
        addNewCallee(callee, new ConnectLegEvent(relayed_invite));
    }

    /** generate debug information into log with overall call leg status */
    void debug();

    const char* getCallStatusStr() const;

    // AmMediaSession interface from AmMediaProcessor
    int readStreams(unsigned long long ts, unsigned char *buffer) override;
    int writeStreams(unsigned long long ts, unsigned char *buffer) override;

  public:
    /** creates A leg */
    CallLeg(AmSipDialog* p_dlg = nullptr, AmSipSubscription* p_subs = nullptr);

    /** creates B leg using given session as A leg */
    CallLeg(
        const CallLeg* caller, AmSipDialog* p_dlg = nullptr,
        AmSipSubscription* p_subs = nullptr);

    virtual ~CallLeg();

    // OA callbacks
    virtual int onSdpCompleted(const AmSdp& local, const AmSdp& remote) override;
    virtual bool getSdpOffer([[maybe_unused]] AmSdp& offer) override
    {
        return false;
    }
    virtual bool getSdpAnswer(
        [[maybe_unused]] const AmSdp& offer,
        [[maybe_unused]] AmSdp& answer) override
    {
        return false;
    }
    virtual void onEarlySessionStart() override { }
    virtual void onSessionStart() override { }

};
