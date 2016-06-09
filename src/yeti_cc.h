#pragma once

#include "yeti_base.h"
#include "yeti_radius.h"

#include "ExtendedCCInterface.h"
#include "SBCCallControlAPI.h"

class YetiCC
  : virtual YetiBase,
    virtual YetiRadius
{

    struct RefuseException {
        int internal_code,response_code;
        string internal_reason,response_reason;
        RefuseException(int ic,string ir,int rc,string rr) :
            internal_code(ic),internal_reason(ir),
            response_code(rc),response_reason(rr){}
    };

    void onLastLegDestroy(CallCtx *ctx,SBCCallLeg *call);
    /*! create new B leg (serial fork)*/
    /*! choose next profile, create cdr and check resources */
    bool connectCallee(CallCtx *call_ctx,SBCCallLeg *call,const AmSipRequest &orig_req);
    bool chooseNextProfile(SBCCallLeg *call);
    /*! return true if call refused */
    bool check_and_refuse(SqlCallProfile *profile,Cdr *cdr,
                          const AmSipRequest& req,ParamReplacerCtx& ctx,
                          bool send_reply = false);
    void onRadiusReply(SBCCallLeg *call, const RadiusReplyEvent &ev);
    void onInterimRadiusTimer(SBCCallLeg *call);

    CCChainProcessing onRtpTimeout(SBCCallLeg *call,const AmRtpTimeoutEvent &rtp_event);
    void onServerShutdown(SBCCallLeg *call);
    CCChainProcessing onControlEvent(SBCCallLeg *call,SBCControlEvent *event);
    CCChainProcessing onSystemEvent(SBCCallLeg *call,AmSystemEvent* event);
    CCChainProcessing onTimerEvent(SBCCallLeg *call,int timer_id);
    CCChainProcessing onTearDown(SBCCallLeg *call);

    void terminateLegOnReplyException(SBCCallLeg *call,const AmSipReply& reply, const InternalException &e);

  public:
    YetiCC(YetiBase &base)
      : YetiBase(base),
        YetiRadius(base)
    { }

    void onRoutingReady(SBCCallLeg *call, AmSipRequest &aleg_modified_invite, AmSipRequest &modified_invite);

    CallCtx *getCallCtx(const AmSipRequest& req,
                            ParamReplacerCtx& ctx);

    bool init(SBCCallLeg *call, const map<string, string> &values);

    void onSendRequest(SBCCallLeg *call,AmSipRequest& req, int &flags);
    void onStateChange(SBCCallLeg *call, const CallLeg::StatusChangeCause &cause);
    void onDestroyLeg(SBCCallLeg *call);
    CCChainProcessing onBLegRefused(SBCCallLeg *call,AmSipReply& reply);

    CCChainProcessing onInitialInvite(SBCCallLeg *call, InitialInviteHandlerParams &params);
    void onInviteException(SBCCallLeg *call,int code,string reason,bool no_reply);
    CCChainProcessing onInDialogRequest(SBCCallLeg *call, const AmSipRequest &req);
    CCChainProcessing onInDialogReply(SBCCallLeg *call, const AmSipReply &reply);
    CCChainProcessing onEvent(SBCCallLeg *call, AmEvent *e);
    CCChainProcessing onDtmf(SBCCallLeg *call, AmDtmfEvent* e);
    CCChainProcessing putOnHold(SBCCallLeg *call);
    CCChainProcessing resumeHeld(SBCCallLeg *call, bool send_reinvite);
    CCChainProcessing createHoldRequest(SBCCallLeg *call, AmSdp &sdp);
    CCChainProcessing handleHoldReply(SBCCallLeg *call, bool succeeded);

    CCChainProcessing onRemoteDisappeared(SBCCallLeg *call, const AmSipReply &reply);
    CCChainProcessing onBye(SBCCallLeg *call, const AmSipRequest &req);
    CCChainProcessing onOtherBye(SBCCallLeg *call, const AmSipRequest &req);
    void onCallConnected(SBCCallLeg *call, const AmSipReply& reply);
    void onCallEnded(SBCCallLeg *call);

    void onRTPStreamDestroy(SBCCallLeg *call,AmRtpStream *stream);
    void onSdpCompleted(SBCCallLeg *call, AmSdp& offer, AmSdp& answer);
    bool getSdpOffer(SBCCallLeg *call, AmSdp& offer);

    int relayEvent(SBCCallLeg *call, AmEvent *e);
};
