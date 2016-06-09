#pragma once

#include "yeti_base.h"
#include "yeti_radius.h"

#include "SBCCallControlAPI.h"

#include "CallLeg.h"
#include "sbc_events.h"

class SBCCallLeg;
struct SBCCallProfile;
class SimpleRelayDialog;

struct InitialInviteHandlerParams
{
  string remote_party;
  string remote_uri;
  string from;
  const AmSipRequest *original_invite;
  AmSipRequest *aleg_modified_invite;
  AmSipRequest *modified_invite;

  InitialInviteHandlerParams(const string &to, const string &ruri, const string &_from,
      const AmSipRequest *original,
      AmSipRequest *aleg_modified,
      AmSipRequest *modified):
      remote_party(to), remote_uri(ruri), from(_from),
      original_invite(original),
      aleg_modified_invite(aleg_modified),modified_invite(modified) { }
};

enum CCChainProcessing { ContinueProcessing, StopProcessing };


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

    /*! create new B leg (serial fork)*/
    /*! choose next profile, create cdr and check resources */
    bool connectCallee(CallCtx *call_ctx,SBCCallLeg *call,const AmSipRequest &orig_req);
    bool chooseNextProfile(SBCCallLeg *call);
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

    /*! return true if call refused */
    bool check_and_refuse(SqlCallProfile *profile,Cdr *cdr,
                          const AmSipRequest& req,ParamReplacerCtx& ctx,
                          bool send_reply = false);

    bool init(SBCCallLeg *call, const map<string, string> &values);

    void onSendRequest(SBCCallLeg *call,AmSipRequest& req, int &flags);
    void onStateChange(SBCCallLeg *call, const CallLeg::StatusChangeCause &cause);
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

    void holdRequested(SBCCallLeg *call) { }
    void holdAccepted(SBCCallLeg *call) { }
    void holdRejected(SBCCallLeg *call) { }
    void resumeRequested(SBCCallLeg *call) { }
    void resumeAccepted(SBCCallLeg *call) { }
    void resumeRejected(SBCCallLeg *call) { }
};
