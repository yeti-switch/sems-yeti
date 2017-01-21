#pragma once

#include "yeti_base.h"
#include "yeti_radius.h"

#include "SBCCallControlAPI.h"

#include "CallLeg.h"
#include "sbc_events.h"

class SBCCallLeg;
struct SBCCallProfile;
class SimpleRelayDialog;

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

  public:
    YetiCC(YetiBase &base)
      : YetiBase(base),
        YetiRadius(base)
    { }

    /*! return true if call refused */
    bool check_and_refuse(SqlCallProfile *profile,Cdr *cdr,
                          const AmSipRequest& req,ParamReplacerCtx& ctx,
                          bool send_reply = false);

    void onSendRequest(SBCCallLeg *call,AmSipRequest& req, int &flags);
    void onStateChange(SBCCallLeg *call, const CallLeg::StatusChangeCause &cause);
    CCChainProcessing onBLegRefused(SBCCallLeg *call,AmSipReply& reply);

    void onInviteException(SBCCallLeg *call,int code,string reason,bool no_reply);
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

    void onB2Binitial1xx(SBCCallLeg *call, AmSipReply& reply, bool forward);

    void onRTPStreamDestroy(SBCCallLeg *call,AmRtpStream *stream);
    void onSdpCompleted(SBCCallLeg *call, AmSdp& offer, AmSdp& answer);
    bool getSdpOffer(SBCCallLeg *call, AmSdp& offer);

};
