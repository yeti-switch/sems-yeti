#include "CallLeg.h"

#include "AmSessionContainer.h"
#include "AmLcConfig.h"
#include "AmUtils.h"

#define TRACE DBG

// helper functions

static const char *callStatus2str(const CallLeg::CallStatus state)
{
    static const char *disconnected = "Disconnected";
    static const char *disconnecting = "Disconnecting";
    static const char *noreply = "NoReply";
    static const char *ringing = "Ringing";
    static const char *connected = "Connected";
    static const char *unknown = "Unknown";

    switch (state) {
        case CallLeg::Disconnected: return disconnected;
        case CallLeg::Disconnecting: return disconnecting;
        case CallLeg::NoReply: return noreply;
        case CallLeg::Ringing: return ringing;
        case CallLeg::Connected: return connected;
    }

    return unknown;
}

ReliableB2BEvent::~ReliableB2BEvent()
{
    TRACE("reliable event was %sprocessed, sending %p to %s\n",
        processed ? "" : "NOT ",
        processed ? processed_reply : unprocessed_reply,
        sender.c_str());
    if (processed) {
        if (unprocessed_reply) delete unprocessed_reply;
        if (processed_reply)
            AmSessionContainer::instance()->postEvent(sender, processed_reply);
    } else {
        if (processed_reply) delete processed_reply;
        if (unprocessed_reply)
            AmSessionContainer::instance()->postEvent(sender, unprocessed_reply);
    }
}

////////////////////////////////////////////////////////////////////////////////

// callee
CallLeg::CallLeg(const CallLeg* caller, AmSipDialog* p_dlg, AmSipSubscription* p_subs)
  : AmB2BSession(caller->getLocalTag(),p_dlg,p_subs),
    call_status(Disconnected),
    allow_1xx_without_to_tag(false),
    on_hold(false),
    hold(PreserveHoldStatus),
    redirects_allowed(0)
{
    a_leg = !caller->a_leg; // we have to be the complement

    set_sip_relay_only(false); // will be changed later on (for now we have no peer so we can't relay)

    // enable OA for the purpose of hold request detection
    if (dlg) dlg->setOAEnabled(true);
    else WARN("can't enable OA!");

    // code below taken from createCalleeSession

    const AmSipDialog* caller_dlg = caller->dlg;

    dlg->setLocalTag(AmSession::getNewId());
    dlg->setCallid(AmSession::getNewId());

    // take important data from A leg
    dlg->setLocalParty(caller_dlg->getRemoteParty());
    dlg->setRemoteParty(caller_dlg->getLocalParty());
    dlg->setRemoteUri(caller_dlg->getLocalUri());

    // copy common RTP relay settings from A leg
    //initRTPRelay(caller);
    vector<SdpPayload> lowfi_payloads;
    setRtpRelayMode(caller->getRtpRelayMode());
    setEnableDtmfTranscoding(caller->getEnableDtmfTranscoding());
    caller->getLowFiPLs(lowfi_payloads);
    setLowFiPLs(lowfi_payloads);
}

// caller
CallLeg::CallLeg(AmSipDialog* p_dlg, AmSipSubscription* p_subs)
  : AmB2BSession("",p_dlg,p_subs),
    call_status(Disconnected),
    allow_1xx_without_to_tag(false),
    on_hold(false),
    hold(PreserveHoldStatus),
    redirects_allowed(0)
{
    a_leg = true;

    // At least in the first version we start relaying after the call is fully
    // established.  This is because of forking possibility - we can't simply
    // relay if we have one A leg and multiple B legs.
    // It is possible to start relaying before call is established if we have
    // exactly one B leg (i.e. no parallel fork happened).
    set_sip_relay_only(false);

    // enable OA for the purpose of hold request detection
    if (dlg) dlg->setOAEnabled(true);
    else WARN("can't enable OA!");
}

CallLeg::~CallLeg()
{
    // do necessary cleanup (might be needed if the call leg is destroyed other
    // way then expected)
    /*for (vector<OtherLegInfo>::iterator i = other_legs.begin(); i != other_legs.end(); ++i) {
        i->releaseMediaSession();
    }*/
}

void CallLeg::terminateOtherLeg()
{
    if (call_status != Connected) {
        DBG("trying to terminate other leg in %s state -> terminating the others as well", callStatus2str(call_status));
        // FIXME: may happen when for example reply forward fails, do we want to terminate
        // all other legs in such case?
        terminateNotConnectedLegs(); // terminates all except the one identified by other_id
    }

    AmB2BSession::terminateOtherLeg();

    // remove this one from the list of other legs
    other_legs.erase(getOtherId());

    // FIXME: call disconnect if connected (to put remote on hold)?
    if (getCallStatus() != Disconnected) updateCallStatus(Disconnected); // no B legs should be remaining
}

void CallLeg::terminateNotConnectedLegs()
{
    auto it = other_legs.begin();
    while(it != other_legs.end()) {
        if(it->first == getOtherId()) {
            ++it;
            continue;
        }

        AmSessionContainer::instance()->postEvent(
            it->first, new B2BEvent(B2BTerminateLeg));

        it = other_legs.erase(it);
    }
}

void CallLeg::removeOtherLeg(const string &id)
{
    if (getOtherId() == id) AmB2BSession::clear_other();

    // remove the call leg from list of B legs
    other_legs.erase(id);

    /*if (terminate)
        AmSessionContainer::instance()->postEvent(id, new B2BEvent(B2BTerminateLeg));*/
}

// composed for caller and callee already
void CallLeg::onB2BEvent(B2BEvent* ev)
{
    switch (ev->event_id) {

    case B2BSipReply:
        onB2BReply(dynamic_cast<B2BSipReplyEvent*>(ev));
        break;

    case ConnectLeg:
        onB2BConnect(dynamic_cast<ConnectLegEvent*>(ev));
        break;

    case ResumeHeld: {
        ResumeHeldEvent *e = dynamic_cast<ResumeHeldEvent*>(ev);
        if (e) resumeHeld();
    } break;

    case B2BSipRequest:
        if (!sip_relay_only) {
            // disable forwarding of relayed request if we are not connected [yet]
            // (only we known that, the B leg has just delayed information about being
            // connected to us and thus it can't set)
            // Need not to be done if we have only one possible B leg so instead of
            // checking call_status we can check if sip_relay_only is set or not
            B2BSipRequestEvent *req_ev = dynamic_cast<B2BSipRequestEvent*>(ev);
            if (req_ev) req_ev->forward = false;
        }
        // continue handling in AmB2bSession
        [[fallthrough]];
    default:
      AmB2BSession::onB2BEvent(ev);
    } //switch (ev->event_id)
}

int CallLeg::relaySipReply(AmSipReply &reply)
{
    std::map<int,AmSipRequest>::iterator t_req = recvd_req.find(reply.cseq);

    if (t_req == recvd_req.end()) {
        ERROR("%s: Request with CSeq %u not found in recvd_req for %u reply.",
            getLocalTag().c_str(),reply.cseq,reply.code);
        return 0; // ignore?
    }

    int res;
    AmSipRequest req(t_req->second);

    if ((reply.code >= 300) && (reply.code <= 305) && !reply.contact.empty()) {
        // relay with Contact in 300 - 305 redirect messages
        AmSipReply n_reply(reply);
        n_reply.hdrs += SIP_HDR_COLSP(SIP_HDR_CONTACT) + reply.contact + CRLF;

        res = relaySip(req, n_reply);
    } else {
        res = relaySip(req, reply); // relay response directly
    }

    return res;
}

bool CallLeg::setOther(const string &id, bool forward)
{
    if (getOtherId() == id)
        return true; // already set (needed when processing 2xx after 1xx)

    auto it = other_legs.find(id);
    if(it == other_legs.end()) {
        ERROR("%s is not in the list of other leg IDs!", id.c_str());
        return false;
    }

    setOtherId(id);

    if(!getMediaSession()) {
        AmB2BMedia *m = it->second;
        setMediaSession(m);
        if(m) {
            TRACE("connecting media session: %s to %s\n",
                  dlg->getLocalTag().c_str(), getOtherId().c_str());
            m->changeSession(a_leg, this);
        } else {
            if(rtp_relay_mode != AmB2BSession::RTP_Direct)
                setRtpRelayMode(AmB2BSession::RTP_Direct);
        }
    }

    if (forward && dlg->getOAState() == AmOfferAnswer::OA_Completed) {
        // reset OA state to offer_recived if already completed to accept new
        // B leg's SDP
        dlg->setOAState(AmOfferAnswer::OA_OfferRecved);
    }

    set_sip_relay_only(true); // relay only from now on

    return true;
}

void CallLeg::b2bInitial1xx(AmSipReply& reply, bool forward)
{
    // stop processing of 100 reply here or add Trying state to handle it without
    // remembering other_id (for now, the 100 won't get here, but to be sure...)
    // Warning: 100 reply may have to tag but forward is explicitly set to false,
    // so it can't be used to check whether it is related to a forwarded request
    // or not!
    if (reply.code == 100) {
        DBG("discard 100 Trying");
        return;
    }

    if(reply.to_tag.empty()){
        DBG("got %d without to_tag. allow_1xx_without_to_tag = %d",
            reply.code,allow_1xx_without_to_tag);
        if(!allow_1xx_without_to_tag) return;
        //fix to_tag
        reply.to_tag = dlg->getExtLocalTag().empty() ?
            dlg->getLocalTag() : dlg->getExtLocalTag();
    }

    if (call_status == NoReply) {
        DBG("1xx reply with to-tag received in NoReply state,"
            " changing status to Ringing and remembering the"
            " other leg ID (%s)\n", getOtherId().c_str());

        if (setOther(reply.from_tag, forward)) {
            updateCallStatus(Ringing, &reply);
            if (forward && relaySipReply(reply) != 0)
                stopCall(StatusChangeCause::InternalError);
        }
    } else {
        if (getOtherId() == reply.from_tag) {
            // we can relay this reply because it is from the same B leg from which
            // we already relayed something
            if (forward && relaySipReply(reply) != 0)
                stopCall(StatusChangeCause::InternalError);
        } else {
            // in Ringing state but the reply comes from another B leg than
            // previous 1xx reply => do not relay or process other way
            DBG("1xx reply received in %s state from another B leg, ignoring", callStatus2str(call_status));
        }
    }
}

void CallLeg::b2bInitial2xx(AmSipReply& reply, bool forward)
{
    if (!setOther(reply.from_tag, forward)) {
        // ignore reply which comes from non-our-peer leg?
        DBG("2xx reply received from unknown B leg, ignoring");
        return;
    }

    DBG("setting call status to connected with leg %s", getOtherId().c_str());

    // terminate all other legs than the connected one (determined by other_id)
    terminateNotConnectedLegs();

    other_legs.clear(); // no need to remember the connected leg here

    onCallConnected(reply);

    if (!forward) {
        // we need to generate re-INVITE based on received SDP
        saveSessionDescription(reply.body);
        sendEstablishedReInvite();
    } else if (relaySipReply(reply) != 0) {
        stopCall(StatusChangeCause::InternalError);
        return;
    }
    updateCallStatus(Connected, &reply);
}

void CallLeg::onInitialReply(B2BSipReplyEvent *e)
{
    if (e->reply.code < 200) b2bInitial1xx(e->reply, e->forward);
    else if (e->reply.code < 300) b2bInitial2xx(e->reply, e->forward);
    else b2bInitialErr(e->reply, e->forward);
}

void CallLeg::b2bInitialErr(AmSipReply& reply, bool forward)
{
    if (getCallStatus() == Ringing && getOtherId() != reply.from_tag) {
        removeOtherLeg(reply.from_tag); // we don't care about this leg any more
        onBLegRefused(reply); // new B leg(s) may be added
        DBG("dropping non-ok reply, it is not from current peer");
        return;
    }

    DBG("clean-up after non-ok reply (reply: %d, status %s, other: %s)",
        reply.code, callStatus2str(getCallStatus()),
        getOtherId().c_str());

    removeOtherLeg(reply.from_tag); // we don't care about this leg any more
    updateCallStatus(NoReply, &reply);
    onBLegRefused(reply); // possible serial fork here
    set_sip_relay_only(false);

    // there are other B legs for us => wait for their responses and do not
    // relay current response
    if (!other_legs.empty()) return;

    clearRtpReceiverRelay();

    onCallFailed(CallRefused, &reply);
    if (forward) relaySipReply(reply);

    // no other B legs, terminate
    updateCallStatus(Disconnected, &reply);
    stopCall(&reply);
}

// was for caller only
void CallLeg::onB2BReply(B2BSipReplyEvent *ev)
{
    if (!ev) {
        ERROR("BUG: invalid argument given");
        return;
    }

    AmSipReply& reply = ev->reply;

    TRACE("%s: B2B SIP reply %d/%d %s received in %s state\n",
        getLocalTag().c_str(),
        reply.code, reply.cseq, reply.cseq_method.c_str(),
        callStatus2str(call_status));

    // FIXME: testing est_invite_cseq is wrong! (checking in what direction or
    // what role would be needed)
    bool initial_reply = (reply.cseq_method == SIP_METH_INVITE &&
        (call_status == NoReply || call_status == Ringing) &&
        ((reply.cseq == est_invite_cseq && ev->forward) || // related to initial INVITE at our side
        (!ev->forward))); // connect not related to initial INVITE at our side

    if (initial_reply) {
        // handle relayed initial replies (replies to initiating INVITE at the other
        // side, note that this need not to be initiating INVITE at our side)
        TRACE("established CSeq: %d, forward: %s\n", est_invite_cseq, ev->forward ? "yes": "no");
        onInitialReply(ev);
    } else {
        // handle non-initial replies
        if (call_status == Connected &&
            reply.code >= 200 &&
            reply.cseq_method == SIP_METH_INVITE &&
            reply.from_tag!=getOtherId())
        {
            if (reply.code < 300) {
                if (!setOther(reply.from_tag, false)) {
                    DBG("2xx reply received from unknown B leg");
                }
            } else {
                b2bConnectedErr(reply);
            }

            DBG("suppress other leg positive reply in Connected state");
            return;
        }

        // reply not from our peer (might be one of the discarded ones)
        if (getOtherId() != ev->sender_ltag &&
            getOtherId() != reply.from_tag)
        {
            TRACE("ignoring reply from %s in %s state, other_id = '%s'\n",
                reply.from_tag.c_str(), callStatus2str(call_status), getOtherId().c_str());
            return;
        }

        // handle replies to other requests than the initial one
        DBG("handling reply via AmB2BSession");
        AmB2BSession::onB2BEvent(ev);
    }
}

// TODO: original callee's version, update
void CallLeg::onB2BConnect(ConnectLegEvent* co_ev)
{
    if (!co_ev) {
        ERROR("BUG: invalid argument given");
        return;
    }

    if (call_status != Disconnected) {
        ERROR("BUG: ConnectLegEvent received in %s state", callStatus2str(call_status));
        return;
    }

    // This leg is marked as 'relay only' since the beginning because it might
    // need not to know on time that it is connected and thus should relay.
    //
    // For example: B leg received 2xx reply, relayed it to A leg and is
    // immediatelly processing in-dialog request which should be relayed, but
    // A leg didn't have chance to process the relayed reply so the B leg is not
    // connected to the A leg yet when handling the in-dialog request.
    set_sip_relay_only(true); // we should relay everything to the other leg from now

    AmMimeBody body(co_ev->body);
    try {
        updateLocalBody(body, SIP_METH_INVITE, dlg->cseq);
    } catch (const string& s) {
        relayError(SIP_METH_INVITE, co_ev->r_cseq, true, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        throw;
    }

    int res = dlg->sendRequest(
        SIP_METH_INVITE, &body,
        co_ev->hdrs, SIP_FLAGS_VERBATIM, &inv_timers_override,
        NULL, //target_set_override
        redirects_allowed);

    if (res < 0) {
        DBG("sending INVITE failed, relaying back error reply");
        relayError(SIP_METH_INVITE, co_ev->r_cseq, true, res);
        stopCall(StatusChangeCause::InternalError);
        return;
    }

    updateCallStatus(NoReply);

    if (co_ev->relayed_invite) {
        AmSipRequest fake_req;
        fake_req.method = SIP_METH_INVITE;
        fake_req.cseq = co_ev->r_cseq;
        relayed_req[dlg->cseq - 1] = fake_req;
        est_invite_other_cseq = co_ev->r_cseq;
    } else {
        est_invite_other_cseq = 0;
    }

    if (!co_ev->body.empty()) {
        saveSessionDescription(co_ev->body);
    }

    // save CSeq of establising INVITE
    est_invite_cseq = dlg->cseq - 1;
}

static void sdp2body(const AmSdp &sdp, AmMimeBody &body)
{
    string body_str;
    sdp.print(body_str);

    AmMimeBody *s = body.hasContentType(SIP_APPLICATION_SDP);
    if (s)
        s->parse(
            SIP_APPLICATION_SDP,
            (const unsigned char*)body_str.c_str(),
            body_str.length());
    else
        body.parse(
            SIP_APPLICATION_SDP,
            (const unsigned char*)body_str.c_str(),
            body_str.length());
}

void CallLeg::putOnHold()
{
    if (on_hold) return;

    TRACE("putting remote on hold\n");
    hold = HoldRequested;

    holdRequested();

    AmSdp sdp;
    createHoldRequest(sdp);
    updateLocalSdp(sdp, SIP_METH_INVITE, dlg->cseq);

    AmMimeBody body;
    sdp2body(sdp, body);

    if (dlg->getUACInvTransPending()) {
        // there is pending INVITE, add reinvite to waiting requests
        DBG("INVITE pending, queueing hold Re-Invite");
        queueReinvite("", body);
    } else if (dlg->reinvite("", &body, SIP_FLAGS_VERBATIM) != 0) {
        ERROR("re-INVITE failed");
        offerRejected();
    }
    //else hold_request_cseq = dlg->cseq - 1;
}

void CallLeg::resumeHeld(/*bool send_reinvite*/)
{
    if (!on_hold) return;

    try {
        TRACE("resume held remote\n");
        hold = ResumeRequested;

        resumeRequested();

        AmSdp sdp;
        createResumeRequest(sdp);
        if (sdp.media.empty()) {
          ERROR("invalid un-hold SDP, can't unhold");
          offerRejected();
          return;
        }

        updateLocalSdp(sdp, SIP_METH_INVITE, dlg->cseq);

        AmMimeBody body(established_body);
        sdp2body(sdp, body);
        if (dlg->getUACInvTransPending()) {
            // there is a pending INVITE, add reinvite to waiting requests
            DBG("INVITE pending, queueing un-hold Re-Invite");
            queueReinvite("", body);
        } else if (dlg->reinvite("", &body, SIP_FLAGS_VERBATIM) != 0) {
            ERROR("re-INVITE failed");
            offerRejected();
        }
        //else hold_request_cseq = dlg->cseq - 1;
    } catch (...) {
        offerRejected();
    }
}

void CallLeg::holdAccepted()
{
    DBG("hold accepted on %c leg", a_leg?'B':'A');
    if (call_status == Disconnecting) updateCallStatus(Disconnected);
    on_hold = true;
    AmB2BMedia *ms = getMediaSession();
    if (ms) {
        DBG("holdAccepted - mute %c leg", a_leg?'B':'A');
        ms->mute(!a_leg); // mute the stream in other (!) leg
    }
}

void CallLeg::holdRejected()
{
    if (call_status == Disconnecting) updateCallStatus(Disconnected);
}

void CallLeg::resumeAccepted()
{
    on_hold = false;
    AmB2BMedia *ms = getMediaSession();
    if (ms) ms->unmute(!a_leg); // unmute the stream in other (!) leg
    DBG("%s: resuming held, unmuting media session %p(%s)", getLocalTag().c_str(), ms, !a_leg ? "A" : "B");
}

// was for caller only
void CallLeg::onInvite(const AmSipRequest& req)
{
    // do not call AmB2BSession::onInvite(req); we changed the behavior
    // this method is not called for re-INVITEs because once connected we are in
    // sip_relay_only mode and the re-INVITEs are relayed instead of processing
    // (see AmB2BSession::onSipRequest)

    if (call_status == Disconnected) { // for initial INVITE only
        est_invite_cseq = req.cseq; // remember initial CSeq
        // initialize RTP relay

        // relayed INVITE - we need to add the original INVITE to
        // list of received (relayed) requests
        recvd_req.insert(std::make_pair(req.cseq, req));
    }
}

void CallLeg::onSipRequest(const AmSipRequest& req)
{
    TRACE("%s: SIP request %d %s received in %s state\n",
        getLocalTag().c_str(),
        req.cseq, req.method.c_str(), callStatus2str(call_status));

    // we need to handle cases if there is no other leg (for example call parking)
    // Note that setting sip_relay_only to false in this case doesn't solve the
    // problem because AmB2BSession always tries to relay the request into the
    // other leg.
    if ((getCallStatus() == Disconnected || getCallStatus() == Disconnecting)
        && getOtherId().empty())
    {
        TRACE("handling request %s in disconnected state", req.method.c_str());

        // this is not correct but what is?
        // handle reINVITEs within B2B call with no other leg
        if (req.method == SIP_METH_INVITE &&
            dlg->getStatus() == AmBasicSipDialog::Connected)
        {
            try {
                AmSession::onInvite(req);
                //or dlg->reply(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR); ?
            } catch(...) {
                ERROR("exception when handling INVITE in disconnected state");
                dlg->reply(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
                // stop the call?
            }
        } else
            AmSession::onSipRequest(req);

        if (req.method == SIP_METH_BYE) {
            stopCall(&req); // is this needed?
        }
    } else {
        if(((getCallStatus() == Disconnected) /*||
            (getCallStatus() == Connected && getOtherId().empty())*/)
            && req.method == SIP_METH_BYE)
        {
            // seems that we have already sent/received a BYE
            // -> we'd better terminate this ASAP
            //    to avoid other confusions...
            dlg->reply(req,200,"OK");
        } else
            AmB2BSession::onSipRequest(req);
    }

    if (req.method == SIP_METH_ACK && !pending_reinvites.empty()) {
        TRACE("ACK received, we can send a queued re-INVITE\n");
        PendingReinvite p = pending_reinvites.front();
        pending_reinvites.pop();
        reinvite(p.hdrs, p.body, p.relayed_invite, p.r_cseq, p.establishing);
    }
}

void CallLeg::onSipReply(const AmSipRequest& req, const AmSipReply& reply, AmSipDialog::Status old_dlg_status)
{
    TransMap::iterator t = relayed_req.find(reply.cseq);
    bool relayed_request = (t != relayed_req.end());

    TRACE("%s: SIP reply %d/%d %s (%s) received in %s state\n",
        getLocalTag().c_str(),
        reply.code, reply.cseq, reply.cseq_method.c_str(),
        (relayed_request ? "to relayed request" : "to locally generated request"),
        callStatus2str(call_status));

    AmB2BSession::onSipReply(req, reply, old_dlg_status);

    // update internal state and call related callbacks based on received reply
    // (i.e. B leg in case of initial INVITE)
    if (reply.cseq == est_invite_cseq &&
        reply.cseq_method == SIP_METH_INVITE &&
        (call_status == NoReply || call_status == Ringing))
    {
        // reply to the initial request
        if ((reply.code > 100) && (reply.code < 200)) {
            if (((call_status == NoReply)) && (!reply.to_tag.empty()))
                updateCallStatus(Ringing, &reply);
        } else if ((reply.code >= 200) && (reply.code < 300)) {
            onCallConnected(reply);
            updateCallStatus(Connected, &reply);
        } else if (reply.code >= 300) {
            updateCallStatus(Disconnected, &reply);
            terminateLeg(); // commit suicide (don't let the master to kill us)
        }
    }
}

// was for caller only
void CallLeg::onInvite2xx(const AmSipReply& reply)
{
    // We don't want to remember reply.cseq as est_invite_cseq, do we? It was in
    // AmB2BCallerSession but we already have initial INVITE cseq remembered and
    // we don't need to change it to last reINVITE one, right? Otherwise we should
    // remember UPDATE cseq as well because SDP may change by it as well (used
    // when handling B2BSipReply in AmB2BSession to check if reINVITE should be
    // sent).
    //
    // est_invite_cseq = reply.cseq;

    // we don't want to handle the 2xx using AmSession so the following may be
    // unwanted for us:
    AmB2BSession::onInvite2xx(reply);
}

void CallLeg::onCancel([[maybe_unused]] const AmSipRequest& req)
{
    // initial INVITE handling
    if ((call_status == Ringing) ||
        (call_status == NoReply) ||
        (call_status == Disconnected))
    {
        if (a_leg) {
            // terminate whole B2B call if the caller receives CANCEL
            onCallFailed(CallCanceled, NULL);
            updateCallStatus(Disconnected, StatusChangeCause::Canceled);
            stopCall(StatusChangeCause::Canceled);
        } // else { } ... ignore for B leg
    }
}

void CallLeg::terminateLeg()
{
    AmB2BSession::terminateLeg();
}

// was for caller only
void CallLeg::onRemoteDisappeared(const AmSipReply& reply) 
{
    if (call_status == Connected) {
        // only in case we are really connected
        // (called on timeout or 481 from the remote)

        DBG("remote unreachable, ending B2BUA call");
        // FIXME: shouldn't be cleared in AmB2BSession as well?
        clearRtpReceiverRelay();
        AmB2BSession::onRemoteDisappeared(reply); // terminates the other leg
        updateCallStatus(Disconnected, &reply);
    }
}

// was for caller only
void CallLeg::onBye(const AmSipRequest& req)
{
    terminateNotConnectedLegs();
    updateCallStatus(Disconnected, &req);
    clearRtpReceiverRelay(); // FIXME: shouldn't be cleared in AmB2BSession as well?
    AmB2BSession::onBye(req);
}

void CallLeg::onOtherBye(const AmSipRequest& req)
{
    updateCallStatus(Disconnected, &req);
    AmB2BSession::onOtherBye(req);
}

void CallLeg::onNoAck(unsigned int cseq)
{
    updateCallStatus(Disconnected, StatusChangeCause::NoAck);
    AmB2BSession::onNoAck(cseq);
}

void CallLeg::onNoPrack(const AmSipRequest &req, const AmSipReply &rpl)
{
    updateCallStatus(Disconnected, StatusChangeCause::NoPrack);
    AmB2BSession::onNoPrack(req, rpl);
}

void CallLeg::onRtpTimeout()
{
    updateCallStatus(Disconnected, StatusChangeCause::RtpTimeout);
    AmB2BSession::onRtpTimeout();
}

void CallLeg::onSessionTimeout()
{
    updateCallStatus(Disconnected, StatusChangeCause::SessionTimeout);
    AmB2BSession::onSessionTimeout();
}

// AmMediaSession interface from AmMediaProcessor
int CallLeg::readStreams(unsigned long long ts, unsigned char *buffer)
{
    // skip RTP processing if in Relay mode
    // (but we want to process DTMF thus we may be in media processor)
    if (getRtpRelayMode()==RTP_Relay)
        return 0;
    return AmB2BSession::readStreams(ts, buffer);
}

int CallLeg::writeStreams(unsigned long long ts, unsigned char *buffer) {
    // skip RTP processing if in Relay mode
    // (but we want to process DTMF thus we may be in media processor)
    if (getRtpRelayMode()==RTP_Relay)
        return 0;
    return AmB2BSession::writeStreams(ts, buffer);
}

void CallLeg::addNewCallee(
    CallLeg *callee, ConnectLegEvent *e,
    AmB2BSession::RTPRelayMode mode)
{
    AmB2BMedia *m = nullptr;

    callee->setRtpRelayMode(mode);
    if (mode != RTP_Direct) {
        m = getMediaSession();
        if(!m) {
            // do not initialise the media session with A leg to avoid unnecessary A leg
            // RTP stream creation in every B leg's media session
            if (a_leg) {
                m = new AmB2BMedia(NULL, callee);
            } else {
                m = new AmB2BMedia(callee, NULL);
            }
            //setMediaSession(m);
            DBG("created b2b media session: %p",m);
        } else {
            DBG("reuse b2b media session: %p",m);
            m->changeSession(!a_leg,callee);
        }

        callee->setMediaSession(m);
    }

    other_legs.emplace(callee->getLocalTag(), m);

    if (AmConfig.log_sessions) {
        TRACE("Starting B2B callee session %s\n",
            callee->getLocalTag().c_str()/*, invite_req.cmd.c_str()*/);
    }

    AmSipDialog* callee_dlg = callee->dlg;
    MONITORING_LOG4(callee->getLocalTag().c_str(),
        "dir",  "out",
        "from", callee_dlg->getLocalParty().c_str(),
        "to",   callee_dlg->getRemoteParty().c_str(),
        "ruri", callee_dlg->getRemoteUri().c_str());

    callee->start_on_same_thread = true;
    callee->start();

    AmSessionContainer* sess_cont = AmSessionContainer::instance();
    sess_cont->addSession(callee->getLocalTag(), callee);

    // generate connect event to the newly added leg
    // Warning: correct callee's role must be already set (in constructor or so)
    TRACE("relaying connect leg event to the new leg\n");
    // other stuff than relayed INVITE should be set directly when creating callee
    // (remote_uri, remote_party is not propagated and thus B2BConnectEvent is not
    // used because it would just overwrite already set things. Note that in many
    // classes derived from AmB2BCaller[Callee]Session was a lot of things set
    // explicitly)
    AmSessionContainer::instance()->postEvent(callee->getLocalTag(), e);

    if (call_status == Disconnected)
        updateCallStatus(NoReply);
}

void CallLeg::setCallStatus(CallStatus new_status)
{
    call_status = new_status;
}

const char* CallLeg::getCallStatusStr() const
{
    return callStatus2str(getCallStatus());
}

void CallLeg::updateCallStatus(CallStatus new_status, const StatusChangeCause &cause)
{
    if (new_status == Connected)
        TRACE("%s leg %s changing status from %s to %s with %s\n",
            a_leg ? "A" : "B",
            getLocalTag().c_str(),
            callStatus2str(call_status),
            callStatus2str(new_status),
            getOtherId().c_str());
    else
        TRACE("%s leg %s changing status from %s to %s\n",
            a_leg ? "A" : "B",
            getLocalTag().c_str(),
            callStatus2str(call_status),
            callStatus2str(new_status));

    setCallStatus(new_status);
    onCallStatusChange(cause);
}

void CallLeg::queueReinvite(
    const string& hdrs, const AmMimeBody& body,
    bool establishing, bool relayed_invite, unsigned int r_cseq)
{
    PendingReinvite p;
    p.hdrs = hdrs;
    p.body = body;
    p.relayed_invite = relayed_invite;
    p.r_cseq = r_cseq;
    p.establishing = establishing;
    pending_reinvites.push(p);
}

void CallLeg::clear_other()
{
    removeOtherLeg(getOtherId());
    AmB2BSession::clear_other();
}

void CallLeg::stopCall(const StatusChangeCause &cause)
{
    if (getCallStatus() != Disconnected)
        updateCallStatus(Disconnected, cause);

    terminateNotConnectedLegs();
    terminateOtherLeg();
    terminateLeg();
}

void CallLeg::acceptPendingInvite(AmSipRequest *invite)
{
    // reply the INVITE with fake 200 reply

    AmMimeBody *sdp = invite->body.hasContentType(SIP_APPLICATION_SDP);
    AmSdp s;
    if (!sdp || s.parse((const char*)sdp->getPayload())) {
        // no offer in the INVITE (or can't be parsed), we have to append fake offer
        // into the reply
        s.version = 0;
        s.origin.user = AmConfig.sdp_origin;
        s.sessionName = AmConfig.sdp_session_name;
        s.conn.network = NT_IN;
        s.conn.addrType = AT_V4;
        s.conn.address = "0.0.0.0";

        s.media.push_back(SdpMedia());
        SdpMedia &m = s.media.back();
        m.type = MT_AUDIO;
        m.transport = TP_RTPAVP;
        m.send = false;
        m.recv = false;
        m.payloads.push_back(SdpPayload(0));
    }

    if (!s.conn.address.empty()) s.conn.address = "0.0.0.0";
    for (vector<SdpMedia>::iterator i = s.media.begin();
         i != s.media.end(); ++i)
    {
        //i->port = 0;
        if (!i->conn.address.empty()) i->conn.address = "0.0.0.0";
    }

    AmMimeBody body;
    string body_str;
    s.print(body_str);
    body.parse(SIP_APPLICATION_SDP, (const unsigned char*)body_str.c_str(), body_str.length());
    try {
        updateLocalBody(body, invite->method, invite->cseq);
    } catch (...) { /* throw ? */  }

    TRACE("replying pending INVITE with body: %s\n", body_str.c_str());
    dlg->reply(*invite, 200, "OK", &body);

    if (getCallStatus() != Connected) updateCallStatus(Connected);
}

void CallLeg::reinvite(
    const string &hdrs, const AmMimeBody &body,
    bool relayed, unsigned r_cseq, bool establishing)
{
    int res;
    try {
        AmMimeBody r_body(body);
        updateLocalBody(r_body, SIP_METH_INVITE, dlg->cseq);
        res = dlg->sendRequest(SIP_METH_INVITE, &r_body, hdrs, SIP_FLAGS_VERBATIM);
    } catch (const string& s) { res = -500; }

    if (res < 0) {
        if (relayed) {
          DBG("sending re-INVITE failed, relaying back error reply");
          relayError(SIP_METH_INVITE, r_cseq, true, res);
        }

        DBG("sending re-INVITE failed, terminating the call");
        stopCall(StatusChangeCause::InternalError);
        return;
    }

    if (relayed) {
        AmSipRequest fake_req;
        fake_req.method = SIP_METH_INVITE;
        fake_req.cseq = r_cseq;
        relayed_req[dlg->cseq - 1] = fake_req;
        est_invite_other_cseq = r_cseq;
    } else
        est_invite_other_cseq = 0;

    saveSessionDescription(body);

    if (establishing) {
        // save CSeq of establishing INVITE
        est_invite_cseq = dlg->cseq - 1;
    }
}

void CallLeg::adjustOffer(AmSdp &sdp)
{
    if (hold != PreserveHoldStatus) {
        DBG("local hold/unhold request");
        // locally generated hold/unhold requests that already contain correct
        // hold/resume bodies and need not to be altered via createHoldRequest
        // hold/resumeRequested is already called
    } else {
        // handling B2B SDP, check for hold/unhold
        HoldMethod hm;

        // if hold request, transform to requested kind of hold and remember that hold
        // was requested with this offer
        if (isHoldRequest(sdp, hm)) {
            DBG("B2b hold request");
            holdRequested();
            alterHoldRequest(sdp);
            hold = HoldRequested;
        } else {
            if (on_hold) {
                DBG("B2b resume request");
                resumeRequested();
                alterResumeRequest(sdp);
                hold = ResumeRequested;
            }
        }
    }
}

void CallLeg::updateLocalSdp(
    AmSdp &sdp,
    const string &sip_msg_method, unsigned int sip_msg_cseq)
{
    TRACE("%s: updateLocalSdp (OA: %d, oa_cseq: %u, msg_cseq: %u)\n",
        getLocalTag().c_str(),
        dlg->getOAState(), dlg->getOAcseq(),
        sip_msg_cseq);

    // handle the body based on current offer-answer status
    // (possibly update the body before sending to remote)
    if (dlg->getOAState() == AmOfferAnswer::OA_None ||
        dlg->getOAState() == AmOfferAnswer::OA_Completed)
    {
        if (!dlg->isOASubsequentSDP(sip_msg_cseq, sip_msg_method)) {
            adjustOffer(sdp);
        } else {
            DBG("skip hold detection for subsequent SDP within the same transaction");
        }
    } else if (sip_msg_method == SIP_METH_ACK &&
               dlg->getOAState() == AmOfferAnswer::OA_OfferRecved)
    {
        //200ok/ACK offer/answer pair
        adjustOffer(sdp);
    }

    if (hold == PreserveHoldStatus && !on_hold) {
        // store non-hold SDP to be able to resumeHeld
        non_hold_sdp = sdp;
    }

    AmB2BSession::updateLocalSdp(sdp, sip_msg_method, sip_msg_cseq);
}

void CallLeg::offerRejected()
{
    switch (hold) {
        case HoldRequested: holdRejected(); break;
        case ResumeRequested: resumeRejected(); break;
        case PreserveHoldStatus: break;
    }
}

void CallLeg::createResumeRequest(AmSdp &sdp)
{
    // use stored non-hold SDP
    // Note: this SDP doesn't need to be correct, but established_body need not to
    // be good enough for unholding (might be held already with zero conncetions)
    if (!non_hold_sdp.media.empty()) sdp = non_hold_sdp;
    else {
        // no stored non-hold SDP
        ERROR("no stored non-hold SDP, but local resume requested");
        // TODO: try to use established_body here and mark properly

        // if no established body exist
        throw string("not implemented");
    }
    // do not touch the sdp otherwise (use directly B2B SDP)
}

void CallLeg::debug()
{
    DBG("call leg: %s", getLocalTag().c_str());
    DBG("\tother: %s", getOtherId().c_str());
    DBG("\tstatus: %s", callStatus2str(getCallStatus()));
    DBG("\tRTP relay mode: %d", rtp_relay_mode);
    DBG("\ton hold: %s", on_hold ? "yes" : "no");
    DBG("\toffer/answer status: %d, hold: %d", dlg->getOAState(), hold);

    AmB2BMedia *ms = getMediaSession();
    if (ms) ms->debug();
}

int CallLeg::onSdpCompleted(const AmSdp& offer, const AmSdp& answer)
{
    TRACE("%s: oaCompleted\n", getLocalTag().c_str());
    switch (hold) {
        case HoldRequested: holdAccepted(); break;
        case ResumeRequested: resumeAccepted(); break;
        case PreserveHoldStatus: break;
    }

    hold = PreserveHoldStatus;
    return AmB2BSession::onSdpCompleted(offer, answer);
}
