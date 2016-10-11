#include "yeti.h"
#include "cdr/Cdr.h"
#include "SDPFilter.h"
#include "sdp_filter.h"
#include "dtmf_sip_info.h"

#include "SipCtrlInterface.h"
#include "AmAudioFileRecorder.h"
#include "RegisterDialog.h"
#include "AmSipMsg.h"

#include "radius_hooks.h"
#include "Sensors.h"

#define getCtx_void \
	CallCtx *ctx = call->getCallCtx();\
	if(NULL==ctx){\
		ERROR("CallCtx = nullptr ");\
		log_stacktrace(L_ERR);\
		return;\
	}

#define getCtx_chained \
	CallCtx *ctx = call->getCallCtx();\
	if(NULL==ctx){\
		ERROR("CallCtx = nullptr ");\
		log_stacktrace(L_ERR);\
		return ContinueProcessing;\
	}

inline Cdr *getCdr(CallCtx *ctx) { return ctx->cdr; }
inline Cdr *getCdr(SBCCallLeg *call) { return getCdr(call->getCallCtx()); }

inline void replace(string& s, const string& from, const string& to){
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

#define with_cdr_for_read \
    Cdr *cdr = ctx->getCdrSafe<false>();\
    if(cdr)

#define with_cdr_for_write \
    Cdr *cdr = ctx->getCdrSafe<true>();\
    if(cdr)

void YetiCC::onSendRequest(SBCCallLeg *call,AmSipRequest& req, int &flags){
	bool aleg = call->isALeg();
	DBG("Yeti::onSendRequest(%p|%s) a_leg = %d",
		call,call->getLocalTag().c_str(),aleg);
	getCtx_void
	if(!aleg && req.method==SIP_METH_INVITE){
		with_cdr_for_read cdr->update(BLegInvite);
	}
}

void YetiCC::onStateChange(SBCCallLeg *call, const CallLeg::StatusChangeCause &cause){
	string reason;
	getCtx_void
	SBCCallLeg::CallStatus status = call->getCallStatus();
	bool aleg = call->isALeg();
	int internal_disconnect_code = 0;

	DBG("Yeti::onStateChange(%p|%s) a_leg = %d",
		call,call->getLocalTag().c_str(),call->isALeg());

	const SBCCallProfile &profile = call->getCallProfile();

	switch(status){
	case CallLeg::Ringing: {
		if(!aleg) {
			if(profile.ringing_timeout > 0)
				call->setTimer(YETI_RINGING_TIMEOUT_TIMER,profile.ringing_timeout);
		} else {
			if(profile.fake_ringing_timeout)
				call->removeTimer(YETI_FAKE_RINGING_TIMER);
			if(profile.force_one_way_early_media) {
				DBG("force one-way audio for early media (mute legB)");
				AmB2BMedia *m = call->getMediaSession();
				if(m) {
					m->mute(false);
					ctx->bleg_early_media_muted = true;
				}
			}
		}
	} break;
	case CallLeg::Connected:
		if(!aleg) {
			call->removeTimer(YETI_RINGING_TIMEOUT_TIMER);
		} else {
			if(profile.fake_ringing_timeout)
				call->removeTimer(YETI_FAKE_RINGING_TIMER);
			if(ctx->bleg_early_media_muted) {
				AmB2BMedia *m = call->getMediaSession();
				if(m) m->unmute(false);
			}
		}
		break;
	case CallLeg::Disconnected:
		call->removeTimer(YETI_RADIUS_INTERIM_TIMER);
		if(aleg && profile.fake_ringing_timeout) {
			call->removeTimer(YETI_FAKE_RINGING_TIMER);
		}
		break;
	default:
		break;
	}

	switch(cause.reason){
		case CallLeg::StatusChangeCause::SipReply:
			if(cause.param.reply!=NULL){
				reason = "SipReply. code = "+int2str(cause.param.reply->code);
				switch(cause.param.reply->code){
				case 408:
					internal_disconnect_code = DC_TRANSACTION_TIMEOUT;
					break;
				case 487:
					if(ctx->isRingingTimeout()){
						internal_disconnect_code = DC_RINGING_TIMEOUT;
					}
					break;
				}
			} else
				reason = "SipReply. empty reply";
			break;
		case CallLeg::StatusChangeCause::SipRequest:
			if(cause.param.request!=NULL){
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
		default:
			reason = "???";
	}

	if(status==CallLeg::Disconnected) {
		with_cdr_for_read {
			if(internal_disconnect_code) {
				unsigned int internal_code,response_code;
				string internal_reason,response_reason;

				CodesTranslator::instance()->translate_db_code(
					internal_disconnect_code,
					internal_code,internal_reason,
					response_code,response_reason,
					ctx->getOverrideId());
				cdr->update_internal_reason(DisconnectByTS,internal_reason,internal_code);
			}
			radius_accounting_stop(call, *cdr);
		}
	}

	DBG("%s(%p,leg%s,state = %s, cause = %s)",FUNC_NAME,call,aleg?"A":"B",
		callStatus2str(status),
		reason.c_str());

}

CCChainProcessing YetiCC::onBLegRefused(SBCCallLeg *call, AmSipReply& reply) {
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
    getCtx_chained
	Cdr* cdr = getCdr(ctx);
	CodesTranslator *ct = CodesTranslator::instance();
	unsigned int intermediate_code;
	string intermediate_reason;

	if(call->isALeg()){
		call->removeTimer(YETI_FAKE_RINGING_TIMER);

		cdr->update(reply);
		cdr->update_bleg_reason(reply.reason,reply.code);

		ct->rewrite_response(reply.code,reply.reason,
							 intermediate_code,intermediate_reason,
							 ctx->getOverrideId(false)); //bleg_override_id
		ct->rewrite_response(intermediate_code,intermediate_reason,
							 reply.code,reply.reason,
							 ctx->getOverrideId(true)); //aleg_override_id
		cdr->update_internal_reason(DisconnectByDST,intermediate_reason,intermediate_code);
		cdr->update_aleg_reason(reply.reason,reply.code);

		if(ct->stop_hunting(reply.code,ctx->getOverrideId(false))){
			DBG("stop hunting");
		} else {
			DBG("continue hunting");

			//put current resources
			//rctl.put(ctx->getCurrentResourceList());
			rctl.put(ctx->getCurrentProfile()->resource_handler);

			if(ctx->initial_invite!=NULL){
				if(chooseNextProfile(call)){
					DBG("%s() has new profile, so create new callee",FUNC_NAME);
					cdr = getCdr(ctx);

					if(0!=cdr_list.insert(cdr)){
						ERROR("onBLegRefused(): double insert into active calls list. integrity threat");
						ERROR("ctx: attempt = %d, cdr.logger_path = %s",
							ctx->attempt_num,cdr->msg_logger_path.c_str());
					} else {
						AmSipRequest &req = *ctx->initial_invite;
						try {
							connectCallee(ctx,call,req);
						} catch(InternalException &e){
							cdr->update_internal_reason(DisconnectByTS,e.internal_reason,e.internal_code);
							throw AmSession::Exception(e.response_code,e.response_reason);
						}
					}
				} else {
					DBG("%s() no new profile, just finish as usual",FUNC_NAME);
				}
			} else {
				ERROR("%s() intial_invite == NULL",FUNC_NAME);
			}
		} //stop_hunting
	} //call->isALeg()

	return ContinueProcessing;
}

void YetiCC::onRoutingReady(SBCCallLeg *call, AmSipRequest &aleg_modified_invite, AmSipRequest &modified_invite)
{
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");

	SqlCallProfile *profile = NULL;
	AmSipRequest &req = aleg_modified_invite;
	AmSipRequest &b_req = modified_invite;

	CallCtx *ctx = call->getCallCtx();
	Cdr *cdr = getCdr(ctx);
	ResourceCtlResponse rctl_ret;
	ResourceList::iterator ri;
	string refuse_reason;
	int refuse_code;
	int attempt = 0;

	PROF_START(func);

	try {

	PROF_START(rchk);
	do {
		DBG("%s() check resources for profile. attempt %d",FUNC_NAME,attempt);
		rctl_ret = rctl.get(ctx->getCurrentResourceList(),
							ctx->getCurrentProfile()->resource_handler,
							call->getLocalTag(),
							refuse_code,refuse_reason,ri);

		if(rctl_ret == RES_CTL_OK){
			DBG("%s() check resources succ",FUNC_NAME);
			break;
		} else if(	rctl_ret ==  RES_CTL_REJECT ||
					rctl_ret ==  RES_CTL_ERROR){
			DBG("%s() check resources failed with code: %d, reply: <%d '%s'>",FUNC_NAME,
				rctl_ret,refuse_code,refuse_reason.c_str());
			if(rctl_ret == RES_CTL_REJECT) {
				cdr->update_failed_resource(*ri);
			}
			break;
		} else if(	rctl_ret == RES_CTL_NEXT){
			DBG("%s() check resources failed with code: %d, reply: <%d '%s'>",FUNC_NAME,
				rctl_ret,refuse_code,refuse_reason.c_str());

			profile = ctx->getNextProfile(true);

			if(NULL==profile){
				cdr->update_failed_resource(*ri);
				DBG("%s() there are no profiles more",FUNC_NAME);
				throw AmSession::Exception(503,"no more profiles");
			}

			DBG("%s() choosed next profile",FUNC_NAME);

			/* show resource disconnect reason instead of
			 * refuse_profile if refuse_profile follows failed resource with
			 * failover to next */
			if(profile->disconnect_code_id!=0){
				cdr->update_failed_resource(*ri);
				throw AmSession::Exception(refuse_code,refuse_reason);
			}

			ParamReplacerCtx rctx(profile);
			if(check_and_refuse(profile,cdr,req,rctx)){
				throw AmSession::Exception(cdr->disconnect_rewrited_code,
										   cdr->disconnect_rewrited_reason);
			}
		}
		attempt++;
	} while(rctl_ret != RES_CTL_OK);

	if(rctl_ret != RES_CTL_OK){
		throw AmSession::Exception(refuse_code,refuse_reason);
	}

	PROF_END(rchk);
	PROF_PRINT("check and grab resources",rchk);

	profile = ctx->getCurrentProfile();
	cdr->update(profile->rl);
	call->updateCallProfile(*profile);

	SBCCallProfile &call_profile = call->getCallProfile();

	PROF_START(sdp_processing);
	//filterSDP
	int res = processSdpOffer(call_profile,
							  req.body, req.method,
							  ctx->aleg_negotiated_media,
							  call_profile.static_codecs_aleg_id);
	if(res < 0){
		INFO("%s() Not acceptable codecs",FUNC_NAME);
		throw InternalException(FC_CODECS_NOT_MATCHED);
	}

	//next we should filter request for legB
	res = filterSdpOffer(call,
						   call_profile,
						   b_req.body,b_req.method,
						   call_profile.static_codecs_bleg_id,
						   &ctx->bleg_initial_offer);
	if(res < 0){
		INFO("%s() Not acceptable codecs for legB",FUNC_NAME);
		throw AmSession::Exception(488, SIP_REPLY_NOT_ACCEPTABLE_HERE);
	}
	PROF_END(sdp_processing);
	PROF_PRINT("initial sdp processing",sdp_processing);

	if(cdr->time_limit){
		DBG("%s() save timer %d with timeout %d",FUNC_NAME,
			YETI_CALL_DURATION_TIMER,
			cdr->time_limit);
		call->saveCallTimer(YETI_CALL_DURATION_TIMER,cdr->time_limit);
	}

	if(0!=cdr_list.insert(cdr)){
		ERROR("onInitialInvite(): double insert into active calls list. integrity threat");
		ERROR("ctx: attempt = %d, cdr.logger_path = %s",
			ctx->attempt_num,cdr->msg_logger_path.c_str());
		log_stacktrace(L_ERR);
		throw AmSession::Exception(500,SIP_REPLY_SERVER_INTERNAL_ERROR);
	}

	if(!call_profile.append_headers.empty()){
		replace(call_profile.append_headers,"%global_tag",call->getGlobalTag());
	}

	call->onRoutingReady();

	} catch(InternalException &e) {
		DBG("%s() catched InternalException(%d)",FUNC_NAME,
			e.icode);
		rctl.put(call->getCallProfile().resource_handler);
		cdr->update_internal_reason(DisconnectByTS,e.internal_reason,e.internal_code);
		throw AmSession::Exception(e.response_code,e.response_reason);
	} catch(AmSession::Exception &e) {
		DBG("%s() catched AmSession::Exception(%d,%s)",FUNC_NAME,
			e.code,e.reason.c_str());
		rctl.put(call->getCallProfile().resource_handler);
		cdr->update_internal_reason(DisconnectByTS,e.reason,e.code);
		throw e;
	}

	PROF_END(func);
	PROF_PRINT("yeti onRoutingReady()",func);
	return;
}

void YetiCC::onInviteException(SBCCallLeg *call,int code,string reason,bool no_reply){
	DBG("%s(%p,leg%s) %d:'%s' no_reply = %d",FUNC_NAME,call,call->isALeg()?"A":"B",
		code,reason.c_str(),no_reply);
    getCtx_void
    Cdr *cdr = getCdr(ctx);
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

CCChainProcessing YetiCC::onInDialogRequest(SBCCallLeg *call, const AmSipRequest &req) {
	bool aleg = call->isALeg();
	SBCCallProfile &p = call->getCallProfile();
	AmSipDialog* dlg = call->dlg;
	const char *local_tag = call->getLocalTag().c_str();

	DBG("%s(%p|%s,leg%s) '%s'",FUNC_NAME,call,local_tag,aleg?"A":"B",req.method.c_str());

	if(req.method == SIP_METH_OPTIONS
		&& ((aleg && !p.aleg_relay_options)
			|| (!aleg && !p.bleg_relay_options)))
	{
		dlg->reply(req, 200, "OK", NULL, "", SIP_FLAGS_VERBATIM);
		return StopProcessing;
	} else if(req.method == SIP_METH_UPDATE
			  && ((aleg && !p.aleg_relay_update)
				  || (!aleg && !p.bleg_relay_update)))
	{
		getCtx_chained

		const AmMimeBody* sdp_body = req.body.hasContentType(SIP_APPLICATION_SDP);
		if(!sdp_body){
			DBG("got UPDATE without body. local processing enabled. generate 200OK without SDP");
			AmSipRequest upd_req(req);
			call->processLocalRequest(upd_req);
			return StopProcessing;
		}

		AmSdp sdp;
		int res = sdp.parse((const char *)sdp_body->getPayload());
		if(0 != res) {
			DBG("SDP parsing failed: %d. respond with 488\n",res);
			dlg->reply(req,488,"Not Acceptable Here");
			return StopProcessing;
		}

		AmSipRequest upd_req(req);
		try {
			int res = processSdpOffer(
				p,
				upd_req.body, upd_req.method,
				ctx->get_self_negotiated_media(aleg),
				aleg ? p.static_codecs_aleg_id : p.static_codecs_bleg_id,
				true,
				aleg ? p.aleg_single_codec : p.bleg_single_codec
			);
			if (res < 0) {
				dlg->reply(req,488,"Not Acceptable Here");
				return StopProcessing;
			}
		} catch(InternalException &e){
			dlg->reply(req,e.response_code,e.response_reason);
			return StopProcessing;
		}

		call->processLocalRequest(upd_req);
		return StopProcessing;
	} else if(req.method == SIP_METH_PRACK
			  && ((aleg && !p.aleg_relay_prack)
				  || (!aleg && !p.bleg_relay_prack)))
	{
		dlg->reply(req,200, "OK", NULL, "", SIP_FLAGS_VERBATIM);
		return StopProcessing;
	} else if(req.method == SIP_METH_INVITE)
	{
		getCtx_chained
		if((aleg && p.aleg_relay_reinvite)
			|| (!aleg && p.bleg_relay_reinvite))
		{
			DBG("skip local processing. relay");
			return ContinueProcessing;
		}

		const AmMimeBody* sdp_body = req.body.hasContentType(SIP_APPLICATION_SDP);
		if(!sdp_body){
			DBG("got reINVITE without body. local processing enabled. generate 200OK with SDP offer");
			DBG("replying 100 Trying to INVITE to be processed locally");
			dlg->reply(req, 100, SIP_REPLY_TRYING);
			AmSipRequest inv_req(req);
			call->processLocalRequest(inv_req);
			return StopProcessing;
		}

		AmSdp sdp;
		int res = sdp.parse((const char *)sdp_body->getPayload());
		if(0 != res) {
			DBG("replying 100 Trying to INVITE to be processed locally");
			dlg->reply(req, 100, SIP_REPLY_TRYING);
			DBG("SDP parsing failed: %d. respond with 488\n",res);
			dlg->reply(req,488,"Not Acceptable Here");
			return StopProcessing;
		}

		//check for hold/unhold request to pass them transparently
		HoldMethod method;
		if(isHoldRequest(sdp,method)){
			DBG("hold request matched. relay_hold = %d",
				aleg?p.aleg_relay_hold:p.bleg_relay_hold);

			if((aleg && p.aleg_relay_hold)
				|| (!aleg && p.bleg_relay_hold))
			{
				DBG("skip local processing for hold request");
				ctx->on_hold = true;
				return ContinueProcessing;
			}
		} else if(ctx->on_hold){
			DBG("we in hold state. skip local processing for unhold request");
			ctx->on_hold = false;
			return ContinueProcessing;
		}

		DBG("replying 100 Trying to INVITE to be processed locally");
		dlg->reply(req, 100, SIP_REPLY_TRYING);

		AmSipRequest inv_req(req);
		try {
			int res = processSdpOffer(
				p,
				inv_req.body, inv_req.method,
				ctx->get_self_negotiated_media(aleg),
				aleg ? p.static_codecs_aleg_id : p.static_codecs_bleg_id,
				true,
				aleg ? p.aleg_single_codec : p.bleg_single_codec
			);
			if (res < 0) {
				dlg->reply(req,488,"Not Acceptable Here");
				return StopProcessing;
			}
		} catch(InternalException &e){
			dlg->reply(req,e.response_code,e.response_reason);
			return StopProcessing;
		}

		call->processLocalRequest(inv_req);
		return StopProcessing;
	}

	if(aleg){
		if(req.method==SIP_METH_CANCEL){
			getCtx_chained
			with_cdr_for_read {
				cdr->update_internal_reason(DisconnectByORG,"Request terminated (Cancel)",487);
			}
		}
	}

	return ContinueProcessing;
}

CCChainProcessing YetiCC::onInDialogReply(SBCCallLeg *call, const AmSipReply &reply) {
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");

	if(!call->isALeg()){
		getCtx_chained
		with_cdr_for_read {
			cdr->update(reply);
		}
	}
	return ContinueProcessing;
}

CCChainProcessing YetiCC::onEvent(SBCCallLeg *call, AmEvent *e) {
	DBG("%s(%p|%s,leg%s)",FUNC_NAME,call,
		call->getLocalTag().c_str(),call->isALeg()?"A":"B");

	getCtx_chained

	RadiusReplyEvent *radius_event = dynamic_cast<RadiusReplyEvent*>(e);
	if(radius_event){
		onRadiusReply(call,*radius_event);
		return StopProcessing;
	}

	AmRtpTimeoutEvent *rtp_event = dynamic_cast<AmRtpTimeoutEvent*>(e);
	if(rtp_event){
		DBG("rtp event id: %d",rtp_event->event_id);
		return onRtpTimeout(call,*rtp_event);
	}

	AmSipRequestEvent *request_event = dynamic_cast<AmSipRequestEvent*>(e);
	if(request_event){
		AmSipRequest &req = request_event->req;
		DBG("request event method: %s",
			req.method.c_str());
	}

	AmSipReplyEvent *reply_event = dynamic_cast<AmSipReplyEvent*>(e);
	if(reply_event){
		AmSipReply &reply = reply_event->reply;
		DBG("reply event  code: %d, reason:'%s'",
			reply.code,reply.reason.c_str());
		//!TODO: find appropiate way to avoid hangup in disconnected state
		if(reply.code==408 && call->getCallStatus()==CallLeg::Disconnected){
			DBG("received 408 in disconnected state. a_leg = %d, local_tag: %s",
				  call->isALeg(), call->getLocalTag().c_str());
			throw AmSession::Exception(500,SIP_REPLY_SERVER_INTERNAL_ERROR);
		}
	}

	AmPluginEvent* plugin_event = dynamic_cast<AmPluginEvent*>(e);
	if(plugin_event){
		DBG("%s plugin_event. name = %s, event_id = %d",FUNC_NAME,
			plugin_event->name.c_str(),
			plugin_event->event_id);
		if(plugin_event->name=="timer_timeout"){
			return onTimerEvent(call,plugin_event->data.get(0).asInt());
		}
	}

	SBCControlEvent* sbc_event = dynamic_cast<SBCControlEvent*>(e);
	if(sbc_event){
		DBG("sbc event id: %d, cmd: %s",sbc_event->event_id,sbc_event->cmd.c_str());
		onControlEvent(call,sbc_event);
	}

	B2BEvent* b2b_e = dynamic_cast<B2BEvent*>(e);
	if(b2b_e){
		if(b2b_e->event_id==B2BTerminateLeg){
			DBG("onEvent(%p|%s) terminate leg event",
				call,call->getLocalTag().c_str());
		}
	}
	if (e->event_id == E_SYSTEM) {
		AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(e);
		if(sys_ev){
			DBG("sys event type: %d",sys_ev->sys_event);
			onSystemEvent(call,sys_ev);
		}
	}

	yeti_dtmf::DtmfInfoSendEvent *dtmf = dynamic_cast<yeti_dtmf::DtmfInfoSendEvent*>(e);
	if(dtmf){
		DBG("onEvent dmtf(%d:%d)",dtmf->event(),dtmf->duration());
		dtmf->send(call->dlg);
		e->processed = true;
		return StopProcessing;
	}

	return ContinueProcessing;
}

CCChainProcessing YetiCC::onDtmf(SBCCallLeg *call, AmDtmfEvent* e){
	DBG("%s(call = %p,event = %d,duration = %d)",
		FUNC_NAME,call,e->event(),e->duration());

	AmSipDtmfEvent *sip_dtmf = NULL;
	SBCCallProfile &p = call->getCallProfile();
	CallCtx *ctx = call->getCallCtx();
	bool aleg = call->isALeg();
	int rx_proto = 0;
	bool allowed = false;
	struct timeval now;

	gettimeofday(&now, NULL);

	//filter incoming methods
	if((sip_dtmf = dynamic_cast<AmSipDtmfEvent *>(e))){
		DBG("received SIP DTMF event\n");
		allowed = aleg ?
					p.aleg_dtmf_recv_modes&DTMF_RX_MODE_INFO :
					p.bleg_dtmf_recv_modes&DTMF_RX_MODE_INFO;
		rx_proto = DTMF_RX_MODE_INFO;
	/*} else if(dynamic_cast<AmRtpDtmfEvent *>(e)){
		DBG("RTP DTMF event\n");*/
	} else {
		DBG("received generic DTMF event\n");
		allowed = aleg ?
					p.aleg_dtmf_recv_modes&DTMF_RX_MODE_RFC2833 :
					p.bleg_dtmf_recv_modes&DTMF_RX_MODE_RFC2833;
		rx_proto = DTMF_RX_MODE_RFC2833;
	}

	if(!allowed){
		DBG("DTMF event for leg %p rejected",call);
		e->processed = true;
		//write with zero tx_proto
		with_cdr_for_read cdr->add_dtmf_event(aleg,e->event(),now,rx_proto,DTMF_TX_MODE_DISABLED);
		return StopProcessing;
	}

	//choose outgoing method
	int send_method = aleg ? p.bleg_dtmf_send_mode_id : p.aleg_dtmf_send_mode_id;
	with_cdr_for_read cdr->add_dtmf_event(aleg,e->event(),now,rx_proto,send_method);
	switch(send_method){
	case DTMF_TX_MODE_DISABLED:
		DBG("dtmf sending is disabled");
		return StopProcessing;
		break;
	case DTMF_TX_MODE_RFC2833:
		DBG("send mode RFC2833 choosen for dtmf event for leg %p",call);
		return ContinueProcessing; //nothing to do. it's default methos thus just continue processing
		break;
	case DTMF_TX_MODE_INFO_DTMF_RELAY:
		DBG("send mode INFO/application/dtmf-relay choosen for dtmf event for leg %p",call);
		call->relayEvent(new yeti_dtmf::DtmfInfoSendEventDtmfRelay(e));
		return StopProcessing;
		break;
	case DTMF_TX_MODE_INFO_DTMF:
		DBG("send mode INFO/application/dtmf choosen for dtmf event for leg %p",call);
		call->relayEvent(new yeti_dtmf::DtmfInfoSendEventDtmf(e));
		return StopProcessing;
		break;
	default:
		ERROR("unknown dtmf send method %d. stop processing",send_method);
		return StopProcessing;
	}
}

CCChainProcessing YetiCC::onRtpTimeout(SBCCallLeg *call,const AmRtpTimeoutEvent &rtp_event){
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
	unsigned int internal_code,response_code;
	string internal_reason,response_reason;

    getCtx_chained

	if(call->getCallStatus()!=CallLeg::Connected){
		WARN("%s: module catched RtpTimeout in no Connected state. ignore it",
			 call->getLocalTag().c_str());
		return StopProcessing;
	}

	CodesTranslator::instance()->translate_db_code(
		DC_RTP_TIMEOUT,
		internal_code,internal_reason,
		response_code,response_reason,
		ctx->getOverrideId());
    with_cdr_for_read {
        cdr->update_internal_reason(DisconnectByTS,internal_reason,internal_code);
        cdr->update_aleg_reason("Bye",200);
        cdr->update_bleg_reason("Bye",200);
    }
	return ContinueProcessing;
}

CCChainProcessing YetiCC::onSystemEvent(SBCCallLeg *call,AmSystemEvent* event){
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
	if (event->sys_event == AmSystemEvent::ServerShutdown) {
		onServerShutdown(call);
	}
	return ContinueProcessing;
}

CCChainProcessing YetiCC::onTimerEvent(SBCCallLeg *call,int timer_id){
	DBG("%s(%p,%d,leg%s)",FUNC_NAME,call,timer_id,call->isALeg()?"A":"B");
    getCtx_chained
    with_cdr_for_read {
        switch(timer_id){
        case YETI_CALL_DURATION_TIMER:
            cdr->update_internal_reason(DisconnectByTS,"Call duration limit reached",200);
            cdr->update_aleg_reason("Bye",200);
            cdr->update_bleg_reason("Bye",200);
            break;
        case YETI_RINGING_TIMEOUT_TIMER:
            ctx->setRingingTimeout();
            call->dlg->cancel();
            break;
        case YETI_RADIUS_INTERIM_TIMER:
            onInterimRadiusTimer(call);
            return StopProcessing;
        case YETI_FAKE_RINGING_TIMER:
            onFakeRingingTimer(call);
            return StopProcessing;
        default:
            cdr->update_internal_reason(DisconnectByTS,"Timer "+int2str(timer_id)+" fired",200);
            break;
        }
    }
	return ContinueProcessing;
}

CCChainProcessing YetiCC::onControlEvent(SBCCallLeg *call,SBCControlEvent *event){
	DBG("%s(%p,leg%s) cmd = %s, event_id = %d",FUNC_NAME,call,call->isALeg()?"A":"B",
			event->cmd.c_str(),event->event_id);
	if(event->cmd=="teardown"){
		return onTearDown(call);
	}
	return ContinueProcessing;
}

void YetiCC::onServerShutdown(SBCCallLeg *call){
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
    getCtx_void
    with_cdr_for_read {
        cdr->update_internal_reason(DisconnectByTS,"ServerShutdown",200);
    }
	//may never reach onDestroy callback so free resources here
	rctl.put(call->getCallProfile().resource_handler);
}

CCChainProcessing YetiCC::onTearDown(SBCCallLeg *call){
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
    getCtx_chained
    with_cdr_for_read {
        cdr->update_internal_reason(DisconnectByTS,"Teardown",200);
        cdr->update_aleg_reason("Bye",200);
        cdr->update_bleg_reason("Bye",200);
    }
	return ContinueProcessing;
}

void YetiCC::onB2Binitial1xx(SBCCallLeg *call, AmSipReply& reply, bool forward)
{
	if(call->isALeg()) {
		if(reply.code==100) {
			const SBCCallProfile &profile = call->getCallProfile();
			if(profile.fake_ringing_timeout)
				call->setTimer(YETI_FAKE_RINGING_TIMER,profile.fake_ringing_timeout);
			return;
		}
		getCtx_void
		ctx->ringing_sent = true;
	}
}

void YetiCC::terminateLegOnReplyException(SBCCallLeg *call,const AmSipReply& reply,const InternalException &e){
	getCtx_void
	if(!call->isALeg()){
		if(!call->getOtherId().empty()){ //ignore not connected B legs
			with_cdr_for_read {
				cdr->update_internal_reason(DisconnectByTS,e.internal_reason,e.internal_code);
				cdr->update(reply);
			}
		}
		call->relayError(reply.cseq_method,reply.cseq,true,e.response_code,e.response_reason.c_str());
		call->disconnect(false,false);
	} else {
		with_cdr_for_read {
			cdr->update_internal_reason(DisconnectByTS,e.internal_reason,e.internal_code);
			cdr->update(reply);
		}
	}
	call->stopCall(CallLeg::StatusChangeCause::InternalError);
}

CCChainProcessing YetiCC::putOnHold(SBCCallLeg *call) {
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
	return ContinueProcessing;
}

CCChainProcessing YetiCC::resumeHeld(SBCCallLeg *call, bool send_reinvite) {
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
	return ContinueProcessing;
}

CCChainProcessing YetiCC::createHoldRequest(SBCCallLeg *call, AmSdp &sdp) {
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
	return ContinueProcessing;
}

CCChainProcessing YetiCC::handleHoldReply(SBCCallLeg *call, bool succeeded) {
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
	return ContinueProcessing;
}

CCChainProcessing YetiCC::onRemoteDisappeared(SBCCallLeg *call, const AmSipReply &reply){
	const static string reinvite_failed("reINVITE failed");

	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
    getCtx_chained
	if(call->isALeg()){
		//trace available values
		if(ctx->initial_invite!=NULL){
			AmSipRequest &req = *ctx->initial_invite;
			DBG("req.method = '%s'",req.method.c_str());
		} else {
			ERROR("intial_invite == NULL");
		}
        with_cdr_for_read {
            cdr->update_internal_reason(DisconnectByTS,reply.reason,reply.code);
        }
	}
	if(call->getCallStatus()==CallLeg::Connected) {
		with_cdr_for_read {
			cdr->update_internal_reason(
				DisconnectByTS,
				reinvite_failed, 200
			);
			cdr->update_aleg_reason("Bye",200);
			cdr->update_bleg_reason("Bye",200);
		}
	}
	return ContinueProcessing;
}

CCChainProcessing YetiCC::onBye(SBCCallLeg *call, const AmSipRequest &req){
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
    getCtx_chained
    with_cdr_for_read {
        if(call->isALeg()){
            if(call->getCallStatus()!=CallLeg::Connected){
                ERROR("received Bye in not connected state");
                cdr->update_internal_reason(DisconnectByORG,"EarlyBye",500);
                cdr->update_aleg_reason("EarlyBye",200);
                cdr->update_bleg_reason("Cancel",487);
            } else {
                cdr->update_internal_reason(DisconnectByORG,"Bye",200);
                cdr->update_bleg_reason("Bye",200);
            }
        } else {
            cdr->update_internal_reason(DisconnectByDST,"Bye",200);
            cdr->update_bleg_reason("Bye",200);
        }
    }
	return ContinueProcessing;
}

CCChainProcessing YetiCC::onOtherBye(SBCCallLeg *call, const AmSipRequest &req){
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
    getCtx_chained
	if(call->isALeg()){
		if(call->getCallStatus()!=CallLeg::Connected){
			//avoid considering of bye in not connected state as succ call
			ERROR("received OtherBye in not connected state");
            with_cdr_for_write {
				cdr->update_internal_reason(DisconnectByDST,"EarlyBye",500);
				cdr->update_aleg_reason("Request terminated",487);
				cdr_list.erase(cdr);
				router.write_cdr(cdr,true);
			}
		}
	}
	return ContinueProcessing;
}

void YetiCC::onCallConnected(SBCCallLeg *call, const AmSipReply& reply){
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
	getCtx_void

	SBCCallProfile &call_profile = call->getCallProfile();
	Cdr *cdr = getCdr(ctx);

	if(call->isALeg()) cdr->update(Connect);
	else cdr->update(BlegConnect);

	radius_accounting_start(call,*cdr,call_profile);
}

void YetiCC::onCallEnded(SBCCallLeg *call){
	getCtx_void
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
	if(!call->isALeg())
		return;
	with_cdr_for_read {
		cdr->update(End);
		cdr_list.erase(cdr);
	}
}

void YetiCC::onRTPStreamDestroy(SBCCallLeg *call,AmRtpStream *stream){
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
	getCtx_void
	with_cdr_for_read {
		if(cdr->writed) return;
		cdr->lock();
		if(call->isALeg()){
			stream->getPayloadsHistory(cdr->legA_payloads);
			stream->getErrorsStats(cdr->legA_stream_errors);
			cdr->legA_bytes_recvd = stream->getRcvdBytes();
			cdr->legA_bytes_sent = stream->getSentBytes();
		} else {
			stream->getPayloadsHistory(cdr->legB_payloads);
			stream->getErrorsStats(cdr->legB_stream_errors);
			cdr->legB_bytes_recvd = stream->getRcvdBytes();
			cdr->legB_bytes_sent = stream->getSentBytes();
		}
		cdr->unlock();
	}
}

#if 0
static void copyMediaPayloads(vector<SdpMedia> &dst, const vector<SdpMedia> &src, const string &local_tag){
	if(src.empty()){
		DBG("%s: still no negotiated media. skip copy", local_tag.c_str());
		return;
	}

	if(dst.size()!=src.size()){
		ERROR("%s: received and negotiated media have different streams count", local_tag.c_str());
		return;
	}

	vector<SdpMedia>::iterator i = dst.begin();
	for (vector<SdpMedia>::const_iterator j = src.begin(); j != src.end(); ++j, ++i) {
		i->payloads = j->payloads;
		/*i->recv = j->recv;
		i->send = j->send;*/
	}
}
#endif

void YetiCC::onSdpCompleted(SBCCallLeg *call, AmSdp& offer, AmSdp& answer){
	bool aleg = call->isALeg();

	DBG("%s(%p,leg%s)",FUNC_NAME,call,aleg?"A":"B");

	getCtx_void
	/*const vector<SdpMedia> &negotiated_media = aleg ?
				ctx->aleg_negotiated_media :
				ctx->bleg_negotiated_media;*/

	//dump_SdpMedia(negotiated_media,"negotiated media");
	//dump_SdpMedia(answer.media,"answer_media");

	//fix sdp for relay mask computing
	//copyMediaPayloads(answer.media,negotiated_media,call->getLocalTag());

	const SqlCallProfile *call_profile = ctx->getCurrentProfile();
	if(call_profile) {
		cutNoAudioStreams(offer,call_profile->filter_noaudio_streams);
		cutNoAudioStreams(answer,call_profile->filter_noaudio_streams);
	}

	dump_SdpMedia(offer.media,"offer");
	dump_SdpMedia(answer.media,"answer");
}

bool YetiCC::getSdpOffer(SBCCallLeg *call, AmSdp& offer){
	DBG("%s(%p)",FUNC_NAME,this);

	CallCtx *ctx = call->getCallCtx();
	if(!ctx) {
		DBG("getSdpOffer[%s] missed call context",call->getLocalTag().c_str());
		return false;
	}

	bool a_leg = call->isALeg();

	AmB2BMedia *m = call->getMediaSession();
	if(!m){
		DBG("getSdpOffer[%s] missed media session",call->getLocalTag().c_str());
		return false;
	}
	if(!m->haveLocalSdp(a_leg)){
		DBG("getSdpOffer[%s] have no local sdp",call->getLocalTag().c_str());
		return false;
	}

	const AmSdp &local_sdp = m->getLocalSdp(a_leg);
	if(a_leg){
		DBG("use last offer from dialog as offer for legA");
		offer = local_sdp;
	} else {
		DBG("provide saved initial offer for legB");
		offer = ctx->bleg_initial_offer;
		m->replaceConnectionAddress(offer,a_leg, call->localMediaIP(), call->advertisedIP());
	}
	offer.origin.sessV = local_sdp.origin.sessV+1; //increase session version. rfc4566 5.2 <sess-version>
	return true;
}

int YetiCC::relayEvent(SBCCallLeg *call, AmEvent *e){
	DBG("%s(%p,leg%s)",FUNC_NAME,call,call->isALeg()?"A":"B");
	CallCtx *ctx = call->getCallCtx();
	if(NULL==ctx) {
		ERROR("Yeti::relayEvent(%p) zero ctx. ignore event",call);
		delete e;
		return -1;
	}

	bool a_leg = call->isALeg();
	AmOfferAnswer::OAState dlg_oa_state = call->dlg->getOAState();

	switch (e->event_id) {
		case B2BSipRequest: {
			B2BSipRequestEvent* req_ev = dynamic_cast<B2BSipRequestEvent*>(e);
			assert(req_ev);

			DBG("Yeti::relayEvent(%p) filtering request '%s' (c/t '%s') oa_state = %d\n",
				call,req_ev->req.method.c_str(), req_ev->req.body.getCTStr().c_str(),
				dlg_oa_state);

			SBCCallProfile &call_profile = call->getCallProfile();
			AmSipRequest &req = req_ev->req;
			try {
				int res;
				if(req.method==SIP_METH_ACK){
					//ACK can contain only answer
					dump_SdpMedia(ctx->bleg_negotiated_media,"bleg_negotiated media_pre");
					dump_SdpMedia(ctx->aleg_negotiated_media,"aleg_negotiated media_pre");

					res = processSdpAnswer(
						call,
						req.body, req.method,
						ctx->get_other_negotiated_media(a_leg),
						a_leg ? call_profile.bleg_single_codec : call_profile.aleg_single_codec,
						call_profile.filter_noaudio_streams,
						//ACK request MUST contain SDP answer if we sent offer in reply
						dlg_oa_state==AmOfferAnswer::OA_OfferSent
					);

					dump_SdpMedia(ctx->bleg_negotiated_media,"bleg_negotiated media_post");
					dump_SdpMedia(ctx->aleg_negotiated_media,"aleg_negotiated media_post");

				} else {
					res = processSdpOffer(
						call_profile,
						req.body, req.method,
						ctx->get_self_negotiated_media(a_leg),
						a_leg ? call_profile.static_codecs_aleg_id : call_profile.static_codecs_bleg_id
					);
					if(res>=0){
						res = filterSdpOffer(
							call,
							call_profile,
							req.body, req.method,
							a_leg ? call_profile.static_codecs_bleg_id : call_profile.static_codecs_aleg_id
						);
					}
				}
				if (res < 0) {
					delete e;
					return res;
				}
			} catch(InternalException &exception){
				DBG("got internal exception %d on request processing",exception.icode);
				delete e;
				return -448;
			}
		} break;

		case B2BSipReply: {
			B2BSipReplyEvent* reply_ev = dynamic_cast<B2BSipReplyEvent*>(e);
			assert(reply_ev);

			DBG("Yeti::relayEvent(%p) filtering body for reply %d cseq.method '%s' (c/t '%s') oa_state = %d\n",
				call,reply_ev->reply.code,reply_ev->trans_method.c_str(), reply_ev->reply.body.getCTStr().c_str(),
				call->dlg->getOAState());

			SBCCallProfile &call_profile = call->getCallProfile();

			//append headers for 200 OK replyin direction B -> A
			AmSipReply &reply = reply_ev->reply;

			inplaceHeaderPatternFilter(
				reply.hdrs,
				a_leg ? call_profile.headerfilter_a2b : call_profile.headerfilter_b2a
			);

			if(!a_leg){
				if(	reply.code==200
					&& !call_profile.aleg_append_headers_reply.empty())
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
					return 0;
				}
			}

			try {
				int res;
				if(dlg_oa_state==AmOfferAnswer::OA_OfferRecved){
					DBG("relayEvent(): process offer in reply");
					res = processSdpOffer(
						call_profile,
						reply.body, reply.cseq_method,
						ctx->get_self_negotiated_media(a_leg),
						a_leg ? call_profile.static_codecs_aleg_id : call_profile.static_codecs_bleg_id,
						false,
						a_leg ? call_profile.aleg_single_codec : call_profile.bleg_single_codec
					);
					if(res>=0){
						res = filterSdpOffer(
							call,
							call_profile,
							reply.body, reply.cseq_method,
							a_leg ? call_profile.static_codecs_bleg_id : call_profile.static_codecs_aleg_id
						);
					}
				} else {
					DBG("relayEvent(): process asnwer in reply");
					res = processSdpAnswer(
						call,
						reply.body, reply.cseq_method,
						ctx->get_other_negotiated_media(a_leg),
						a_leg ? call_profile.bleg_single_codec : call_profile.aleg_single_codec,
						call_profile.filter_noaudio_streams,
						//final positive reply MUST contain SDP answer if we sent offer
						(dlg_oa_state==AmOfferAnswer::OA_OfferSent
							&& reply.code >= 200 && reply.code < 300)
					);
				}

				if(res<0){
					terminateLegOnReplyException(call,reply,InternalException(DC_REPLY_SDP_GENERIC_EXCEPTION));
					delete e;
					return -488;
				}
			} catch(InternalException &exception){
				DBG("got internal exception %d on reply processing",exception.icode);
				terminateLegOnReplyException(call,reply,exception);
				delete e;
				return -488;
			}
		} break;
		case B2BDtmfEvent:
			//
			break;
	} //switch(e->event_id)
	return 0;
}

/****************************************
 *				aux funcs				*
 ****************************************/

bool YetiCC::connectCallee(CallCtx *call_ctx,SBCCallLeg *call,const AmSipRequest &orig_req){

	SBCCallProfile &call_profile = call->getCallProfile();
	ParamReplacerCtx ctx(&call_profile);
	ctx.app_param = getHeader(orig_req.hdrs, PARAM_HDR, true);

	AmSipRequest uac_req(orig_req);
	AmUriParser uac_ruri;

	uac_ruri.uri = uac_req.r_uri;
	if(!uac_ruri.parse_uri()) {
		DBG("Error parsing R-URI '%s'\n",uac_ruri.uri.c_str());
		throw AmSession::Exception(400,"Failed to parse R-URI");
	}

	call_profile.sst_aleg_enabled = ctx.replaceParameters(
		call_profile.sst_aleg_enabled,
		"enable_aleg_session_timer",
		orig_req
	);

	call_profile.sst_enabled = ctx.replaceParameters(
		call_profile.sst_enabled,
		"enable_session_timer", orig_req
	);

	if ((call_profile.sst_aleg_enabled == "yes") ||
		(call_profile.sst_enabled == "yes"))
	{
		call_profile.eval_sst_config(ctx,orig_req,call_profile.sst_a_cfg);
		if(call->applySSTCfg(call_profile.sst_a_cfg,&orig_req) < 0) {
			throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
		}
	}


	if (!call_profile.evaluate(ctx, orig_req)) {
		ERROR("call profile evaluation failed\n");
		throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
	}
	if(!call_profile.append_headers.empty()){
		replace(call_profile.append_headers,"%global_tag",call->getGlobalTag());
	}

	if(call_profile.contact_hiding) {
		if(RegisterDialog::decodeUsername(orig_req.user,uac_ruri)) {
			uac_req.r_uri = uac_ruri.uri_str();
		}
	} else if(call_profile.reg_caching) {
		// REG-Cache lookup
		uac_req.r_uri = call_profile.retarget(orig_req.user,*call->dlg);
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
	from = call_profile.from.empty() ? orig_req.from : call_profile.from;
	to = call_profile.to.empty() ? orig_req.to : call_profile.to;

	call->applyAProfile();
	call_profile.apply_a_routing(ctx,orig_req,*call->dlg);

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

	int res = filterSdpOffer(call,
							   call_profile,
							   invite_req.body,invite_req.method,
							   call_profile.static_codecs_bleg_id,
							   &call_ctx->bleg_initial_offer);
	if(res < 0){
		INFO("onInitialInvite() Not acceptable codecs for legB");
		throw AmSession::Exception(488, SIP_REPLY_NOT_ACCEPTABLE_HERE);
	}

	call->connectCallee(to, ruri, from, orig_req, invite_req);

	return false;
}

bool YetiCC::chooseNextProfile(SBCCallLeg *call){
	DBG("%s()",FUNC_NAME);

	string refuse_reason;
	int refuse_code;
	CallCtx *ctx;
	Cdr *cdr;
	SqlCallProfile *profile = NULL;
	ResourceCtlResponse rctl_ret;
	ResourceList::iterator ri;
	bool has_profile = false;

	ctx = call->getCallCtx();
	cdr = getCdr(ctx);

	profile = ctx->getNextProfile(false);

	if(NULL==profile){
		//pretend that nothing happen. we were never called
		DBG("%s() no more profiles or refuse profile on serial fork. ignore it",FUNC_NAME);
		return false;
	}

	//write cdr and replace ctx pointer with new
	cdr_list.erase(cdr);
	router.write_cdr(cdr,false);
	cdr = getCdr(ctx);

	do {
		DBG("%s() choosed next profile. check it for refuse",FUNC_NAME);

		ParamReplacerCtx rctx(profile);
		if(check_and_refuse(profile,cdr,*ctx->initial_invite,rctx)){
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
								call->getLocalTag(),
								refuse_code,refuse_reason,ri);
		}

		if(rctl_ret == RES_CTL_OK){
			DBG("%s() check resources  successed",FUNC_NAME);
			has_profile = true;
			break;
		} else {
			DBG("%s() check resources failed with code: %d, reply: <%d '%s'>",FUNC_NAME,
				rctl_ret,refuse_code,refuse_reason.c_str());
			if(rctl_ret ==  RES_CTL_ERROR) {
				break;
			} else if(rctl_ret ==  RES_CTL_REJECT) {
				cdr->update_failed_resource(*ri);
				break;
			} else if(	rctl_ret == RES_CTL_NEXT){
				profile = ctx->getNextProfile(false,true);
				if(NULL==profile){
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

	if(!has_profile){
		cdr->update_internal_reason(DisconnectByTS,refuse_reason,refuse_code);
		return false;
	} else {
		DBG("%s() update call profile for legA",FUNC_NAME);
		cdr->update(profile->rl);
		call->updateCallProfile(*profile);
		return true;
	}
}

bool YetiCC::check_and_refuse(SqlCallProfile *profile,Cdr *cdr,
							const AmSipRequest& req,ParamReplacerCtx& ctx,
							bool send_reply){
	bool need_reply;
	bool write_cdr;
	unsigned int internal_code,response_code;
	string internal_reason,response_reason;

	if(profile->disconnect_code_id==0)
		return false;

	write_cdr = CodesTranslator::instance()->translate_db_code(profile->disconnect_code_id,
							 internal_code,internal_reason,
							 response_code,response_reason,
							 profile->aleg_override_id);
	need_reply = (response_code!=NO_REPLY_DISCONNECT_CODE);

	if(write_cdr){
		cdr->update_internal_reason(DisconnectByDB,internal_reason,internal_code);
		cdr->update_aleg_reason(response_reason,response_code);
	} else {
		cdr->setSuppress(true);
	}
	if(send_reply && need_reply){
		if(write_cdr){
			cdr->update(req);
			cdr->update_sbc(*profile);
		}
		//prepare & send sip response
		string hdrs = ctx.replaceParameters(profile->append_headers, "append_headers", req);
		if (hdrs.size()>2)
			assertEndCRLF(hdrs);
		AmSipDialog::reply_error(req, response_code, response_reason, hdrs);
	}
	return true;
}

void YetiCC::onRadiusReply(SBCCallLeg *call, const RadiusReplyEvent &ev)
{
	DBG("got radius reply for %s",call->getLocalTag().c_str());
	getCtx_void
	try {
		switch(ev.result){
		case RadiusReplyEvent::Accepted:
			onRoutingReady(call,call->getAlegModifiedReq(),call->getModifiedReq());
			break;
		case RadiusReplyEvent::Rejected:
			throw InternalException(RADIUS_RESPONSE_REJECT);
			break;
		case RadiusReplyEvent::Error:
			if(ev.reject_on_error){
				DBG("radius error. reject");
				throw InternalException(ev.error_code);
			} else {
				DBG("radius error, but radius profile configured to ignore errors.");
				onRoutingReady(call,call->getAlegModifiedReq(),call->getModifiedReq());
			}
			break;
		}
	} catch(AmSession::Exception &e) {
		call->onEarlyEventException(e.code,e.reason);
	} catch(InternalException &e){
		call->onEarlyEventException(e.response_code,e.response_reason);
	}
}

void YetiCC::onInterimRadiusTimer(SBCCallLeg *call)
{
	DBG("interim accounting timer fired for %s",call->getLocalTag().c_str());
	getCtx_void
	with_cdr_for_read {
		radius_accounting_interim(call,*cdr);
	}
}

void YetiCC::onFakeRingingTimer(SBCCallLeg *call)
{
	DBG("fake ringing timer fired for %s",call->getLocalTag().c_str());
	getCtx_void
	if(!ctx->ringing_sent) {
		call->dlg->reply(*ctx->initial_invite,180,SIP_REPLY_RINGING);
		ctx->ringing_sent = true;
	}
}
