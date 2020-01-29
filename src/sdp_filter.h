#ifndef SDP_FILTER_H
#define SDP_FILTER_H

#include <string>
using std::string;
#include <vector>
using std::vector;

#include <AmSdp.h>
#include "SBCCallLeg.h"
#include "CallCtx.h"

#define DTMF_ENCODING_NAME "TELEPHONE-EVENT"

int AmMimeBody2Sdp(const AmMimeBody &body,AmSdp &sdp);

void dump_SdpPayload(const vector<SdpPayload> &p,string prefix="");
void dump_SdpMedia(const vector<SdpMedia> &m,string prefix="");

void fix_dynamic_payloads(AmSdp &sdp,PayloadIdMapping &mapping);

enum conn_location {
	BOTH = 0,
	SESSION_ONLY,
	MEDIA_ONLY
};
const char *conn_location2str(int location_id);
void normalize_conn_location(AmSdp &sdp, int location_id);

int filterNoAudioStreams(AmSdp &sdp, bool filter);
int cutNoAudioStreams(AmSdp &sdp, bool cut);

int filter_arrange_SDP(
		AmSdp& sdp,
		const std::vector<SdpPayload> &static_payloads,
		bool add_codecs);

int processSdpOffer(
		SBCCallProfile &call_profile,
		AmMimeBody &body, string &method,
		vector<SdpMedia> &negotiated_media,
		int static_codecs_id,
		bool local = false,
		bool single_codec = false);

int filterSdpOffer(
		SBCCallLeg *call,
		_AmSipMsgInDlg &sip_msg,
		SBCCallProfile &call_profile,
		AmMimeBody &body,
		string &method,
		int static_codecs_id,
		AmSdp *out_sdp = NULL);

int processSdpAnswer(
		SBCCallLeg *call,
		_AmSipMsgInDlg &sip_msg,
		AmMimeBody &body,
		const string &method,
		vector<SdpMedia> &negotiated_media,
		bool single_codec,
		bool noaudio_streams_filtered,
		bool answer_is_mandatory);

#endif // SDP_FILTER_H
