#include "SqlCallProfile.h"
#include "AmUtils.h"
#include "SBC.h"
#include "yeti.h"
#include <algorithm>
#include "RTPParameters.h"
#include "sdp_filter.h"
#include "sip/parse_via.h"

SqlCallProfile::SqlCallProfile():
	aleg_override_id(0),
	bleg_override_id(0)
{
	rtprelay_transparent_seqno = true;
	rtprelay_transparent_ssrc = true;
}

SqlCallProfile::~SqlCallProfile(){ }

bool SqlCallProfile::skip(const pqxx::result::tuple &t){
	try {
		if(t["ruri"].is_null()){
			DBG("callprofile skip condition matched: row 'ruri' field is NULL");
			return true;
		}
	} catch(...) {
		DBG("callprofile skip condition matched: row has no 'ruri' field");
		return true;
	}
	return false;
}

bool SqlCallProfile::readFromTuple(const pqxx::result::tuple &t,const DynFieldsT &df){
	profile_file = "SQL";

	for(pqxx::result::tuple::const_iterator it = t.begin();
		it!=t.end();++it)
	{
		const pqxx::result::field &f = *it;
		placeholders_hash[f.name()] = f.c_str();
	}

	assign_str(ruri,"ruri");
	assign_str(from,"from");
	assign_str(to,"to");

	assign_str(callid,"call_id");

	assign_bool(transparent_dlg_id,"transparent_dlg_id",false);
	assign_bool(dlg_nat_handling,"dlg_nat_handling",false);

	assign_bool(force_outbound_proxy,"force_outbound_proxy",false);
	assign_str(outbound_proxy,"outbound_proxy");

	assign_bool(aleg_force_outbound_proxy,"aleg_force_outbound_proxy",false);
	assign_str(aleg_outbound_proxy,"aleg_outbound_proxy");

	assign_str(next_hop,"next_hop");
	assign_bool(next_hop_1st_req,"next_hop_1st_req",false);
	assign_bool_safe(patch_ruri_next_hop,"patch_ruri_next_hop",false,false);

	assign_str(aleg_next_hop,"aleg_next_hop");

	if(!readFilterSet(t,"transit_headers_a2b",headerfilter_a2b))
		return false;

	if(!readFilterSet(t,"transit_headers_b2a",headerfilter_b2a))
		return false;

	if (!readFilter(t, "message_filter", messagefilter, false))
		return false;

	if (!readFilter(t, "sdp_filter", sdpfilter, true))
		return false;

	assign_bool(anonymize_sdp,"anonymize_sdp",true);
	//DBG("db: %s, anonymize_sdp = %d",t["anonymize_sdp"].c_str(),anonymize_sdp);

	// SDP alines filter
	if (!readFilter(t, "sdp_alines_filter", sdpalinesfilter, false))
		return false;

	if (!readFilter(t, "bleg_sdp_alines_filter", bleg_sdpalinesfilter, false, FILTER_TYPE_WHITELIST))
		return false;

	assign_bool_str(sst_enabled,"enable_session_timer",false);
	if(column_exist(t,"enable_aleg_session_timer")) {
		assign_bool_str(sst_aleg_enabled,"enable_aleg_session_timer",false);
	} else {
		sst_aleg_enabled = sst_enabled;
	}

#define CP_SST_CFGVAR(cfgprefix, cfgkey, dstcfg)			\
	if (column_exist(t,cfgprefix cfgkey)) {				\
	dstcfg.setParameter(cfgkey, t[cfgprefix cfgkey].c_str());	\
	} else if (column_exist(t,cfgkey)) {				\
		dstcfg.setParameter(cfgkey, t[cfgkey].c_str());		\
	} else if (SBCFactory::instance()->cfg.hasParameter(cfgkey)) {	\
	  dstcfg.setParameter(cfgkey, SBCFactory::instance()->		\
			  cfg.getParameter(cfgkey));			\
	}
#define	CP_SESSION_REFRESH_METHOD(prefix,method_id,dstcfg)\
	switch(method_id){\
		case REFRESH_METHOD_INVITE:\
			dstcfg.setParameter(prefix "session_refresh_method",\
				"INVITE");\
			break;\
		case REFRESH_METHOD_UPDATE:\
			dstcfg.setParameter(prefix "session_refresh_method",\
				"UPDATE");\
			break;\
		case REFRESH_METHOD_UPDATE_FALLBACK_INVITE:\
			dstcfg.setParameter(prefix "session_refresh_method",\
				"UPDATE_FALLBACK_INVITE");\
			break;\
		default:\
			ERROR("unknown session_refresh_method id '%d'",method_id);\
			return false;\
	}

	if (sst_enabled.size() && sst_enabled != "no") {
		if (NULL == SBCFactory::instance()->session_timer_fact) {
			ERROR("session_timer module not loaded thus SST not supported, but required");
			return false;
		}
		sst_b_cfg.setParameter("enable_session_timer", "yes");
		// create sst_cfg with values from aleg_*
		CP_SST_CFGVAR("", "session_expires", sst_b_cfg);
		CP_SST_CFGVAR("", "minimum_timer", sst_b_cfg);
		CP_SST_CFGVAR("", "maximum_timer", sst_b_cfg);
		//CP_SST_CFGVAR("", "session_refresh_method", sst_b_cfg);
		CP_SST_CFGVAR("", "accept_501_reply", sst_b_cfg);
		assign_int(session_refresh_method_id,"session_refresh_method_id",1);
		CP_SESSION_REFRESH_METHOD("",session_refresh_method_id,sst_b_cfg);
	}

	if (sst_aleg_enabled.size() && sst_aleg_enabled != "no") {
		sst_a_cfg.setParameter("enable_session_timer", "yes");
		// create sst_a_cfg superimposing values from aleg_*
		CP_SST_CFGVAR("aleg_", "session_expires", sst_a_cfg);
		CP_SST_CFGVAR("aleg_", "minimum_timer", sst_a_cfg);
		CP_SST_CFGVAR("aleg_", "maximum_timer", sst_a_cfg);
		//CP_SST_CFGVAR("aleg_", "session_refresh_method", sst_a_cfg);
		CP_SST_CFGVAR("aleg_", "accept_501_reply", sst_a_cfg);
		assign_int(aleg_session_refresh_method_id,"aleg_session_refresh_method_id",1);
		CP_SESSION_REFRESH_METHOD("aleg_",aleg_session_refresh_method_id,sst_a_cfg);
	}
#undef CP_SST_CFGVAR
#undef CP_SESSION_REFRESH_METHOD

	assign_bool(auth_enabled,"enable_auth",false);
	assign_str(auth_credentials.user,"auth_user");
	assign_str(auth_credentials.pwd,"auth_pwd");

	assign_bool(auth_aleg_enabled,"enable_aleg_auth",false);
	assign_str(auth_aleg_credentials.user,"auth_aleg_user");
	assign_str(auth_aleg_credentials.pwd,"auth_aleg_pwd");


	vector<string> reply_translations_v =
			explode(t["reply_translations"].c_str(), "|");
	for (vector<string>::iterator it =
			reply_translations_v.begin(); it != reply_translations_v.end(); it++) {
		// expected: "603=>488 Not acceptable here"
		vector<string> trans_components = explode(*it, "=>");
		if (trans_components.size() != 2) {
			ERROR("entry '%s' in reply_translations could not be understood.\n", it->c_str());
			ERROR("expected 'from_code=>to_code reason'\n");
			return false;
		}

		unsigned int from_code, to_code;
		if (str2i(trans_components[0], from_code)) {
			ERROR("code '%s' in reply_translations not understood.\n", trans_components[0].c_str());
			return false;
		}
		unsigned int s_pos = 0;
		string to_reply = trans_components[1];
		while (s_pos < to_reply.length() && to_reply[s_pos] != ' ')
		s_pos++;
		if (str2i(to_reply.substr(0, s_pos), to_code)) {
			ERROR("code '%s' in reply_translations not understood.\n", to_reply.substr(0, s_pos).c_str());
			return false;
		}
		if (s_pos < to_reply.length())
			s_pos++;
		// DBG("got translation %u => %u %s\n",
		// 	from_code, to_code, to_reply.substr(s_pos).c_str());
		reply_translations[from_code] = make_pair(to_code, to_reply.substr(s_pos));
	}

	assign_str(append_headers,"append_headers");
	assign_str(append_headers_req,"append_headers_req");
	assign_str(aleg_append_headers_req,"aleg_append_headers_req");
	assign_str_safe(aleg_append_headers_reply,"aleg_append_headers_reply","");

	assign_bool(rtprelay_enabled,"enable_rtprelay",false);
	assign_bool_str_safe(force_symmetric_rtp,"bleg_force_symmetric_rtp",false,false);
	assign_bool_str_safe(aleg_force_symmetric_rtp,"aleg_force_symmetric_rtp",false,false);
	assign_bool(msgflags_symmetric_rtp,"rtprelay_msgflags_symmetric_rtp",false);

	assign_str(rtprelay_interface,"rtprelay_interface");
	assign_str(aleg_rtprelay_interface,"aleg_rtprelay_interface");

	assign_bool(rtprelay_transparent_seqno,"rtprelay_transparent_seqno",false);
	assign_bool(rtprelay_transparent_ssrc,"rtprelay_transparent_ssrc",false);

	assign_str(outbound_interface,"outbound_interface");
	assign_str(aleg_outbound_interface,"aleg_outbound_interface");

	assign_str(contact.displayname,"contact_displayname");
	assign_str(contact.user,"contact_user");
	assign_str(contact.host,"contact_host");
	assign_str(contact.port,"contact_port");

	assign_bool(contact.hiding,"enable_contact_hiding",false);
	assign_str(contact.hiding_prefix,"contact_hiding_prefix");
	assign_str(contact.hiding_vars,"contact_hiding_vars");

	if (!readCodecPrefs(t)) return false;
	if (!readTranscoder(t)) return false;
	if(!readDynFields(t,df)) return false;

	assign_int(dump_level_id,"dump_level_id",0);
	dump_level_id |= AmConfig::DumpLevel;
	log_rtp = dump_level_id&LOG_RTP_MASK;
	log_sip = dump_level_id&LOG_SIP_MASK;

	assign_bool(reg_caching,"enable_reg_caching",false);
	assign_int(min_reg_expires,"min_reg_expires",0);
	assign_int(max_ua_expires,"max_ua_expires",0);
	assign_int(time_limit,"time_limit",0);
	assign_str(resources,"resources");

	assign_int(disconnect_code_id,"disconnect_code_id",0);

	assign_int(aleg_override_id,"aleg_policy_id",0);
	assign_int(bleg_override_id,"bleg_policy_id",0);

	assign_int_safe(ringing_timeout,"ringing_timeout",0,0);

	assign_str_safe(global_tag,"global_tag","");

	assign_bool_safe(rtprelay_dtmf_filtering,"rtprelay_dtmf_filtering",false,false);
	assign_bool_safe(rtprelay_dtmf_detection,"rtprelay_dtmf_detection",false,false);
	assign_bool_safe(rtprelay_force_dtmf_relay,"rtprelay_force_dtmf_relay",true,true);

	assign_bool_safe(aleg_symmetric_rtp_ignore_rtcp,"aleg_symmetric_rtp_ignore_rtcp",false,false);
	assign_bool_safe(bleg_symmetric_rtp_ignore_rtcp,"bleg_symmetric_rtp_ignore_rtcp",false,false);
	assign_bool_safe(aleg_symmetric_rtp_nonstop,"aleg_symmetric_rtp_nonstop",false,false);
	assign_bool_safe(bleg_symmetric_rtp_nonstop,"bleg_symmetric_rtp_nonstop",false,false);

	assign_bool_safe(aleg_relay_options,"aleg_relay_options",false,false);
	assign_bool_safe(bleg_relay_options,"bleg_relay_options",false,false);

	assign_bool_safe(aleg_relay_update,"aleg_relay_update",true,true);
	assign_bool_safe(bleg_relay_update,"bleg_relay_update",true,true);

	assign_bool_safe(filter_noaudio_streams,"filter_noaudio_streams",true,true);

	assign_bool_safe(aleg_rtp_ping,"aleg_rtp_ping",false,false);
	assign_bool_safe(bleg_rtp_ping,"bleg_rtp_ping",false,false);

	assign_int_safe(aleg_conn_location_id,"aleg_sdp_c_location_id",0,0);
	assign_int_safe(bleg_conn_location_id,"bleg_sdp_c_location_id",0,0);

	assign_int_safe(dead_rtp_time,"dead_rtp_time",AmConfig::DeadRtpTime,AmConfig::DeadRtpTime);

	assign_bool_safe(aleg_relay_reinvite,"aleg_relay_reinvite",true,true);
	assign_bool_safe(bleg_relay_reinvite,"bleg_relay_reinvite",true,true);
	/*assign_bool_safe(aleg_relay_prack,"aleg_relay_prack",true,true);
	assign_bool_safe(bleg_relay_prack,"bleg_relay_prack",true,true);*/
	assign_bool_safe(aleg_relay_hold,"aleg_relay_hold",true,true);
	assign_bool_safe(bleg_relay_hold,"bleg_relay_hold",true,true);

	assign_bool_safe(relay_timestamp_aligning,"rtp_relay_timestamp_aligning",false,false);

	assign_bool_safe(trusted_hdrs_gw,"trusted_hdrs_gw",false,false);

	assign_bool_safe(allow_1xx_without_to_tag,"allow_1xx_wo2tag",false,false);

	assign_type_safe(inv_transaction_timeout,"invite_timeout",0,unsigned int,0);
	assign_type_safe(inv_srv_failover_timeout,"srv_failover_timeout",0,unsigned int,0);

	assign_bool_safe(force_relay_CN,"rtp_force_relay_cn",false,false);

	assign_int_safe(aleg_sensor_id,"aleg_sensor_id",-1,-1);
	assign_int_safe(bleg_sensor_id,"bleg_sensor_id",-1,-1);
	assign_int_safe(aleg_sensor_level_id,"aleg_sensor_level_id",0,0);
	assign_int_safe(bleg_sensor_level_id,"bleg_sensor_level_id",0,0);

	assign_int_safe(aleg_dtmf_send_mode_id,"aleg_dtmf_send_mode_id",DTMF_TX_MODE_RFC2833,DTMF_TX_MODE_RFC2833);
	assign_int_safe(bleg_dtmf_send_mode_id,"bleg_dtmf_send_mode_id",DTMF_TX_MODE_RFC2833,DTMF_TX_MODE_RFC2833);
	assign_int_safe(aleg_dtmf_recv_modes,"aleg_dtmf_recv_modes",DTMF_RX_MODE_ALL,DTMF_RX_MODE_ALL);
	assign_int_safe(bleg_dtmf_recv_modes,"bleg_dtmf_recv_modes",DTMF_RX_MODE_ALL,DTMF_RX_MODE_ALL);

	assign_bool_safe(suppress_early_media,"suppress_early_media",false,false);
	assign_bool_safe(force_one_way_early_media,"force_one_way_early_media",false,false);
	assign_int_safe_silent(fake_ringing_timeout,"fake_180_timer",0,0);

	assign_int_safe_silent(aleg_rel100_mode_id,"aleg_rel100_mode_id",-1,-1);
	assign_int_safe_silent(bleg_rel100_mode_id,"bleg_rel100_mode_id",-1,-1);

	assign_int_safe_silent(radius_profile_id,"radius_auth_profile_id",0,0);
	assign_int_safe_silent(aleg_radius_acc_profile_id,"aleg_radius_acc_profile_id",0,0);
	assign_int_safe_silent(bleg_radius_acc_profile_id,"bleg_radius_acc_profile_id",0,0);

	assign_bool_safe_silent(record_audio,"record_audio",false,false);

	assign_int_safe_silent(bleg_transport_id,"bleg_transport_protocol_id",0,0);
	assign_int_safe_silent(outbound_proxy_transport_id,"bleg_outbound_proxy_transport_protocol_id",0,0);
	assign_int_safe_silent(aleg_outbound_proxy_transport_id,"aleg_outbound_proxy_transport_protocol_id",0,0);

	assign_int_safe_silent(bleg_max_30x_redirects,"bleg_max_30x_redirects",0,0);
	assign_int_safe_silent(bleg_max_transfers, "bleg_max_transfers",0,0);

	DBG("Yeti: loaded SQL profile\n");

	return true;
}

inline void printFilterList(const char *name, const vector<FilterEntry>& filter_list)
{
	int i = 0;
	for (vector<FilterEntry>::const_iterator fe =
		 filter_list.begin(); fe != filter_list.end(); fe++, i++)
	{
		DBG("%s[%d]: %zd items in list",name,i,fe->filter_list.size());
	}
}

void SqlCallProfile::infoPrint(const DynFieldsT &df){
	if(disconnect_code_id!=0) {
		DBG("refusing calls with code '%d'\n", disconnect_code_id);
	/*} else if (!refuse_with.empty()) {
		DBG("refusing calls with '%s'\n", refuse_with.c_str());
		*/
	} else {
		DBG("RURI      = '%s'\n", ruri.c_str());
		DBG("RURI transport id = %d",bleg_transport_id);
		DBG("From = '%s'\n", from.c_str());
		DBG("To   = '%s'\n", to.c_str());
		// if (!contact.empty()) {
		//   DBG("Contact   = '%s'\n", contact.c_str());
		// }
		if (!callid.empty()) {
			DBG("Call-ID   = '%s'\n", callid.c_str());
		}

		DBG("force outbound proxy: %s\n", force_outbound_proxy?"yes":"no");
		DBG("outbound proxy = '%s'\n", outbound_proxy.c_str());
		DBG("outbound proxy transport id = %d\n", outbound_proxy_transport_id);

		if (!outbound_interface.empty()) {
			DBG("outbound interface = '%s'\n", outbound_interface.c_str());
		}

		if (!aleg_outbound_interface.empty()) {
			DBG("A leg outbound interface = '%s'\n", aleg_outbound_interface.c_str());
		}

		DBG("A leg force outbound proxy: %s\n", aleg_force_outbound_proxy?"yes":"no");
		DBG("A leg outbound proxy = '%s'\n", aleg_outbound_proxy.c_str());
		DBG("A leg outbound transport id = %d\n", aleg_outbound_proxy_transport_id);

		if (!next_hop.empty()) {
			DBG("next hop = %s (%s)\n", next_hop.c_str(),
			next_hop_1st_req ? "1st req" : "all reqs");
		}

		if (!aleg_next_hop.empty()) {
			DBG("A leg next hop = %s\n", aleg_next_hop.c_str());
		}

		printFilterList("transit_headers_a2b", headerfilter_a2b);
		printFilterList("transit_headers_b2a", headerfilter_b2a);

		string filter_type; size_t filter_elems;
		filter_type = messagefilter.size() ? FilterType2String(messagefilter.back().filter_type) : "disabled";
		filter_elems = messagefilter.size() ? messagefilter.back().filter_list.size() : 0;
		DBG("message filter is %s, %zd items in list\n", filter_type.c_str(), filter_elems);

		filter_type = sdpfilter.size() ? FilterType2String(sdpfilter.back().filter_type) : "disabled";
		filter_elems = sdpfilter.size() ? sdpfilter.back().filter_list.size() : 0;
		DBG("SDP filter is %sabled, %s, %zd items in list, %sanonymizing SDP\n",
		sdpfilter.size()?"en":"dis", filter_type.c_str(), filter_elems, anonymize_sdp?"":"not ");

		filter_type = sdpalinesfilter.size() ? FilterType2String(sdpalinesfilter.back().filter_type) : "disabled";
		filter_elems = sdpalinesfilter.size() ? sdpalinesfilter.back().filter_list.size() : 0;
		DBG("SDP alines-filter is %sabled, %s, %zd items in list\n", sdpalinesfilter.size()?"en":"dis", filter_type.c_str(), filter_elems);

		filter_type = bleg_sdpalinesfilter.size() ? FilterType2String(bleg_sdpalinesfilter.back().filter_type) : "disabled";
		filter_elems = bleg_sdpalinesfilter.size() ? bleg_sdpalinesfilter.back().filter_list.size() : 0;
		DBG("SDP Bleg alines-filter is %sabled, %s, %zd items in list\n", bleg_sdpalinesfilter.size()?"en":"dis", filter_type.c_str(), filter_elems);

		DBG("RTP relay %sabled\n", rtprelay_enabled?"en":"dis");
		if (rtprelay_enabled) {
			if (!force_symmetric_rtp.empty()) {
				DBG("RTP force symmetric RTP: %s\n",
				force_symmetric_rtp.c_str());
			}
			if (msgflags_symmetric_rtp) {
				DBG("P-MsgFlags symmetric RTP detection enabled\n");
			}
			if (!aleg_rtprelay_interface.empty()) {
				DBG("RTP Relay interface A leg '%s'\n", aleg_rtprelay_interface.c_str());
			}
			if (!rtprelay_interface.empty()) {
				DBG("RTP Relay interface B leg '%s'\n", rtprelay_interface.c_str());
			}

			DBG("RTP Relay RTP DTMF filtering %sabled\n",
				rtprelay_dtmf_filtering?"en":"dis");
			DBG("RTP Relay RTP DTMF detection %sabled\n",
				rtprelay_dtmf_detection?"en":"dis");
			DBG("RTP Relay RTP DTMF force relay %sabled\n",
				rtprelay_force_dtmf_relay?"en":"dis");
			DBG("RTP Relay Aleg symmetric RTP ignore RTCP %sabled\n",
				aleg_symmetric_rtp_ignore_rtcp?"en":"dis");
			DBG("RTP Relay Bleg symmetric RTP ignore RTCP %sabled\n",
				bleg_symmetric_rtp_ignore_rtcp?"en":"dis");
			DBG("RTP Relay Aleg nonstop symmetric RTP %sabled\n",
				aleg_symmetric_rtp_nonstop?"en":"dis");
			DBG("RTP Relay Bleg nonstop symmetric RTP %sabled\n",
				bleg_symmetric_rtp_nonstop?"en":"dis");
			DBG("RTP Relay %s seqno\n",
			rtprelay_transparent_seqno?"transparent":"opaque");
			DBG("RTP Relay %s SSRC\n",
			rtprelay_transparent_ssrc?"transparent":"opaque");
			DBG("RTP Relay timestamp aligning %sabled\n",
			relay_timestamp_aligning?"en":"dis");
		}

		DBG("RTP Ping Aleg %sabled\n", aleg_rtp_ping?"en":"dis");
		DBG("RTP Ping Bleg %sabled\n", bleg_rtp_ping?"en":"dis");

		DBG("SST on A leg enabled: '%s'\n", sst_aleg_enabled.empty() ? "no" : sst_aleg_enabled.c_str());
		if (sst_aleg_enabled.size() && sst_aleg_enabled != "no") {
			DBG("session_expires=%s\n",
			sst_a_cfg.getParameter("session_expires").c_str());
			DBG("minimum_timer=%s\n",
			sst_a_cfg.getParameter("minimum_timer").c_str());
			DBG("maximum_timer=%s\n",
			sst_a_cfg.getParameter("maximum_timer").c_str());
			DBG("session_refresh_method=%s\n",
			sst_a_cfg.getParameter("session_refresh_method").c_str());
			DBG("accept_501_reply=%s\n",
			sst_a_cfg.getParameter("accept_501_reply").c_str());
		}
		DBG("SST on B leg enabled: '%s'\n", sst_enabled.empty() ? "no" : sst_enabled.c_str());
		if (sst_enabled.size() && sst_enabled != "no") {
			DBG("session_expires=%s\n",
			sst_b_cfg.getParameter("session_expires").c_str());
			DBG("minimum_timer=%s\n",
			sst_b_cfg.getParameter("minimum_timer").c_str());
			DBG("maximum_timer=%s\n",
			sst_b_cfg.getParameter("maximum_timer").c_str());
			DBG("session_refresh_method=%s\n",
			sst_b_cfg.getParameter("session_refresh_method").c_str());
			DBG("accept_501_reply=%s\n",
			sst_b_cfg.getParameter("accept_501_reply").c_str());
		}

		DBG("SIP auth %sabled\n", auth_enabled?"en":"dis");
		DBG("SIP auth for A leg %sabled\n", auth_aleg_enabled?"en":"dis");

		if (reply_translations.size()) {
			string reply_trans_codes;
			for(map<unsigned int, std::pair<unsigned int, string> >::iterator it=
					reply_translations.begin(); it != reply_translations.end(); it++)
				reply_trans_codes += int2str(it->first)+", ";
			reply_trans_codes.erase(reply_trans_codes.length()-2);
			DBG("reply translation for  %s\n", reply_trans_codes.c_str());
		}

		codec_prefs.infoPrint();
		transcoder.infoPrint();

		DBG("time_limit: %i\n", time_limit);
		DBG("ringing_timeout: %i\n", ringing_timeout);
		DBG("invite_timeout: %i\n", inv_transaction_timeout);
		DBG("src_vailover_timeout: %i\n", inv_srv_failover_timeout);
		DBG("fake_180_timer: %i\n",fake_ringing_timeout);

		DBG("dead_rtp_time: %i\n",dead_rtp_time);
		DBG("global_tag: %s\n", global_tag.c_str());

		DBG("resources: %s\n", resources.c_str());
		for(ResourceList::const_iterator i = rl.begin();i!=rl.end();++i)
			DBG("   resource: <%s>",(*i).print().c_str());

		DBG("aleg_override_id: %i\n", aleg_override_id);
		DBG("bleg_override_id: %i\n", bleg_override_id);

		DBG("reg-caching: '%s'\n", reg_caching ? "yes" : "no");
		DBG("min_reg_expires: %i\n", min_reg_expires);
		DBG("max_ua_expires: %i\n", max_ua_expires);

		DBG("static_codecs_aleg_id: %i\n", static_codecs_aleg_id);
		DBG("static_codecs_bleg_id: %i\n", static_codecs_bleg_id);
		DBG("aleg_single_codec: '%s'\n", aleg_single_codec?"yes":"no");
		DBG("bleg_single_codec: '%s'\n", bleg_single_codec?"yes":"no");
		DBG("try_avoid_transcoding: '%s'\n", avoid_transcoding?"yes":"no");

		DBG("filter_noaudio_streams: '%s'\n",filter_noaudio_streams?"yes":"no");

		DBG("aleg_conn_location: '%s'\n",conn_location2str(aleg_conn_location_id));
		DBG("bleg_conn_location: '%s'\n",conn_location2str(bleg_conn_location_id));

		DBG("relay_reinvite(A/B): (%s/%s)\n",
			aleg_relay_reinvite?"yes":"no",
			bleg_relay_reinvite?"yes":"no");
		DBG("relay_hold(A/B): (%s/%s)\n",
			aleg_relay_hold?"yes":"no",
			bleg_relay_hold?"yes":"no");
		/*DBG("relay_prack(A/B): (%s/%s)\n",
			aleg_relay_prack?"yes":"no",
			bleg_relay_prack?"yes":"no");*/
		DBG("relay_options(A/B): (%s/%s)\n",
			aleg_relay_options?"yes":"no",
			bleg_relay_options?"yes":"no");
		DBG("relay_update(A/B): (%s/%s)\n",
			aleg_relay_update?"yes":"no",
			bleg_relay_update?"yes":"no");

		DBG("log_sip: '%s'",log_sip?"yes":"no");
		DBG("log_rtp: '%s'",log_rtp?"yes":"no");
		DBG("record audio: '%s'",record_audio?"yes":"no");

		DBG("aleg_sensor_id: %d",aleg_sensor_id);
		DBG("aleg_sensor_level_id: %d",aleg_sensor_level_id);
		DBG("bleg_sensor_id: %d",bleg_sensor_id);
		DBG("bleg_sensor_level_id: %d",bleg_sensor_level_id);

		DBG("aleg_dtmf_send_mode_id: %d",aleg_dtmf_send_mode_id);
		DBG("bleg_dtmf_send_mode_id: %d",bleg_dtmf_send_mode_id);
		DBG("aleg_dtmf_recv_modes: %d",aleg_dtmf_recv_modes);
		DBG("bleg_dtmf_recv_modes: %d",bleg_dtmf_recv_modes);

		DBG("disable_early_media: '%s'",suppress_early_media?"yes":"no");
		DBG("force_one_way_early_media '%s'",force_one_way_early_media?"yes":"no");

		DBG("aleg_rel100_mode_id: %d",aleg_radius_acc_profile_id);
		DBG("bleg_rel100_mode_id: %d",bleg_radius_acc_profile_id);

		DBG("append_headers '%s'\n", append_headers.c_str());
		DBG("append_headers_req '%s'\n", append_headers_req.c_str());
		DBG("aleg_append_headers_reply '%s'\n", aleg_append_headers_reply.c_str());
		DBG("aleg_append_headers_req '%s'\n", aleg_append_headers_req.c_str());

		DBG("radius_profile_id: %d\n", radius_profile_id);
		DBG("aleg_radius_acc_profile_id: %d\n", aleg_radius_acc_profile_id);
		if(aleg_radius_acc_profile_id){
			DBG("aleg_radius_acc_rules: %d %d/%d %d",
				aleg_radius_acc_rules.enable_start_accounting,
				aleg_radius_acc_rules.enable_interim_accounting,
				aleg_radius_acc_rules.interim_accounting_interval,
				aleg_radius_acc_rules.enable_stop_accounting);
		}
		DBG("bleg_radius_acc_profile_id: %d\n", bleg_radius_acc_profile_id);
		if(bleg_radius_acc_profile_id){
			DBG("bleg_radius_acc_rules: %d %d/%d %d",
				bleg_radius_acc_rules.enable_start_accounting,
				bleg_radius_acc_rules.enable_interim_accounting,
				bleg_radius_acc_rules.interim_accounting_interval,
				bleg_radius_acc_rules.enable_stop_accounting);
		}


		for(AmArg::ValueStruct::const_iterator it = dyn_fields.begin();
			it!=dyn_fields.end();++it)
		{
			const AmArg &a = it->second;
			DBG("dynamic_field['%s']: %s [%s]\n",
				 it->first.c_str(),
				 AmArg::print(a).c_str(),
				 a.t2str(a.getType()));
		}
	}
}

bool SqlCallProfile::readFilter(const pqxx::result::tuple &t, const char* cfg_key_filter,
		vector<FilterEntry>& filter_list, bool keep_transparent_entry,
		int failover_type_id){
	FilterEntry hf;

	string filter_key_type_field = string(cfg_key_filter)+"_type_id";
	string filter_list_field = string(cfg_key_filter)+"_list";

	int filter_type_id;
	assign_int_safe(filter_type_id,filter_key_type_field.c_str(),FILTER_TYPE_TRANSPARENT,failover_type_id);

	switch(filter_type_id){
		case FILTER_TYPE_TRANSPARENT:
			hf.filter_type = Transparent;
			break;
		case FILTER_TYPE_BLACKLIST:
			hf.filter_type = Blacklist;
			break;
		case FILTER_TYPE_WHITELIST:
			hf.filter_type = Whitelist;
			break;
		default:
			hf.filter_type = Undefined;
			ERROR("invalid %s type_id: %d\n", cfg_key_filter, filter_type_id);
			return false;
	}

	// no transparent filter
	if (!keep_transparent_entry && hf.filter_type==Transparent)
	return true;

	string elems_str;
	assign_str_safe(elems_str,filter_list_field.c_str(),"");

	vector<string> elems = explode(elems_str,",");
	for (vector<string>::iterator it=elems.begin(); it != elems.end(); it++) {
		string c = *it;
		std::transform(c.begin(), c.end(), c.begin(), ::tolower);
		hf.filter_list.insert(c);
	}

	filter_list.push_back(hf);
	return true;
}

bool SqlCallProfile::readFilterSet(const pqxx::result::tuple &t, const char* cfg_key_filter,
		vector<FilterEntry>& filter_list)
{
	string s;
	assign_str_safe(s,cfg_key_filter,"");

	if(s.empty()){
		FilterEntry f;
		f.filter_type = Whitelist;
		filter_list.push_back(f);
		return true;
	}

	vector<string> filters = explode(s,";",true);
	for (vector<string>::iterator filter =
		filters.begin(); filter != filters.end(); filter++)
	{
		FilterEntry f;
		f.filter_type = Whitelist;

		if(filter->empty()){
			filter_list.push_back(f);
			continue;
		}

		std::transform(filter->begin(), filter->end(), filter->begin(), ::tolower);

		vector<string> values = explode(*filter,",");
		for(vector<string>::iterator value =
			values.begin(); value != values.end(); value++)
		{
			f.filter_list.insert(*value);
		}
		filter_list.push_back(f);
	}
	return true;
}

bool SqlCallProfile::readCodecPrefs(const pqxx::result::tuple &t){
	/*assign_str(codec_prefs.bleg_payload_order_str,"codec_preference");
	assign_bool_str(codec_prefs.bleg_prefer_existing_payloads_str,"prefer_existing_codecs",false);

	assign_str(codec_prefs.aleg_payload_order_str,"codec_preference_aleg");
	assign_bool_str(codec_prefs.aleg_prefer_existing_payloads_str,"prefer_existing_codecs_aleg",false);*/

	assign_int(static_codecs_aleg_id,"aleg_codecs_group_id",0);
	assign_int(static_codecs_bleg_id,"bleg_codecs_group_id",0);
	assign_bool_safe(aleg_single_codec,"aleg_single_codec_in_200ok",false,false);
	assign_bool_safe(bleg_single_codec,"bleg_single_codec_in_200ok",false,false);
	assign_bool_safe(avoid_transcoding,"try_avoid_transcoding",false,false);

	return true;
}

bool SqlCallProfile::readTranscoder(const pqxx::result::tuple &t){
	// store string values for later evaluation
	//assign_str(transcoder.audio_codecs_str,"transcoder_codecs");
	//assign_str(transcoder.callee_codec_capabilities_str,"callee_codeccaps");
	//assign_str(transcoder.transcoder_mode_str,"enable_transcoder");
	assign_str(transcoder.dtmf_mode_str,"dtmf_transcoding");
	assign_str(transcoder.lowfi_codecs_str,"lowfi_codecs");
	//assign_str(transcoder.audio_codecs_norelay_str,"prefer_transcoding_for_codecs");
	//assign_str(transcoder.audio_codecs_norelay_aleg_str,"prefer_transcoding_for_codecs_aleg");

	return true;
}

bool SqlCallProfile::readDynFields(const pqxx::result::tuple &t,const DynFieldsT &df){
	dyn_fields.assertStruct();
	for(DynFieldsT::const_iterator it = df.begin();it!=df.end();++it){
		it->tuple2AmArg(t,dyn_fields[it->name]);
	}
	return true;
}

bool SqlCallProfile::column_exist(const pqxx::result::tuple &t,string column_name){
	try {
		t.column_number(column_name);
		return true;
	} catch(...){
		DBG("%s column: %s",FUNC_NAME,column_name.c_str());
	}
	return false;
}

bool SqlCallProfile::eval_resources(){
	try {
		rl.parse(resources);
	} catch(ResourceParseException &e){
		ERROR("resources parse error:  %s <ctx = '%s'>",e.what.c_str(),e.ctx.c_str());
	}
	return true;
}

bool SqlCallProfile::eval_radius(){
	if(Yeti::instance().config.use_radius){
		AmDynInvoke* radius_client = NULL;
		if(aleg_radius_acc_profile_id){
			AmArg rules;
			radius_client = AmPlugIn::instance()->getFactory4Di("radius_client")->getInstance();
			radius_client->invoke("r",aleg_radius_acc_profile_id,rules);
			aleg_radius_acc_rules.unpack(rules);
		}
		if(bleg_radius_acc_profile_id){
			AmArg rules;
			if(!radius_client) radius_client = AmPlugIn::instance()->getFactory4Di("radius_client")->getInstance();
			radius_client->invoke("r",bleg_radius_acc_profile_id,rules);
			bleg_radius_acc_rules.unpack(rules);
		}
	} else {
		if(radius_profile_id){
			ERROR("got call_profile with radius_profile_id set, but radius support is disabled. "
				  "fix your configuration ");
			return false;
		}
		if(aleg_radius_acc_profile_id){
			ERROR("got call_profile with aleg_radius_acc_profile_id set, but radius support is disabled. "
				  "fix your configuration ");
			return false;
		}
		if(bleg_radius_acc_profile_id){
			ERROR("got call_profile with bleg_radius_acc_profile_id set, but radius support is disabled. "
				  "fix your configuration ");
			return false;
		}
	}
	return true;
}

static void _patch_uri_transport(
	string &uri,
	unsigned int transport_id,
	const char *field_name,
	const char *transport_field_name)
{
	if(!transport_id) return;
	switch(transport_id) {
	case sip_transport::UDP: break;
	case sip_transport::TCP: {
		AmUriParser parser;
		DBG("patch %s to use TCP transport. current value is: '%s'",
			field_name,uri.c_str());
		parser.uri = uri;
		if(!parser.parse_uri()) {
			ERROR("Error parsing %s '%s' for protocol patching to TCP. leave it as is",
				  field_name,uri.c_str());
			break;
		}
		//check for existent transport param
		if(!parser.uri_param.empty()) {
			bool can_patch = true;
			auto uri_params_list = explode(URL_decode(parser.uri_param),";");
			for(const auto &p: uri_params_list) {
				auto v = explode(p,"=");
				if(v[0]=="transport") {
					ERROR("attempt to patch %s with existent transport parameter: '%s'."
						 " leave it as is",
						  field_name,v.size()>1?v[1].c_str():"");
					can_patch = false;
					break;
				}
			}
			if(can_patch) {
				parser.uri_param+=";transport=TCP";
				uri = parser.uri_str();
				DBG("%s patched to: '%s'",field_name,uri.c_str());
			}
		} else {
			parser.uri_param = "transport=TCP";
			uri = parser.uri_str();
			DBG("%s patched to: '%s'",field_name,uri.c_str());
		}
	} break;
	default:
		ERROR("%s %d is not supported yet. ignore it",transport_field_name,transport_id);
	}
}
#define patch_uri_transport(profile_field,transport_id_field) \
	_patch_uri_transport(profile_field,transport_id_field,#profile_field,#transport_id_field);

bool SqlCallProfile::eval_transport_ids()
{
	patch_uri_transport(ruri,bleg_transport_id);
	patch_uri_transport(outbound_proxy,outbound_proxy_transport_id);
	patch_uri_transport(aleg_outbound_proxy,aleg_outbound_proxy_transport_id);
	return true;
}

bool SqlCallProfile::eval(){
	if(!outbound_interface.empty())
		if(!evaluateOutboundInterface())
			return false;
	if(0!=disconnect_code_id){
		DBG("skip resources parsing for refusing profile");
		return true;
	}
	return eval_transport_ids() &&
		   eval_resources() &&
		   eval_radius();
}

SqlCallProfile *SqlCallProfile::copy(){
	SqlCallProfile *profile = new SqlCallProfile();
	*profile = *this;
	return profile;
}

void SqlCallProfile::info(AmArg &s)
{
	s["ruri"] = ruri;
	s["from"] = from;
	s["to"] = to;
	s["resource_handler"] = resource_handler;
	s["append_headers"] = append_headers;
	s["outbound_interface"] = outbound_interface;
	for(const auto &f: dyn_fields)
		s[f.first] = f.second;
}
