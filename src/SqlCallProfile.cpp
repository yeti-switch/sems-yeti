#include "SqlCallProfile.h"
#include "AmUtils.h"
#include "SBC.h"
#include "yeti.h"
#include <algorithm>
#include "RTPParameters.h"
#include "sdp_filter.h"
#include "sip/parse_via.h"
#include "sip/resolver.h"
#include "db/DbHelpers.h"
#include "jsonArg.h"

SqlCallProfile::SqlCallProfile():
	aleg_override_id(0),
	bleg_override_id(0),
	legab_res_mode_enabled{false}
{}

SqlCallProfile::~SqlCallProfile(){ }

static void readMediaAcl(const AmArg &t, const char key[], std::vector<AmSubnet> &acl)
{
	if(!t.hasMember(key))
		return;

	AmArg &v = t[key];
	if(!isArgArray(v)) {
		DBG("expected array by the key: %s", key);
		return;
	}
	for(size_t i = 0; i < v.size(); i++) {
		AmArg &a = v[i];
		if(!isArgCStr(a)) {
			ERROR("skip unexpected array entry: %s", a.print().data());
			continue;
		}
		AmSubnet subnet;
		if(!subnet.parse(a.asCStr())) {
			ERROR("failed to parse subnet '%s' for %s",
				a.asCStr(), key);
			continue;
		}
		acl.emplace_back(subnet);
	}
}

bool SqlCallProfile::readFromTuple(const AmArg &t,const DynFieldsT &df){
	//common fields both for routing and refusing profiles

	ruri = DbAmArg_hash_get_str(t, "ruri");
	outbound_proxy = DbAmArg_hash_get_str(t, "outbound_proxy");

        if(t.hasMember("lega_res") || t.hasMember("legb_res")) {
		lega_res = DbAmArg_hash_get_str(t, "lega_res");
		resources = DbAmArg_hash_get_str(t, "legb_res");
		legab_res_mode_enabled = true;
        } else {
		resources = DbAmArg_hash_get_str(t, "resources");
        }

	append_headers = DbAmArg_hash_get_str(t, "append_headers");

	time_limit = DbAmArg_hash_get_int(t,"time_limit",0);
	aleg_override_id = DbAmArg_hash_get_int(t,"aleg_policy_id",0);

	trusted_hdrs_gw = DbAmArg_hash_get_bool(t, "trusted_hdrs_gw", false);
	record_audio = DbAmArg_hash_get_bool(t, "record_audio", false);

	dump_level_id = DbAmArg_hash_get_int(t,"dump_level_id",0);
	dump_level_id |= AmConfig.dump_level;
	log_rtp = dump_level_id&LOG_RTP_MASK;
	log_sip = dump_level_id&LOG_SIP_MASK;

	if(!readDynFields(t,df)) {
		ERROR("failed to read dynamic fields");
		return false;
	}

	if(Yeti::instance().config.use_radius){
		for(const auto &f: t) {
			placeholders_hash[f.first] = arg2json(f.second);
		}
	}

	disconnect_code_id = DbAmArg_hash_get_int(t,"disconnect_code_id",0);
	if(0 != disconnect_code_id)
		return true; //skip excess fields reading for refusing profile

	//fields fore the routing profiles only

	from = DbAmArg_hash_get_str(t, "from");
	to = DbAmArg_hash_get_str(t, "to");
	callid = DbAmArg_hash_get_str(t, "call_id");

	dlg_nat_handling = DbAmArg_hash_get_bool(t, "dlg_nat_handling", false);

	force_outbound_proxy = DbAmArg_hash_get_bool(t, "force_outbound_proxy", false);
	outbound_proxy = DbAmArg_hash_get_str(t, "outbound_proxy");

	aleg_force_outbound_proxy = DbAmArg_hash_get_bool(t, "aleg_force_outbound_proxy", false);
	aleg_outbound_proxy = DbAmArg_hash_get_str(t, "aleg_outbound_proxy");

	next_hop = DbAmArg_hash_get_str(t, "next_hop");
	next_hop_1st_req = DbAmArg_hash_get_bool(t, "next_hop_1st_req", false);
	patch_ruri_next_hop = DbAmArg_hash_get_bool(t, "patch_ruri_next_hop", false);
	aleg_next_hop = DbAmArg_hash_get_str(t, "aleg_next_hop");

	if(!readFilterSet(t,"transit_headers_a2b",headerfilter_a2b)) {
		ERROR("failed to read transit_headers_a2b");
		return false;
	}

	if(!readFilterSet(t,"transit_headers_b2a",headerfilter_b2a)) {
		ERROR("failed to read transit_headers_b2a");
		return false;
	}

	if (!readFilter(t, "sdp_filter", sdpfilter, true)) {
		ERROR("failed to read sdp_filter");
		return false;
	}

	// SDP alines filter
	if (!readFilter(t, "sdp_alines_filter", sdpalinesfilter, false)) {
		ERROR("failed to read sdp_alines_filter");
		return false;
	}

	if (!readFilter(t, "bleg_sdp_alines_filter", bleg_sdpalinesfilter, false, FILTER_TYPE_WHITELIST)) {
		ERROR("failed to read bleg_sdp_alines_filter");
		return false;
	}

	sst_enabled = DbAmArg_hash_get_bool_any(t, "enable_session_timer", false);
	if(t.hasMember("enable_aleg_session_timer")) {
		sst_aleg_enabled = DbAmArg_hash_get_bool_any(t, "enable_aleg_session_timer", false);
	} else {
		sst_aleg_enabled = sst_enabled;
	}

#define CP_SST_CFGVAR(cfgprefix, cfgkey, dstcfg)			\
	if(t.hasMember(cfgprefix cfgkey)) { \
		dstcfg.setParameter(cfgkey, DbAmArg_hash_get_str_any(t,cfgprefix cfgkey));	\
	} else { \
		dstcfg.setParameter(cfgkey, DbAmArg_hash_get_str_any(t,cfgkey));		\
	}

#define	CP_SESSION_REFRESH_METHOD(method_id,dstcfg)\
	switch(method_id){\
		case REFRESH_METHOD_INVITE:\
			dstcfg.setParameter("session_refresh_method",\
				"INVITE");\
			break;\
		case REFRESH_METHOD_UPDATE:\
			dstcfg.setParameter("session_refresh_method",\
				"UPDATE");\
			break;\
		case REFRESH_METHOD_UPDATE_FALLBACK_INVITE:\
			dstcfg.setParameter("session_refresh_method",\
				"UPDATE_FALLBACK_INVITE");\
			break;\
		default:\
			ERROR("unknown session_refresh_method id '%d'",method_id);\
			return false;\
	}

	if (sst_enabled) {
		if (nullptr == SBCFactory::instance()->session_timer_fact) {
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
		session_refresh_method_id = DbAmArg_hash_get_int(t,"session_refresh_method_id",1);
		CP_SESSION_REFRESH_METHOD(session_refresh_method_id,sst_b_cfg);
	}

	if (sst_aleg_enabled) {
		sst_a_cfg.setParameter("enable_session_timer", "yes");
		// create sst_a_cfg superimposing values from aleg_*
		CP_SST_CFGVAR("aleg_", "session_expires", sst_a_cfg);
		CP_SST_CFGVAR("aleg_", "minimum_timer", sst_a_cfg);
		CP_SST_CFGVAR("aleg_", "maximum_timer", sst_a_cfg);
		//CP_SST_CFGVAR("aleg_", "session_refresh_method", sst_a_cfg);
		CP_SST_CFGVAR("aleg_", "accept_501_reply", sst_a_cfg);
		aleg_session_refresh_method_id = DbAmArg_hash_get_int(t,"aleg_session_refresh_method_id",1);
		CP_SESSION_REFRESH_METHOD(aleg_session_refresh_method_id,sst_a_cfg);
	}
#undef CP_SST_CFGVAR
#undef CP_SESSION_REFRESH_METHOD

	auth_enabled = DbAmArg_hash_get_bool(t, "enable_auth", false);
	auth_credentials.user = DbAmArg_hash_get_str(t, "auth_user");
	auth_credentials.pwd = DbAmArg_hash_get_str(t, "auth_pwd");
	
	auth_aleg_enabled = DbAmArg_hash_get_bool(t, "enable_aleg_auth", false);
	auth_aleg_credentials.user = DbAmArg_hash_get_str(t, "auth_aleg_user");
	auth_aleg_credentials.pwd = DbAmArg_hash_get_str(t, "auth_aleg_pwd");
	
	vector<string> reply_translations_v =
		explode(DbAmArg_hash_get_str_any(t,"reply_translations"), "|");
	
	for (vector<string>::iterator it =
			reply_translations_v.begin(); it != reply_translations_v.end(); it++) {
		// expected: "603=>488 Not acceptable here"
		vector<string> trans_components = explode(*it, "=>");
		if (trans_components.size() != 2) {
			ERROR("entry '%s' in reply_translations could not be understood.", it->c_str());
			ERROR("expected 'from_code=>to_code reason'");
			return false;
		}
	
		unsigned int from_code, to_code;
		if (str2i(trans_components[0], from_code)) {
			ERROR("code '%s' in reply_translations not understood.", trans_components[0].c_str());
			return false;
		}
		unsigned int s_pos = 0;
		string to_reply = trans_components[1];
		while (s_pos < to_reply.length() && to_reply[s_pos] != ' ')
		s_pos++;
		if (str2i(to_reply.substr(0, s_pos), to_code)) {
			ERROR("code '%s' in reply_translations not understood.", to_reply.substr(0, s_pos).c_str());
			return false;
		}
		if (s_pos < to_reply.length())
			s_pos++;
		// DBG("got translation %u => %u %s",
		// 	from_code, to_code, to_reply.substr(s_pos).c_str());
		reply_translations[from_code] = make_pair(to_code, to_reply.substr(s_pos));
	}
	
	append_headers_req = DbAmArg_hash_get_str(t, "append_headers_req");
	aleg_append_headers_req = DbAmArg_hash_get_str(t, "aleg_append_headers_req");
	aleg_append_headers_reply = DbAmArg_hash_get_str(t, "aleg_append_headers_reply");
	
	rtprelay_enabled = DbAmArg_hash_get_bool(t, "enable_rtprelay", false);
	force_symmetric_rtp = DbAmArg_hash_get_bool(t, "bleg_force_symmetric_rtp", false);
	aleg_force_symmetric_rtp = DbAmArg_hash_get_bool(t, "aleg_force_symmetric_rtp", false);
	
	rtprelay_interface = DbAmArg_hash_get_str(t, "rtprelay_interface");
	aleg_rtprelay_interface = DbAmArg_hash_get_str(t, "aleg_rtprelay_interface");
	
	outbound_interface = DbAmArg_hash_get_str(t, "outbound_interface");
	aleg_outbound_interface = DbAmArg_hash_get_str(t, "aleg_outbound_interface");

	bleg_force_cancel_routeset = DbAmArg_hash_get_bool(t, "bleg_force_cancel_routeset", false);

	if (!readCodecPrefs(t)) {
		ERROR("failed to read codec prefs");
		return false;
	}
	
	disconnect_code_id = DbAmArg_hash_get_int(t,"disconnect_code_id",0);
	
	bleg_override_id = DbAmArg_hash_get_int(t,"bleg_policy_id",0);
	
	ringing_timeout = DbAmArg_hash_get_int(t,"ringing_timeout",0);
	
	global_tag = DbAmArg_hash_get_str(t, "global_tag");
	
	rtprelay_dtmf_filtering = DbAmArg_hash_get_bool(t, "rtprelay_dtmf_filtering", false);
	rtprelay_dtmf_detection = DbAmArg_hash_get_bool(t, "rtprelay_dtmf_detection", false);
	rtprelay_force_dtmf_relay = DbAmArg_hash_get_bool(t, "rtprelay_force_dtmf_relay", true);
	
	aleg_symmetric_rtp_nonstop = DbAmArg_hash_get_bool(t, "aleg_symmetric_rtp_nonstop", false);
	bleg_symmetric_rtp_nonstop = DbAmArg_hash_get_bool(t, "bleg_symmetric_rtp_nonstop", false);
	
	aleg_relay_options = DbAmArg_hash_get_bool(t, "aleg_relay_options", false);
	bleg_relay_options = DbAmArg_hash_get_bool(t, "bleg_relay_options", false);
	
	aleg_relay_update = DbAmArg_hash_get_bool(t, "aleg_relay_update", true);
	bleg_relay_update = DbAmArg_hash_get_bool(t, "bleg_relay_update", true);
	
	filter_noaudio_streams = DbAmArg_hash_get_bool(t, "filter_noaudio_streams", true);
	
	aleg_rtp_ping = DbAmArg_hash_get_bool(t, "aleg_rtp_ping", false);
	bleg_rtp_ping = DbAmArg_hash_get_bool(t, "bleg_rtp_ping", false);
	
	aleg_conn_location_id = DbAmArg_hash_get_int(t,"aleg_sdp_c_location_id",0);
	bleg_conn_location_id = DbAmArg_hash_get_int(t,"bleg_sdp_c_location_id",0);

	dead_rtp_time = DbAmArg_hash_get_int(
		t,"dead_rtp_time",
		AmConfig.dead_rtp_time);

	aleg_relay_reinvite = DbAmArg_hash_get_bool(t, "aleg_relay_reinvite", true);
	bleg_relay_reinvite = DbAmArg_hash_get_bool(t, "bleg_relay_reinvite", true);
	/*assign_bool_safe(aleg_relay_prack,"aleg_relay_prack",true,true);
	assign_bool_safe(bleg_relay_prack,"bleg_relay_prack",true,true);*/
	aleg_relay_hold = DbAmArg_hash_get_bool(t, "aleg_relay_hold", true);
	bleg_relay_hold = DbAmArg_hash_get_bool(t, "bleg_relay_hold", true);

	relay_timestamp_aligning = DbAmArg_hash_get_bool(t, "rtp_relay_timestamp_aligning", false);

	allow_1xx_without_to_tag = DbAmArg_hash_get_bool(t, "allow_1xx_wo2tag", false);

	inv_transaction_timeout = DbAmArg_hash_get_int(t,"invite_timeout",0);
	inv_srv_failover_timeout = DbAmArg_hash_get_int(t,"srv_failover_timeout",0);
	/*assign_type_safe(inv_transaction_timeout,"invite_timeout",0,unsigned int,0);
	assign_type_safe(inv_srv_failover_timeout,"srv_failover_timeout",0,unsigned int,0);*/

	force_relay_CN = DbAmArg_hash_get_bool(t, "rtp_force_relay_cn", false);

	aleg_sensor_id = DbAmArg_hash_get_int(t,"aleg_sensor_id",-1);
	bleg_sensor_id = DbAmArg_hash_get_int(t,"bleg_sensor_id",-1);
	aleg_sensor_level_id = DbAmArg_hash_get_int(t,"aleg_sensor_level_id", 0);
	bleg_sensor_level_id = DbAmArg_hash_get_int(t,"bleg_sensor_level_id", 0);

	aleg_dtmf_send_mode_id = DbAmArg_hash_get_int(t,"aleg_dtmf_send_mode_id",DTMF_TX_MODE_RFC2833);
	bleg_dtmf_send_mode_id = DbAmArg_hash_get_int(t,"bleg_dtmf_send_mode_id",DTMF_TX_MODE_RFC2833);
	aleg_dtmf_recv_modes = DbAmArg_hash_get_int(t,"aleg_dtmf_recv_modes",DTMF_RX_MODE_ALL);
	bleg_dtmf_recv_modes = DbAmArg_hash_get_int(t,"bleg_dtmf_recv_modes",DTMF_RX_MODE_ALL);

	aleg_rtp_filter_inband_dtmf = DbAmArg_hash_get_bool(t, "aleg_rtp_filter_inband_dtmf", false);
	bleg_rtp_filter_inband_dtmf = DbAmArg_hash_get_bool(t, "bleg_rtp_filter_inband_dtmf", false);

	if(aleg_rtp_filter_inband_dtmf ||
	   bleg_rtp_filter_inband_dtmf ||
	   (aleg_dtmf_recv_modes & DTMF_RX_MODE_INBAND) ||
	   (aleg_dtmf_recv_modes & DTMF_RX_MODE_INBAND))
	{
		transcoder.dtmf_mode = TranscoderSettings::DTMFAlways;
		force_transcoding = true;
	} else {
		transcoder.dtmf_mode = TranscoderSettings::DTMFNever;
	}

	suppress_early_media = DbAmArg_hash_get_bool(t, "suppress_early_media", false);
	force_one_way_early_media = DbAmArg_hash_get_bool(t, "force_one_way_early_media", false);
	fake_ringing_timeout = DbAmArg_hash_get_int(t,"fake_180_timer",0);

	aleg_rel100_mode_id = DbAmArg_hash_get_int(t,"aleg_rel100_mode_id",-1);
	bleg_rel100_mode_id = DbAmArg_hash_get_int(t,"bleg_rel100_mode_id",-1);

	radius_profile_id = DbAmArg_hash_get_int(t,"radius_auth_profile_id",0);
	aleg_radius_acc_profile_id = DbAmArg_hash_get_int(t,"aleg_radius_acc_profile_id",0);
	bleg_radius_acc_profile_id = DbAmArg_hash_get_int(t,"bleg_radius_acc_profile_id",0);

	bleg_transport_id = DbAmArg_hash_get_int(t,"bleg_transport_protocol_id",0);
	outbound_proxy_transport_id = DbAmArg_hash_get_int(t,"bleg_outbound_proxy_transport_protocol_id",0);
	aleg_outbound_proxy_transport_id = DbAmArg_hash_get_int(t,"aleg_outbound_proxy_transport_protocol_id",0);

	bleg_protocol_priority_id = DbAmArg_hash_get_int(t,"bleg_protocol_priority_id",dns_priority::IPv4_only);

	bleg_protocol_priority_id = DbAmArg_hash_get_int(t,"bleg_max_30x_redirects",0);
	bleg_max_transfers = DbAmArg_hash_get_int(t,"bleg_max_transfers",0);

	auth_required = DbAmArg_hash_get_bool(t, "aleg_auth_required", false);

	registered_aor_id = DbAmArg_hash_get_int(t,"registered_aor_id",0);
	registered_aor_mode_id = DbAmArg_hash_get_int(t,"registered_aor_mode_id", REGISTERED_AOR_MODE_AS_IS);

	aleg_media_encryption_mode_id = DbAmArg_hash_get_int(t,"aleg_media_encryption_mode_id",0);
	bleg_media_encryption_mode_id = DbAmArg_hash_get_int(t,"bleg_media_encryption_mode_id",0);

	readMediaAcl(t, "aleg_rtp_acl", aleg_rtp_acl);
	readMediaAcl(t, "bleg_rtp_acl", bleg_rtp_acl);

	ss_crt_id = DbAmArg_hash_get_int(t, "ss_crt_id", 0);
	ss_attest_id = DbAmArg_hash_get_int(t, "ss_attest_id", 3 /* attest level C */);
	ss_otn = DbAmArg_hash_get_str(t, "ss_otn");
	ss_dtn = DbAmArg_hash_get_str(t, "ss_dtn");

	DBG("Yeti: loaded SQL profile");

	return true;
}

ResourceList& SqlCallProfile::getResourceList(bool a_leg)
{
	return legab_res_mode_enabled
		? (a_leg ? lega_rl : rl)
		: rl;
}

string& SqlCallProfile::getResourceHandler(bool a_leg)
{
        return legab_res_mode_enabled
		? (a_leg ? lega_resource_handler: resource_handler)
		: resource_handler;
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
		DBG("refusing calls with code '%d'", disconnect_code_id);
	/*} else if (!refuse_with.empty()) {
		DBG("refusing calls with '%s'", refuse_with.c_str());
		*/
	} else {
		DBG("RURI      = '%s'", ruri.c_str());
		DBG("RURI transport id = %d",bleg_transport_id);
		DBG("bleg_protocol_priority_id = %d(%s)",
			bleg_protocol_priority_id,
			dns_priority_str(static_cast<const dns_priority>(bleg_protocol_priority_id)));
		DBG("From = '%s'", from.c_str());
		DBG("To   = '%s'", to.c_str());
		// if (!contact.empty()) {
		//   DBG("Contact   = '%s'", contact.c_str());
		// }
		if (!callid.empty()) {
			DBG("Call-ID   = '%s'", callid.c_str());
		}

		DBG("force outbound proxy: %s", force_outbound_proxy?"yes":"no");
		DBG("outbound proxy = '%s'", outbound_proxy.c_str());
		DBG("outbound proxy transport id = %d", outbound_proxy_transport_id);

		if (!outbound_interface.empty()) {
			DBG("outbound interface = '%s'", outbound_interface.c_str());
		}

		if (!aleg_outbound_interface.empty()) {
			DBG("A leg outbound interface = '%s'", aleg_outbound_interface.c_str());
		}

		DBG("A leg force outbound proxy: %s", aleg_force_outbound_proxy?"yes":"no");
		DBG("A leg outbound proxy = '%s'", aleg_outbound_proxy.c_str());
		DBG("A leg outbound transport id = %d", aleg_outbound_proxy_transport_id);

		if (!next_hop.empty()) {
			DBG("next hop = %s (%s)", next_hop.c_str(),
			next_hop_1st_req ? "1st req" : "all reqs");
		}

		if (!aleg_next_hop.empty()) {
			DBG("A leg next hop = %s", aleg_next_hop.c_str());
		}

		printFilterList("transit_headers_a2b", headerfilter_a2b);
		printFilterList("transit_headers_b2a", headerfilter_b2a);

		string filter_type; size_t filter_elems;

		filter_type = sdpfilter.size() ? FilterType2String(sdpfilter.back().filter_type) : "disabled";
		filter_elems = sdpfilter.size() ? sdpfilter.back().filter_list.size() : 0;
		DBG("SDP filter is %sabled, %s, %zd items in list",
		sdpfilter.size()?"en":"dis", filter_type.c_str(), filter_elems);

		filter_type = sdpalinesfilter.size() ? FilterType2String(sdpalinesfilter.back().filter_type) : "disabled";
		filter_elems = sdpalinesfilter.size() ? sdpalinesfilter.back().filter_list.size() : 0;
		DBG("SDP alines-filter is %sabled, %s, %zd items in list", sdpalinesfilter.size()?"en":"dis", filter_type.c_str(), filter_elems);

		filter_type = bleg_sdpalinesfilter.size() ? FilterType2String(bleg_sdpalinesfilter.back().filter_type) : "disabled";
		filter_elems = bleg_sdpalinesfilter.size() ? bleg_sdpalinesfilter.back().filter_list.size() : 0;
		DBG("SDP Bleg alines-filter is %sabled, %s, %zd items in list", bleg_sdpalinesfilter.size()?"en":"dis", filter_type.c_str(), filter_elems);

		DBG("RTP relay %sabled", rtprelay_enabled?"en":"dis");
		if (rtprelay_enabled) {
			DBG("RTP force symmetric RTP: %d", force_symmetric_rtp);
			if (!aleg_rtprelay_interface.empty()) {
				DBG("RTP Relay interface A leg '%s'", aleg_rtprelay_interface.c_str());
			}
			if (!rtprelay_interface.empty()) {
				DBG("RTP Relay interface B leg '%s'", rtprelay_interface.c_str());
			}

			DBG("RTP Relay RTP DTMF filtering %sabled",
				rtprelay_dtmf_filtering?"en":"dis");
			DBG("RTP Relay RTP DTMF detection %sabled",
				rtprelay_dtmf_detection?"en":"dis");
			DBG("RTP Relay RTP DTMF force relay %sabled",
				rtprelay_force_dtmf_relay?"en":"dis");
			DBG("RTP Relay Aleg nonstop symmetric RTP %sabled",
				aleg_symmetric_rtp_nonstop?"en":"dis");
			DBG("RTP Relay Bleg nonstop symmetric RTP %sabled",
				bleg_symmetric_rtp_nonstop?"en":"dis");
			DBG("RTP Relay timestamp aligning %sabled",
			relay_timestamp_aligning?"en":"dis");
		}

		DBG("RTP Ping Aleg %sabled", aleg_rtp_ping?"en":"dis");
		DBG("RTP Ping Bleg %sabled", bleg_rtp_ping?"en":"dis");

		DBG("SST on A leg enabled: %d", sst_aleg_enabled);
		if (sst_aleg_enabled) {
			DBG("session_expires=%s",
			sst_a_cfg.getParameter("session_expires").c_str());
			DBG("minimum_timer=%s",
			sst_a_cfg.getParameter("minimum_timer").c_str());
			DBG("maximum_timer=%s",
			sst_a_cfg.getParameter("maximum_timer").c_str());
			DBG("session_refresh_method=%s",
			sst_a_cfg.getParameter("session_refresh_method").c_str());
			DBG("accept_501_reply=%s",
			sst_a_cfg.getParameter("accept_501_reply").c_str());
		}
		DBG("SST on B leg enabled: %d'", sst_enabled);
		if (sst_enabled) {
			DBG("session_expires=%s",
			sst_b_cfg.getParameter("session_expires").c_str());
			DBG("minimum_timer=%s",
			sst_b_cfg.getParameter("minimum_timer").c_str());
			DBG("maximum_timer=%s",
			sst_b_cfg.getParameter("maximum_timer").c_str());
			DBG("session_refresh_method=%s",
			sst_b_cfg.getParameter("session_refresh_method").c_str());
			DBG("accept_501_reply=%s",
			sst_b_cfg.getParameter("accept_501_reply").c_str());
		}

		DBG("SIP auth %sabled", auth_enabled?"en":"dis");
		DBG("SIP auth for A leg %sabled", auth_aleg_enabled?"en":"dis");

		if (reply_translations.size()) {
			string reply_trans_codes;
			for(map<unsigned int, std::pair<unsigned int, string> >::iterator it=
					reply_translations.begin(); it != reply_translations.end(); it++)
				reply_trans_codes += int2str(it->first)+", ";
			reply_trans_codes.erase(reply_trans_codes.length()-2);
			DBG("reply translation for  %s", reply_trans_codes.c_str());
		}

		transcoder.infoPrint();

		DBG("time_limit: %i", time_limit);
		DBG("ringing_timeout: %i", ringing_timeout);
		DBG("invite_timeout: %i", inv_transaction_timeout);
		DBG("src_vailover_timeout: %i", inv_srv_failover_timeout);
		DBG("fake_180_timer: %i",fake_ringing_timeout);

		DBG("dead_rtp_time: %i",dead_rtp_time);
		DBG("global_tag: %s", global_tag.c_str());

		DBG("auth_required: %d",auth_required);
		DBG("registered_aor_id: %d",registered_aor_id);
		DBG("registered_aor_mode_id: %d",registered_aor_mode_id);
		DBG("resources: %s", resources.c_str());
		for(ResourceList::const_iterator i = rl.begin();i!=rl.end();++i)
			DBG("   resource: <%s>",(*i).print().c_str());

		DBG("aleg_override_id: %i", aleg_override_id);
		DBG("bleg_override_id: %i", bleg_override_id);

		DBG("static_codecs_aleg_id: %i", static_codecs_aleg_id);
		DBG("static_codecs_bleg_id: %i", static_codecs_bleg_id);
		DBG("aleg_single_codec: '%s'", aleg_single_codec?"yes":"no");
		DBG("bleg_single_codec: '%s'", bleg_single_codec?"yes":"no");
		DBG("try_avoid_transcoding: '%s'", avoid_transcoding?"yes":"no");

		DBG("aleg_media_encryption_mode_id: %d",aleg_media_encryption_mode_id);
		DBG("aleg_media_transport: %s, aleg_media_allow_zrtp: %d",
			transport_p_2_str(aleg_media_transport).data(), aleg_media_allow_zrtp);

		DBG("bleg_media_encryption_mode_id: %d",bleg_media_encryption_mode_id);
		DBG("bleg_media_transport: %s, bleg_media_allow_zrtp: %d",
			transport_p_2_str(bleg_media_transport).data(), bleg_media_allow_zrtp);

		DBG("filter_noaudio_streams: '%s'",filter_noaudio_streams?"yes":"no");

		DBG("aleg_conn_location: '%s'",conn_location2str(aleg_conn_location_id));
		DBG("bleg_conn_location: '%s'",conn_location2str(bleg_conn_location_id));

		DBG("relay_reinvite(A/B): (%s/%s)",
			aleg_relay_reinvite?"yes":"no",
			bleg_relay_reinvite?"yes":"no");
		DBG("relay_hold(A/B): (%s/%s)",
			aleg_relay_hold?"yes":"no",
			bleg_relay_hold?"yes":"no");
		/*DBG("relay_prack(A/B): (%s/%s)",
			aleg_relay_prack?"yes":"no",
			bleg_relay_prack?"yes":"no");*/
		DBG("relay_options(A/B): (%s/%s)",
			aleg_relay_options?"yes":"no",
			bleg_relay_options?"yes":"no");
		DBG("relay_update(A/B): (%s/%s)",
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
		DBG("aleg_rtp_filter_inband_dtmf: %d",aleg_rtp_filter_inband_dtmf);
		DBG("bleg_rtp_filter_inband_dtmf: %d",bleg_rtp_filter_inband_dtmf);

		DBG("aleg_rtp_acl size: %zd", aleg_rtp_acl.size());
		DBG("bleg_rtp_acl size: %zd", bleg_rtp_acl.size());

		DBG("disable_early_media: '%s'",suppress_early_media?"yes":"no");
		DBG("force_one_way_early_media '%s'",force_one_way_early_media?"yes":"no");

		DBG("aleg_rel100_mode_id: %d",aleg_radius_acc_profile_id);
		DBG("bleg_rel100_mode_id: %d",bleg_radius_acc_profile_id);

		DBG("append_headers '%s'", append_headers.c_str());
		DBG("append_headers_req '%s'", append_headers_req.c_str());
		DBG("aleg_append_headers_reply '%s'", aleg_append_headers_reply.c_str());
		DBG("aleg_append_headers_req '%s'", aleg_append_headers_req.c_str());

		DBG("radius_profile_id: %d", radius_profile_id);
		DBG("aleg_radius_acc_profile_id: %d", aleg_radius_acc_profile_id);
		if(aleg_radius_acc_profile_id){
			DBG("aleg_radius_acc_rules: %d %d/%d %d",
				aleg_radius_acc_rules.enable_start_accounting,
				aleg_radius_acc_rules.enable_interim_accounting,
				aleg_radius_acc_rules.interim_accounting_interval,
				aleg_radius_acc_rules.enable_stop_accounting);
		}
		DBG("bleg_radius_acc_profile_id: %d", bleg_radius_acc_profile_id);
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
			DBG("dynamic_field['%s']: %s [%s]",
				 it->first.c_str(),
				 AmArg::print(a).c_str(),
				 a.t2str(a.getType()));
		}
	}
}

bool SqlCallProfile::readFilter(
	const AmArg &t, const char* cfg_key_filter,
	vector<FilterEntry>& filter_list, bool keep_transparent_entry,
	int failover_type_id)
{
	FilterEntry hf;

	string filter_key_type_field = string(cfg_key_filter)+"_type_id";
	string filter_list_field = string(cfg_key_filter)+"_list";

	int filter_type_id;
	filter_type_id = DbAmArg_hash_get_int(
		t,filter_key_type_field,
		FILTER_TYPE_TRANSPARENT, failover_type_id);

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
			ERROR("invalid %s type_id: %d", cfg_key_filter, filter_type_id);
			return false;
	}

	// no transparent filter
	if (!keep_transparent_entry && hf.filter_type==Transparent)
	return true;

	vector<string> elems = explode(DbAmArg_hash_get_str(t,filter_list_field),",");
	for (vector<string>::iterator it=elems.begin(); it != elems.end(); it++) {
		string c = *it;
		std::transform(c.begin(), c.end(), c.begin(), ::tolower);
		hf.filter_list.insert(c);
	}

	filter_list.push_back(hf);
	return true;
}

bool SqlCallProfile::readFilterSet(
	const AmArg &t, const char* cfg_key_filter,
	vector<FilterEntry>& filter_list)
{
	string s;
	s = DbAmArg_hash_get_str(t, cfg_key_filter);

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

bool SqlCallProfile::readCodecPrefs(const AmArg &t)
{
	/*assign_str(codec_prefs.bleg_payload_order_str,"codec_preference");
	assign_bool_str(codec_prefs.bleg_prefer_existing_payloads_str,"prefer_existing_codecs",false);

	assign_str(codec_prefs.aleg_payload_order_str,"codec_preference_aleg");
	assign_bool_str(codec_prefs.aleg_prefer_existing_payloads_str,"prefer_existing_codecs_aleg",false);*/

	static_codecs_aleg_id = DbAmArg_hash_get_int(t,"aleg_codecs_group_id",0);
	static_codecs_bleg_id = DbAmArg_hash_get_int(t,"bleg_codecs_group_id",0);

	aleg_single_codec = DbAmArg_hash_get_bool(t, "aleg_single_codec_in_200ok", false);
	bleg_single_codec = DbAmArg_hash_get_bool(t, "bleg_single_codec_in_200ok", false);
	avoid_transcoding = DbAmArg_hash_get_bool(t, "try_avoid_transcoding", false);

	return true;
}

bool SqlCallProfile::readDynFields(const AmArg &t,const DynFieldsT &df)
{
	dyn_fields.assertStruct();
	for(DynFieldsT::const_iterator it = df.begin();it!=df.end();++it) {
		dyn_fields[it->name] = t.hasMember(it->name) ? t[it->name] : AmArg();
	}
	return true;
}

bool SqlCallProfile::eval_resources(){
	try {
		lega_rl.parse(lega_res);
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
			ERROR("got call_profile with radius_profile_id set, but radius_client module is not loaded");
			return false;
		}
		if(aleg_radius_acc_profile_id){
			ERROR("got call_profile with aleg_radius_acc_profile_id set, but radius_client module is not loaded");
			return false;
		}
		if(bleg_radius_acc_profile_id){
			ERROR("got call_profile with bleg_radius_acc_profile_id set, but radius_client module is not loaded");
			return false;
		}
	}
	return true;
}

static TransProt encryption_mode2transport(int mode, bool &allow_zrtp)
{
	/*
	 * 0 - RTP_AVP
	 * 1 - UDP/TLS/RTP/SAVP
	 * 2 - UDP/TLS/RTP/SAVPF
	 * 3 - ZRTP
	 */
	allow_zrtp = false;
	switch(mode) {
		case 0: return TP_RTPAVP;
		case 1: return TP_RTPSAVP;
		case 2: return TP_UDPTLSRTPSAVP;
		case 3:
			allow_zrtp = true;
			return TP_RTPAVP;
		default: return TP_NONE;
	}
}

bool SqlCallProfile::eval_media_encryption()
{
	aleg_media_transport = encryption_mode2transport(aleg_media_encryption_mode_id, aleg_media_allow_zrtp);
	if(TP_NONE == aleg_media_transport) {
		ERROR("unexpected aleg_media_encryption_mode_id value %d", aleg_media_encryption_mode_id);
		return false;
	}

	bleg_media_transport = encryption_mode2transport(bleg_media_encryption_mode_id, bleg_media_allow_zrtp);
	if(TP_NONE == bleg_media_transport) {
		ERROR("unexpected bleg_media_encryption_mode_id value %d", bleg_media_encryption_mode_id);
		return false;
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
	case sip_transport::TCP:
	case sip_transport::TLS: {
		AmUriParser parser;
		auto transport_name = transport_str(transport_id);
		DBG("patch %s to use %.*s transport. current value is: '%s'",
			field_name,transport_name.len, transport_name.s, uri.c_str());
		parser.uri = uri;
		if(!parser.parse_uri()) {
			ERROR("Error parsing %s '%s' for protocol patching to %.*s. leave it as is",
				  field_name,uri.c_str(), transport_name.len, transport_name.s);
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
				parser.uri_param+=";transport=";
				parser.uri_param+=c2stlstr(transport_name);
				uri = parser.uri_str();
				DBG("%s patched to: '%s'",field_name,uri.c_str());
			}
		} else {
			parser.uri_param = "transport=";
			parser.uri_param+=c2stlstr(transport_name);
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

bool SqlCallProfile::eval_protocol_priority()
{
	switch(bleg_protocol_priority_id) {
	case IPv4_only:
	case IPv6_only:
	case Dualstack:
	case IPv4_pref:
	case IPv6_pref:
		return true;
	default:
		ERROR("unknown protocol priority: %d", bleg_protocol_priority_id);
	}
	return false;
}

bool SqlCallProfile::eval()
{
	if(!outbound_interface.empty())
		if(!evaluateOutboundInterface())
			return false;

	if(0!=disconnect_code_id){
		DBG("skip evals for refusing profile");
		return true;
	}

	if(registered_aor_mode_id < REGISTERED_AOR_MODE_AS_IS ||
			registered_aor_mode_id > REGISTERED_AOR_MODE_REPLACE_USERPART)
	{
		DBG("incorrect registered_aor_mode_id value. replace %d -> %d",
			registered_aor_mode_id, REGISTERED_AOR_MODE_AS_IS);
		registered_aor_mode_id = REGISTERED_AOR_MODE_AS_IS;
	}

	return
		eval_transport_ids() &&
		eval_protocol_priority() &&
		eval_resources() &&
		eval_radius() &&
		eval_media_encryption();
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
