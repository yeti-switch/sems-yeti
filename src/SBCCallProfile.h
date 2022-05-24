/*
 * Copyright (C) 2010-2011 Stefan Sayer
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * For a license to use the SEMS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * SEMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _SBCCallProfile_h
#define _SBCCallProfile_h

#include "AmConfigReader.h"
#include "HeaderFilter.h"
#include "ampi/UACAuthAPI.h"
#include "ParamReplacer.h"
#include "atomic_types.h"
#include "sip/msg_logger.h"
#include "ampi/RadiusClientAPI.h"
#include "sip/resolver.h"
#include "sip/types.h"

#include <set>
#include <string>
#include <map>
#include <list>

using std::string;
using std::map;
using std::set;
using std::pair;

class PlaceholdersHash: public std::map<string,string>
{
  public:
    void update(const PlaceholdersHash &h);
};

#define DTMF_RX_MODE_RFC2833			0x1		// telephone-event RTP payload
#define DTMF_RX_MODE_INFO				0x2		// SIP INFO msg
#define DTMF_RX_MODE_INBAND 			0x4		// inband dtmf

#define DTMF_TX_MODE_DISABLED			0x0		// avoid sending
#define DTMF_TX_MODE_RFC2833			0x1		// telephone-event RTP payload
#define DTMF_TX_MODE_INFO_DTMF_RELAY	0x2		// application/dtmf-relay
#define DTMF_TX_MODE_INFO_DTMF			0x4		// application/dtmf
#define DTMF_TX_MODE_INBAND     		0x8		// inband dtmf

#define DTMF_RX_MODE_ALL	(DTMF_RX_MODE_RFC2833|DTMF_RX_MODE_INFO|DTMF_RX_MODE_INBAND)

template <class T>
class ref_counted_ptr
{
  private:
    T *ptr;

  public:
    void reset(T *p) { if (ptr) dec_ref(ptr); ptr = p; if (ptr) inc_ref(ptr); }
    T *get() const { return ptr; }

    ref_counted_ptr(): ptr(0) { }
    ~ref_counted_ptr() { if (ptr) dec_ref(ptr); }

    ref_counted_ptr(const ref_counted_ptr &other): ptr(other.ptr) { if (ptr) inc_ref(ptr); }
    ref_counted_ptr &operator=(const ref_counted_ptr &other) { reset(other.ptr); return *this; }

};

class PayloadDesc {
  protected:
    std::string name;
    unsigned clock_rate; // 0 means "doesn't matter"

  public:
    bool match(const SdpPayload &p) const;
    std::string print() const;
    bool operator==(const PayloadDesc &other) const;

    /* FIXME: really want all of this?
     * reads from format: name/clock_rate, nothing need to be set
     * for example: 
     *	  PCMU
     *	  bla/48000
     *	  /48000
     * */
    bool read(const std::string &s);
};

typedef pair<unsigned int, std::string> ReplyCodeReasonPair;
typedef map<unsigned int, ReplyCodeReasonPair> ReplyTranslationMap;

struct SBCCallProfile
  : public AmObject {
  string md5hash;
  //string profile_file;

  string ruri;       /* updated if set */
  string ruri_host;  /* updated if set */
  string from;       /* updated if set */
  string to;         /* updated if set */

  unsigned int bleg_transport_id;
  unsigned int bleg_protocol_priority_id;

  PlaceholdersHash placeholders_hash;

  string callid;

  string dlg_contact_params;
  string bleg_dlg_contact_params;

  bool dlg_nat_handling;
  bool keep_vias;
  bool bleg_keep_vias;

  string outbound_proxy;
  bool force_outbound_proxy;
  unsigned int outbound_proxy_transport_id;

  string route;

  string aleg_outbound_proxy;
  bool aleg_force_outbound_proxy;
  unsigned int aleg_outbound_proxy_transport_id;

  string next_hop;
  bool next_hop_1st_req;
  bool patch_ruri_next_hop;
  bool next_hop_fixed;

  string aleg_next_hop;

  bool aleg_rtp_ping;
  bool bleg_rtp_ping;

  int aleg_conn_location_id;
  int bleg_conn_location_id;

  unsigned int dead_rtp_time;

  bool allow_1xx_without_to_tag;

  int aleg_sensor_id, bleg_sensor_id;
  int aleg_sensor_level_id, bleg_sensor_level_id;

  int aleg_dtmf_recv_modes, bleg_dtmf_recv_modes;
  int aleg_dtmf_send_mode_id, bleg_dtmf_send_mode_id;

  int aleg_rel100_mode_id;
  int bleg_rel100_mode_id;

  int radius_profile_id;
  int aleg_radius_acc_profile_id;
  int bleg_radius_acc_profile_id;
  RadiusAccountingRules aleg_radius_acc_rules;
  RadiusAccountingRules bleg_radius_acc_rules;

  bool suppress_early_media;
  bool force_one_way_early_media;

  vector<FilterEntry> headerfilter_a2b;
  vector<FilterEntry> headerfilter_b2a;

  vector<FilterEntry> sdpfilter;
  vector<FilterEntry> sdpalinesfilter;
  vector<FilterEntry> bleg_sdpalinesfilter;
  vector<FilterEntry> mediafilter;

  bool aleg_relay_prack,bleg_relay_prack;
  bool aleg_relay_reinvite,bleg_relay_reinvite;
  bool aleg_relay_hold, bleg_relay_hold;
  bool relay_timestamp_aligning;

  string resource_handler;

  int static_codecs_aleg_id;
  int static_codecs_bleg_id;
  bool aleg_single_codec;
  bool bleg_single_codec;
  bool avoid_transcoding;

  bool aleg_relay_options;
  bool bleg_relay_options;

  bool aleg_relay_update;
  bool bleg_relay_update;

  bool filter_noaudio_streams;
  bool force_relay_CN;

  string sst_enabled;
  bool sst_enabled_value;
  string sst_aleg_enabled;
  AmConfigReader sst_a_cfg;    // SST config (A leg)
  AmConfigReader sst_b_cfg;    // SST config (B leg)

  bool auth_enabled;
  UACAuthCred auth_credentials;

  bool auth_aleg_enabled;
  UACAuthCred auth_aleg_credentials;

  ReplyTranslationMap reply_translations;

  string append_headers;
  string append_headers_req;
  string aleg_append_headers_req;
  string aleg_append_headers_reply;

  string refuse_with;

  bool rtprelay_enabled;
  string force_symmetric_rtp;
  string aleg_force_symmetric_rtp;
  bool force_symmetric_rtp_value;
  bool aleg_force_symmetric_rtp_value;

  bool aleg_symmetric_rtp_nonstop;
  bool bleg_symmetric_rtp_nonstop;

  bool rtprelay_dtmf_filtering;
  bool rtprelay_dtmf_detection;
  bool rtprelay_force_dtmf_relay;

  //wether to filter inbound dtmf in direction A->B
  bool aleg_rtp_filter_inband_dtmf;
  //whether to filter inbound dtmf in direction B->A
  bool bleg_rtp_filter_inband_dtmf;

  bool force_transcoding;

  string rtprelay_interface;
  int rtprelay_interface_value;
  string aleg_rtprelay_interface;
  int aleg_rtprelay_interface_value;

  int rtprelay_bw_limit_rate;
  int rtprelay_bw_limit_peak;

  list<::atomic_int*> aleg_rtp_counters;
  list<::atomic_int*> bleg_rtp_counters;

  string outbound_interface;
  int outbound_interface_value;

  string aleg_outbound_interface;
  int aleg_outbound_interface_value;

  int ringing_timeout;
  unsigned int inv_transaction_timeout;
  unsigned int inv_srv_failover_timeout;

  string global_tag;

  bool record_audio;
  string audio_record_path;

  int fake_ringing_timeout;

  unsigned int bleg_max_30x_redirects;
  unsigned int bleg_max_transfers;

  bool auth_required;

  int registered_aor_id;
  int skip_code_id;

  int aleg_media_encryption_mode_id;
  int bleg_media_encryption_mode_id;

  TransProt aleg_media_transport;
  bool  aleg_media_allow_zrtp;

  TransProt bleg_media_transport;
  bool  bleg_media_allow_zrtp;

  std::vector<AmSubnet> aleg_rtp_acl;
  std::vector<AmSubnet> bleg_rtp_acl;

  struct TranscoderSettings {
    enum { DTMFAlways, DTMFNever } dtmf_mode;

    bool enabled;
    bool evaluate(ParamReplacerCtx& ctx, const AmSipRequest& req);

    bool readConfig(AmConfigReader &cfg);
    void infoPrint() const;
    bool operator==(const TranscoderSettings& rhs) const;
    string print() const;

    bool isActive() { return enabled; }
	TranscoderSettings(): enabled(true) { }
  } transcoder;

  // hold settings
  class HoldSettings {
    public:
        enum Activity { sendrecv, sendonly, recvonly, inactive };

    private:
      struct HoldParams {
        // non-replaced params
        string mark_zero_connection_str, activity_str, alter_b2b_str;

        bool mark_zero_connection;
        Activity activity;
        bool alter_b2b; // transform B2B hold requests (not locally generated ones)

        bool setActivity(const string &s);
        HoldParams(): mark_zero_connection(false), activity(sendonly), alter_b2b(false) { }
      } aleg, bleg;

    public:
      bool mark_zero_connection(bool a_leg) { return a_leg ? aleg.mark_zero_connection : bleg.mark_zero_connection; }
      Activity activity(bool a_leg) { return a_leg ? aleg.activity : bleg.activity; }
      const string &activity_str(bool a_leg) { return a_leg ? aleg.activity_str : bleg.activity_str; }
      bool alter_b2b(bool a_leg) { return a_leg ? aleg.alter_b2b : bleg.alter_b2b; }

      void readConfig(AmConfigReader &cfg);
      bool evaluate(ParamReplacerCtx& ctx, const AmSipRequest& req);
  } hold_settings;

 private:
  // message logging feature
  string msg_logger_path;
  ref_counted_ptr<msg_logger> logger;

  void create_logger(const AmSipRequest& req);

 public:
  bool log_rtp;
  bool log_sip;
  bool has_logger() { return logger.get() != NULL; }
  msg_logger* get_logger(const AmSipRequest& req);
  void set_logger_path(const std::string path) { msg_logger_path = path; }
  const string &get_logger_path() const { return msg_logger_path; }

  SBCCallProfile()
  : auth_enabled(false),
    bleg_transport_id(0),
    bleg_protocol_priority_id(dns_priority::IPv4_only),
    outbound_proxy_transport_id(0),
    aleg_outbound_proxy_transport_id(0),
    dlg_nat_handling(false),
    keep_vias(false),bleg_keep_vias(false),
    sst_enabled_value(false),
    rtprelay_enabled(false),
    force_symmetric_rtp_value(false),
    aleg_force_symmetric_rtp_value(false),
    rtprelay_interface_value(-1),
    aleg_rtprelay_interface_value(-1),
    rtprelay_bw_limit_rate(-1),
    rtprelay_bw_limit_peak(-1),
    outbound_interface_value(-1),
    log_rtp(false),
    log_sip(false),
    patch_ruri_next_hop(false),
    next_hop_1st_req(false),
	next_hop_fixed(false),
	ringing_timeout(0),
	relay_timestamp_aligning(false),
	aleg_relay_hold(true),
	bleg_relay_hold(true),
	aleg_relay_prack(false),
	bleg_relay_prack(false),
	aleg_relay_reinvite(true),
	bleg_relay_reinvite(true),
	allow_1xx_without_to_tag(false),
	inv_srv_failover_timeout(0),
	force_relay_CN(false),
	inv_transaction_timeout(0),
	aleg_sensor_id(-1), bleg_sensor_id(-1),
	aleg_sensor_level_id(0), bleg_sensor_level_id(0),
	aleg_dtmf_send_mode_id(DTMF_RX_MODE_RFC2833),
	bleg_dtmf_send_mode_id(DTMF_RX_MODE_RFC2833),
	aleg_dtmf_recv_modes(DTMF_RX_MODE_ALL),
	bleg_dtmf_recv_modes(DTMF_RX_MODE_ALL),
	force_one_way_early_media(false),
	suppress_early_media(false),
	aleg_rel100_mode_id(-1),
	bleg_rel100_mode_id(-1),
	radius_profile_id(0),
	aleg_radius_acc_profile_id(0),
	bleg_radius_acc_profile_id(0),
	fake_ringing_timeout(0),
	bleg_max_30x_redirects(0),
	bleg_max_transfers(0),
	auth_required(false),
	registered_aor_id(0),
	skip_code_id(0),
	force_transcoding(false),
    aleg_media_encryption_mode_id(0),
    aleg_media_allow_zrtp(false),
    bleg_media_encryption_mode_id(0),
    bleg_media_allow_zrtp(false)
  { }

  bool operator==(const SBCCallProfile& rhs) const;
  string print() const;

#if 0
  int refuse(ParamReplacerCtx& ctx, const AmSipRequest& req) const;
#endif

  int apply_a_routing(ParamReplacerCtx& ctx,
		      const AmSipRequest& req,
		      AmBasicSipDialog& dlg) const;
  
  int apply_b_routing(ParamReplacerCtx& ctx,
		      const AmSipRequest& req,
		      AmBasicSipDialog& dlg) const;

  int apply_common_fields(ParamReplacerCtx& ctx,
			  AmSipRequest& req) const;

  bool evaluateOutboundInterface();

  bool evaluate(ParamReplacerCtx& ctx,
		const AmSipRequest& req);

  bool evaluateRTPRelayInterface();
  bool evaluateRTPRelayAlegInterface();

  void eval_sst_config(ParamReplacerCtx& ctx,
		       const AmSipRequest& req,
		       AmConfigReader& sst_cfg);

  void fix_append_hdrs(ParamReplacerCtx& ctx, const AmSipRequest& req);

};

#endif // _SBCCallProfile_h
