#ifndef CDR_H
#define CDR_H
#include "time.h"

#include "../SqlCallProfile.h"
//#include "../SBCCallLeg.h"
#include "../resources/Resource.h"
#include "AmRtpStream.h"
#include "AmISUP.h"
#include "cJSON.h"
#include <pqxx/pqxx>

enum UpdateAction {
	Start,
	BLegInvite,
    Connect,
    BlegConnect,
    End,
    Write
};

enum DisconnectInitiator {
    DisconnectByDB = 0,
    DisconnectByTS,
    DisconnectByDST,
    DisconnectByORG,
    DisconnectUndefined
};
const char *DisconnectInitiator2Str(int initiator);

struct Cdr: public
	AmMutex
{
    bool writed;
    bool suppress;
	bool trusted_hdrs_gw;
	bool inserted2list;
	int attempt_num;
	bool is_last;

	string msg_logger_path;
	int dump_level_id;
	bool audio_record_enabled;

    int disconnect_initiator;
	bool disconnect_initiator_writed;

    string disconnect_reason;
    int disconnect_code;
	bool aleg_reason_writed;
    bool bleg_reason_writed;

	string disconnect_internal_reason;
	int disconnect_internal_code;

	string disconnect_rewrited_reason;
	int disconnect_rewrited_code;

    struct timeval cdr_born_time;
    struct timeval start_time;
	struct timeval bleg_invite_time;
    struct timeval connect_time;
    struct timeval bleg_connect_time;
    struct timeval end_time;

	struct timeval sip_10x_time;
	struct timeval sip_18x_time;
	bool sip_early_media_present;

    string legB_remote_ip, legB_local_ip;
    unsigned short legB_remote_port, legB_local_port,
                   legB_transport_protocol_id;
    string legA_remote_ip, legA_local_ip;
    unsigned short legA_remote_port, legA_local_port,
                   legA_transport_protocol_id;

    string orig_call_id;
    string term_call_id;
    string local_tag;
	string global_tag;
    int time_limit;

    AmArg dyn_fields;
    string outbound_proxy;

	vector<AmArg> trusted_hdrs;

	AmRtpStream::PayloadsHistory legA_payloads;
	AmRtpStream::PayloadsHistory legB_payloads;

	AmRtpStream::ErrorsStats legA_stream_errors;
	AmRtpStream::ErrorsStats legB_stream_errors;

	unsigned long legA_bytes_recvd, legB_bytes_recvd;
	unsigned long legA_bytes_sent, legB_bytes_sent;

	string resources;
	string active_resources;
	AmArg active_resources_amarg;
	int failed_resource_type_id;
	int failed_resource_id;

	unsigned short isup_propagation_delay;

	struct dtmf_event_info {
		int event, rx_proto,tx_proto;
		struct timeval time;
		dtmf_event_info(int e,struct timeval &now, int r, int t):
			event(e), time(now), rx_proto(r), tx_proto(t) {}
		cJSON *serialize2json(const struct timeval *t);
	};
	std::queue<dtmf_event_info> dtmf_events_a2b;
	std::queue<dtmf_event_info> dtmf_events_b2a;

	Cdr();
	Cdr(const Cdr& cdr,const SqlCallProfile &profile);
    Cdr(const SqlCallProfile &profile);
    ~Cdr();

    void init();
	void update_sql(const SqlCallProfile &profile);
	void update_sbc(const SBCCallProfile &profile);
	void update(const AmSipRequest &req);
	void update(const AmISUP &isup);
	void update(const AmSipReply &reply);
	void update_init_aleg(const string &leg_local_tag, const string &leg_global_tag, const string &leg_orig_call_id);
	void update_init_bleg(const string &leg_term_call_id);
	void update(UpdateAction act);
	void update(const ResourceList &rl);
	void update_failed_resource(const Resource &r);
	void add_dtmf_event(bool aleg, int event, struct timeval &now, int rx_proto, int tx_proto);
	void set_start_time(const timeval &t);
    void update_bleg_reason(string reason, int code);
    void update_aleg_reason(string reason, int code);
    void update_internal_reason(DisconnectInitiator initiator,string reason, int code);
    void setSuppress(bool s);
	void replace(ParamReplacerCtx &ctx,const AmSipRequest &req);
	void replace(string& s, const string& from, const string& to);
    void refuse(const SBCCallProfile &profile);
	void refuse(int code, string reason);

	void invoc(pqxx::prepare::invocation &invoc,
			   AmArg &invoced_values,
			   const DynFieldsT &df,
			   bool serialize_dynamic_fields);
	void to_csv_stream(ofstream &s, const DynFieldsT &df);
    //serializators
    char *serialize_rtp_stats();
	char *serialize_timers_data();
	char *serialize_dtmf_events();
	char *serialize_dynamic(const DynFieldsT &df);

	void info(AmArg &s);
};

#endif // CDR_H
