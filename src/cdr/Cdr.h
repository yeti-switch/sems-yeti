#pragma once

#include "../SqlCallProfile.h"
#include "../resources/Resource.h"
#include "../ReasonParser.h"

#include "AmRtpStream.h"
#include "AmISUP.h"
#include "cJSON.h"
#include "ampi/PostgreSqlAPI.h"
#include "CdrBase.h"

#include <unordered_set>

extern const string cdr_statement_name;

enum UpdateAction { Start, BLegInvite, Connect, BlegConnect, End };

enum DisconnectInitiator { DisconnectByDB = 0, DisconnectByTS, DisconnectByDST, DisconnectByORG, DisconnectUndefined };
const char *DisconnectInitiator2Str(int initiator);

struct Cdr : public CdrBase
#ifdef OBJECTS_COUNTER
    ,
             ObjCounter(Cdr)
#endif
{
    bool writed;
    bool is_last;
    bool snapshoted;
    bool trusted_hdrs_gw;
    bool inserted2list;
    int  attempt_num;

    string msg_logger_path;
    int    dump_level_id;
    bool   audio_record_enabled;

    int  disconnect_internal_code_id;
    int  disconnect_initiator;
    bool disconnect_initiator_writed;

    string disconnect_reason;
    int    disconnect_code;
    bool   aleg_reason_writed;
    bool   bleg_reason_writed;

    string disconnect_internal_reason;
    int    disconnect_internal_code;

    string disconnect_rewrited_reason;
    int    disconnect_rewrited_code;

    struct timeval start_time;
    struct timeval bleg_invite_time;
    struct timeval connect_time;
    struct timeval bleg_connect_time;
    struct timeval end_time;

    struct timeval sip_10x_time;
    struct timeval sip_18x_time;
    bool           sip_early_media_present;

    string         legB_remote_ip, legB_local_ip;
    unsigned short legB_remote_port, legB_local_port, legB_transport_protocol_id;
    string         legA_remote_ip, legA_local_ip;
    unsigned short legA_remote_port, legA_local_port, legA_transport_protocol_id;

    string orig_call_id;
    string term_call_id;
    string local_tag;
    string bleg_local_tag;
    string global_tag;
    int    time_limit;

    AmArg  dyn_fields;
    string outbound_proxy;
    string ruri;

    vector<AmArg> trusted_hdrs;

    vector<AmRtpStream::MediaStats> aleg_media_stats;
    vector<AmRtpStream::MediaStats> bleg_media_stats;
    bool                            aleg_sdp_completed;
    bool                            bleg_sdp_completed;

    string resources;
    string active_resources;
    AmArg  active_resources_amarg;
    AmArg  active_resources_clickhouse;
    int    failed_resource_type_id;
    string failed_resource_id;

    std::set<string> aleg_versions;
    std::set<string> bleg_versions;

    unsigned short isup_propagation_delay;

    bool is_redirected;

    struct dtmf_event_info {
        int            event, rx_proto, tx_proto;
        struct timeval time;
        dtmf_event_info(int e, struct timeval &now, int r, int t)
            : event(e)
            , rx_proto(r)
            , tx_proto(t)
            , time(now)
        {
        }
        cJSON *serialize2json(const struct timeval *t);
    };
    std::queue<dtmf_event_info> dtmf_events_a2b;
    std::queue<dtmf_event_info> dtmf_events_b2a;

    AmArg aleg_headers_amarg;
    AmArg aleg_headers_snapshot_amarg;
    AmArg bleg_headers_amarg;
    AmArg bleg_reply_headers_amarg;
    AmArg identity_data;

    ReasonParser aleg_reasons;
    ReasonParser bleg_reasons;

    Cdr();
    // initial CDR in CallCtx::getFirstProfile
    Cdr(const SqlCallProfile &profile);
    // rerouting/failover CDRs in CallCtx::getNextProfile, SBCCallLeg::onRedisReply
    Cdr(const Cdr &cdr, const SqlCallProfile &profile);
    // std::queue::emplace(construct_at) in CdrList::onSessionFinalize
    Cdr(const Cdr &cdr) = default;

    ~Cdr();

    // void init();

    void update_sql(const SqlCallProfile &profile);
    void update_sbc(const SBCCallProfile &profile);

    void update_with_aleg_sip_request(const AmSipRequest &req);
    void update_with_bleg_sip_request(const AmSipRequest &req);
    void update_with_bleg_sip_reply(const AmSipReply &reply);
    void update_reasons_with_sip_request(const AmSipRequest &req, bool a_leg);
    void update_with_isup(const AmISUP &isup);

    void update_init_aleg(const string &leg_local_tag, const string &leg_global_tag, const string &leg_orig_call_id);
    void update_init_bleg(const string &leg_term_call_id, const string &leg_local_tag);

    void update_with_action(UpdateAction act);

    void update_with_resource_list(const SqlCallProfile &profile);
    void update_failed_resource(const Resource &r);

    void add_dtmf_event(bool aleg, int event, struct timeval &now, int rx_proto, int tx_proto);

    void set_start_time(const timeval &t);

    void update_bleg_reason(const string &reason, int code);
    void update_aleg_reason(const string &reason, int code);
    void update_internal_reason(DisconnectInitiator initiator, const string &reason, unsigned int code,
                                unsigned int internal_code_id);

    void setSuppress(bool s);

    void replace(string & s, const string &from, const string &to);

    void setSdpCompleted(bool a_leg);

    void apply_params(QueryInfo & query_info, const DynFieldsT &df);

    // serializators
    char *serialize_rtp_stats();
    char *serialize_media_stats();
    void  serialize_media_stats(cJSON * j, const string &local_tag, AmRtpStream::MediaStats &m);

    char *serialize_timers_data();
    char *serialize_dtmf_events();
    char *serialize_dynamic(const DynFieldsT &df);
    char *serialize_versions() const;

    void add_versions_to_amarg(AmArg & arg) const;

    void snapshot_info(AmArg & s, const DynFieldsT &df) const;
    void snapshot_info_filtered(AmArg & s, const DynFieldsT &df, const unordered_set<string> &wanted_fields) const;

    void serialize_for_http_common(AmArg & a, const DynFieldsT &df) const;
    void serialize_for_http_connected(AmArg & a) const;
    void serialize_for_http_disconnected(AmArg & a) const;

    void info(AmArg & s) override;
};
