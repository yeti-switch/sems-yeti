#ifndef CDR_H
#define CDR_H

#include "time.h"
#include "../SqlCallProfile.h"
#include "../resources/Resource.h"
#include "AmRtpStream.h"
#include "AmISUP.h"
#include "cJSON.h"
#include <pqxx/pqxx>
#include <unordered_set>

#include "CdrBase.h"

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

struct Cdr
  : public CdrBase,
    public AmMutex
{
    bool writed;
    bool is_last;
    bool snapshoted;
    bool trusted_hdrs_gw;
    bool inserted2list;
    int attempt_num;

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
    string bleg_local_tag;
    string global_tag;
    int time_limit;

    AmArg dyn_fields;
    string outbound_proxy;
    string ruri;

    vector<AmArg> trusted_hdrs;

    AmRtpStream::MediaStats aleg_media_stats;
    AmRtpStream::MediaStats bleg_media_stats;

    string resources;
    string active_resources;
    AmArg active_resources_amarg;
    AmArg active_resources_clickhouse;
    int failed_resource_type_id;
    int failed_resource_id;

    std::set<string> aleg_versions;
    std::set<string> bleg_versions;

    unsigned short isup_propagation_delay;

    bool is_redirected;

    struct dtmf_event_info {
        int event, rx_proto,tx_proto;
        struct timeval time;
        dtmf_event_info(int e,struct timeval &now, int r, int t)
          : event(e),
            time(now),
            rx_proto(r),
            tx_proto(t)
        {}
        cJSON *serialize2json(const struct timeval *t);
    };
    std::queue<dtmf_event_info> dtmf_events_a2b;
    std::queue<dtmf_event_info> dtmf_events_b2a;

    Cdr();
    Cdr(const Cdr& cdr,const SqlCallProfile &profile);
    Cdr(const Cdr& cdr);
    Cdr(const SqlCallProfile &profile);
    ~Cdr();

    //void init();

    void update_sql(const SqlCallProfile &profile);
    void update_sbc(const SBCCallProfile &profile);
    void update(const AmSipRequest &req);
    void update(const AmISUP &isup);
    void update(const AmSipReply &reply);
    void update_init_aleg(const string &leg_local_tag, const string &leg_global_tag, const string &leg_orig_call_id);
    void update_init_bleg(const string &leg_term_call_id, const string &leg_local_tag);
    void update(UpdateAction act);
    void update(const ResourceList &rl);
    void update_failed_resource(const Resource &r);
    void add_dtmf_event(bool aleg, int event, struct timeval &now, int rx_proto, int tx_proto);
    void set_start_time(const timeval &t);
    void update_bleg_reason(string reason, int code);
    void update_aleg_reason(string reason, int code);
    void update_internal_reason(DisconnectInitiator initiator,string reason, unsigned int code);
    void setSuppress(bool s);
    void replace(ParamReplacerCtx &ctx,const AmSipRequest &req);
    void replace(string& s, const string& from, const string& to);
    void refuse(const SBCCallProfile &profile);
    void refuse(int code, string reason);

    pqxx::prepare::invocation get_invocation(cdr_transaction &tnx) override;
    void invoc(pqxx::prepare::invocation &invoc,
               const DynFieldsT &df,
               bool serialize_dynamic_fields) override;
    void to_csv_stream(ofstream &s, const DynFieldsT &df) override;

    //serializators
    char *serialize_rtp_stats();
    char *serialize_media_stats();
    void serialize_media_stats(cJSON *j, const string &local_tag, AmRtpStream::MediaStats &m);

    char *serialize_timers_data();
    char *serialize_dtmf_events();
    char *serialize_dynamic(const DynFieldsT &df);
    char *serialize_versions() const;

    void add_versions_to_amarg(AmArg &arg) const;
    void snapshot_info(AmArg &s, const DynFieldsT &df) const;
    void snapshot_info_filtered(AmArg &s, const DynFieldsT &df, const unordered_set<string> &wanted_fields) const;
    void info(AmArg &s) override;
};

#endif // CDR_H
