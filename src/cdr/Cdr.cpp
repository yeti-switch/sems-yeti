#include "Cdr.h"
#include "AmUtils.h"
#include "AmSipMsg.h"
#include "log.h"
#include "CoreRpc.h"
#include "jsonArg.h"
#include "sip/defs.h"
#include "sems.h"
#include "yeti_version.h"
#include "../RTPParameters.h"
#include "../yeti.h"

#include <stdio.h>
//#include <float.h>
#include <type_traits>

#define DTMF_EVENTS_MAX 50

#define timeriseq(a,b) \
    (((a).tv_sec == (b).tv_sec) && ((a).tv_usec == (b).tv_usec))

const string cdr_statement_name("writecdr");

static string user_agent_hdr(SIP_HDR_USER_AGENT);
static string server_hdr(SIP_HDR_SERVER);

static const char *updateAction2str(UpdateAction act)
{
    switch(act) {
        case Start: return "Start";
        case BLegInvite: return "BlegInvite";
        case Connect: return "Connect";
        case BlegConnect: return "BlegConnect";
        case End: return "End";
        default: return "Unknown";
    }
}

const char *DisconnectInitiator2Str(int initiator)
{
    static const char *DisconnectInitiatorStr[] = {
        "Database",
        "TrafficSwitch",
        "Destination",
        "Originator",
        "Undefined"
    };
    if(initiator < 0 || initiator > DisconnectUndefined){
        return "Invalid";
    }
    return DisconnectInitiatorStr[initiator];
}

Cdr::Cdr()
  : CdrBase(CdrBase::Call),
    writed(false),
    snapshoted(false),
    trusted_hdrs_gw(false),
    inserted2list(false),
    attempt_num(1),
    dump_level_id(0),
    audio_record_enabled(false),
    disconnect_internal_code_id(0),
    disconnect_initiator(DisconnectUndefined),
    disconnect_initiator_writed(false),
    disconnect_code(0),
    aleg_reason_writed(false),
    bleg_reason_writed(false),
    disconnect_internal_reason("Unhandled sequence"),
    disconnect_internal_code(0),
    disconnect_rewrited_code(0),
    sip_early_media_present(false),
    legB_remote_port(0),
    legB_local_port(0),
    legB_transport_protocol_id(0),
    legA_remote_port(0),
    legA_local_port(0),
    legA_transport_protocol_id(0),
    time_limit(0),
    aleg_sdp_completed(false),
    bleg_sdp_completed(false),
    active_resources("[]"),
    failed_resource_type_id(-1),
    failed_resource_id(-1),
    isup_propagation_delay(0),
    is_redirected(false)
{
    DBG("Cdr[%p]()",this);

    timerclear(&start_time);
    timerclear(&bleg_invite_time);
    timerclear(&connect_time);
    timerclear(&bleg_connect_time);
    timerclear(&end_time);
    timerclear(&sip_10x_time);
    timerclear(&sip_18x_time);

    //TrustedHeaders::instance()->init_hdrs(trusted_hdrs);

    active_resources_amarg.assertArray();
    active_resources_clickhouse.assertStruct();
    bleg_reply_headers_amarg.assertStruct();
    identity_data.assertArray();
    dyn_fields.assertStruct();
}

Cdr::Cdr(const SqlCallProfile &profile)
  : Cdr()
{
    DBG("Cdr[%p](profile = %p)", this, &profile);

    update_sql(profile);
}

Cdr::Cdr(const Cdr& cdr, const SqlCallProfile &profile)
  : Cdr(profile)
{
    DBG("Cdr[%p](cdr = %p, profile = %p)", this, &cdr, &profile);

    attempt_num = cdr.attempt_num+1;
    end_time = start_time = cdr.start_time;

    legA_remote_ip = cdr.legA_remote_ip;
    legA_remote_port = cdr.legA_remote_port;
    legA_local_ip = cdr.legA_local_ip;
    legA_local_port = cdr.legA_local_port;

    orig_call_id = cdr.orig_call_id;
    local_tag = cdr.local_tag;
    global_tag = cdr.global_tag;
    aleg_versions = cdr.aleg_versions;

    msg_logger_path = cdr.msg_logger_path;
    dump_level_id = cdr.dump_level_id;
    legA_transport_protocol_id = cdr.legA_transport_protocol_id;

    aleg_headers_amarg = cdr.aleg_headers_amarg;
    identity_data = cdr.identity_data;

    audio_record_enabled = cdr.audio_record_enabled;
}

Cdr::~Cdr()
{
    DBG("~Cdr[%p]()",this);
}

void Cdr::replace(string& s, const string& from, const string& to)
{
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != string::npos) {
        s.replace(pos, from.length(), to);
        pos += s.length();
    }
}

void Cdr::update_sql(const SqlCallProfile &profile)
{
    DBG("Cdr::%s(SqlCallProfile)",FUNC_NAME);

    trusted_hdrs_gw = profile.trusted_hdrs_gw;
    outbound_proxy = profile.route;
    ruri = profile.ruri;
    dyn_fields = profile.dyn_fields;
    time_limit = profile.time_limit;
    dump_level_id = profile.dump_level_id;
    resources = profile.resources;
}

void Cdr::update_sbc(const SBCCallProfile &profile)
{
    DBG("Cdr::%s(SBCCallProfile)",FUNC_NAME);
    msg_logger_path = profile.get_logger_path();
    audio_record_enabled = profile.record_audio;
}

void Cdr::update_with_aleg_sip_request(const AmSipRequest &req)
{
    size_t pos1,pos2,pos;

    DBG("Cdr::%s(AmSipRequest)",FUNC_NAME);

    if(writed) return;

    legA_transport_protocol_id = req.transport_id;
    legA_remote_ip = req.remote_ip;
    legA_remote_port = req.remote_port;
    legA_local_ip = req.local_ip;
    legA_local_port = req.local_port;
    orig_call_id=req.callid;

    if(findHeader(req.hdrs,user_agent_hdr,0,pos1,pos2,pos))
        aleg_versions.emplace(req.hdrs.substr(pos1,pos2-pos1));

    if(findHeader(req.hdrs,server_hdr,0,pos1,pos2,pos))
        aleg_versions.emplace(req.hdrs.substr(pos1,pos2-pos1));

    if(req.method==SIP_METH_INVITE) {
        const AmMimeBody *body = req.body.hasContentType(SIP_APPLICATION_ISUP);
        if(body){
            AmISUP isup;
            if(0==isup.parse(body)){
                update_with_isup(isup);
            }
        }
        aleg_headers_amarg =
            Yeti::instance().config.aleg_cdr_headers.serialize_headers(req.hdrs);
    }
}

inline void remove_ipv6_reference_inplace(string &s)
{
    //detect ipv6 reference
    if(s.size() < 4) {
        //minimal ref is "[::]"
        return;
    }

    if(s.front() == '[' && s.back() == ']') {
        s.pop_back();
        s.erase(s.begin());
    }
}

void Cdr::update_with_bleg_sip_reply(const AmSipReply &reply)
{
    size_t pos1,pos2,pos;

    DBG("Cdr::%s(AmSipReply)",FUNC_NAME);

    if(writed) return;

    if(reply.code == 200 && trusted_hdrs_gw){ //try to fill trusted headers from 200 OK reply
        //TrustedHeaders::instance()->parse_reply_hdrs(reply,trusted_hdrs);
        bleg_reply_headers_amarg = Yeti::instance().config.bleg_reply_cdr_headers.serialize_headers(reply.hdrs);
    }

    legB_transport_protocol_id = reply.transport_id;

    if(reply.remote_port==0) {
        return; //local reply
    }

    if(reply.code >= 300) {
        bleg_reasons.parse_headers(reply.hdrs);
    }

    legB_remote_ip = reply.remote_ip;
    legB_remote_port = reply.remote_port;

    legB_local_ip = reply.actual_ip;
    remove_ipv6_reference_inplace(legB_local_ip);
    legB_local_port = reply.actual_port;

    if(findHeader(reply.hdrs,server_hdr,0,pos1,pos2,pos))
        bleg_versions.emplace(reply.hdrs.substr(pos1,pos2-pos1));

    if(findHeader(reply.hdrs,user_agent_hdr,0,pos1,pos2,pos))
        bleg_versions.emplace(reply.hdrs.substr(pos1,pos2-pos1));


    if(reply.code>=100) {
        if(reply.code<110) { //10x codes
            if(!timerisset(&sip_10x_time)){
                gettimeofday(&sip_10x_time,NULL);
            }
        } else if(reply.code>=180 && reply.code<190) { //18x codes
            if(!timerisset(&sip_18x_time)) {
                gettimeofday(&sip_18x_time,NULL);
            }
            if(NULL!=reply.body.hasContentType(SIP_APPLICATION_SDP)){ //18x with SDP
                sip_early_media_present = true;
            }
        }
    }
}

void Cdr::update_reasons_with_sip_request(const AmSipRequest &req, bool a_leg)
{
    auto &reasons = a_leg ? aleg_reasons : bleg_reasons;
    reasons.parse_headers(req.hdrs);
}

void Cdr::update_with_isup(const AmISUP &isup)
{
    DBG("Cdr::%s(AmISUP)",FUNC_NAME);
    isup_propagation_delay = isup.propagation_delay;
}

void Cdr::update_init_aleg(
    const string &leg_local_tag,
    const string &leg_global_tag,
    const string &leg_orig_call_id)
{
    if(writed) return;

    local_tag = leg_local_tag;
    global_tag = leg_global_tag;
    orig_call_id = leg_orig_call_id;
}

void Cdr::update_init_bleg(
    const string &leg_term_call_id,
    const string &leg_local_tag)
{
    if(writed) return;

    term_call_id = leg_term_call_id;
    bleg_local_tag = leg_local_tag;
}

void Cdr::update_with_action(UpdateAction act)
{
    DBG("Cdr::%s(act = %s)",FUNC_NAME,updateAction2str(act));
    if(writed) return;

    switch(act) {
    case Start:
        gettimeofday(&start_time, NULL);
        end_time = start_time;
        break;
    case BLegInvite:
        if(!timerisset(&bleg_invite_time))
            gettimeofday(&bleg_invite_time, NULL);
        break;
    case Connect:
        if(timeriseq(start_time,end_time)) {
            gettimeofday(&connect_time, NULL);
        } else {
            WARN("%s: attempt to set connect_time after the end_time",
                  local_tag.data());
        }
        break;
    case BlegConnect:
        gettimeofday(&bleg_connect_time, NULL);
        break;
    case End:
        if(timeriseq(start_time,end_time))
            gettimeofday(&end_time, NULL);
        break;
    }
}

void Cdr::update_with_resource_list(const SqlCallProfile &profile)
{
    active_resources_amarg.clear();
    active_resources_clickhouse.clear();

    active_resources_clickhouse.assertStruct();

    cJSON *j = cJSON_CreateArray();

    auto serialize_resource = [this, j](const Resource &r) {
        if(!r.active) return;

        active_resources_amarg.push(AmArg());
        AmArg &a = active_resources_amarg.back();

        string clickhouse_key_prefix = "active_resource_" + int2str(r.type);

        AmArg &id_arg = active_resources_clickhouse[clickhouse_key_prefix + "_id"];
        if(isArgUndef(id_arg)) id_arg = r.id;

        AmArg &limit_arg = active_resources_clickhouse[clickhouse_key_prefix + "_limit"];
        if(isArgUndef(limit_arg)) limit_arg = r.limit;

        AmArg &used_arg = active_resources_clickhouse[clickhouse_key_prefix + "_used"];
        if(isArgUndef(used_arg)) used_arg = r.takes;

        cJSON *i = cJSON_CreateObject();

        cJSON_AddNumberToObject(i,"type",r.type);
        a["type"] = r.type;
        cJSON_AddNumberToObject(i,"id",r.id);
        a["id"] = r.id;
        cJSON_AddNumberToObject(i,"takes",r.takes);
        a["takes"] = r.takes;
        cJSON_AddNumberToObject(i,"limit",r.limit);
        a["limit"] = r.limit;

        cJSON_AddItemToArray(j,i);
    };

    std::for_each(profile.lega_rl.begin(), profile.lega_rl.end(), serialize_resource);
    std::for_each(profile.rl.begin(), profile.rl.end(), serialize_resource);

    char *s = cJSON_PrintUnformatted(j);
    active_resources = s;
    free(s);

    cJSON_Delete(j);
}

void Cdr::update_failed_resource(const Resource &r)
{
    failed_resource_type_id = r.type;
    failed_resource_id = r.id;
}

void Cdr::set_start_time(const timeval &t)
{
    end_time = start_time = t;
}

void Cdr::update_bleg_reason(string reason, int code)
{
    DBG("Cdr::%s(reason = '%s',code = %d)",FUNC_NAME,
        reason.c_str(),code);

    if(writed) return;

    if(bleg_reason_writed) return;

    disconnect_reason = reason;
    disconnect_code = code;
    bleg_reason_writed = true;
}

void Cdr::update_aleg_reason(string reason, int code)
{
    DBG("Cdr::%s(reason = '%s',code = %d)",FUNC_NAME,
        reason.c_str(),code);

    if(writed) return;

    disconnect_rewrited_reason = reason;
    disconnect_rewrited_code = code;
    aleg_reason_writed = true;
}

void Cdr::update_internal_reason(
    DisconnectInitiator initiator,
    string reason, unsigned int code,
    unsigned int internal_code_id)
{
    DBG("Cdr[%p]::%s(initiator = %d,reason = '%s',code = %d) cdr.disconnect_initiator_writed = %d",
        this,FUNC_NAME,initiator,reason.c_str(),code,disconnect_initiator_writed);

    if(writed) return;

    update_with_action(End);

    if(!disconnect_initiator_writed) {
        disconnect_internal_code_id = internal_code_id;
        disconnect_initiator = initiator;
        disconnect_internal_reason = reason;
        disconnect_internal_code = code;
        disconnect_initiator_writed = true;
    }

    if(!aleg_reason_writed) {
        disconnect_rewrited_reason = reason;
        disconnect_rewrited_code = code;
    }
}

void Cdr::setSuppress(bool s)
{
    if(writed) return;
    suppress = s;
}

void Cdr::setSdpCompleted(bool a_leg)
{
    if(a_leg) aleg_sdp_completed = true;
    else bleg_sdp_completed = true;
}

void Cdr::replace(ParamReplacerCtx &ctx,const AmSipRequest &req)
{
    //msg_logger_path = ctx.replaceParameters(msg_logger_path,"msg_logger_path",req);
}

static string join_str_vector2(const vector<string> &v1,
                               const vector<string> &v2,
                               const string &delim)
{
    std::stringstream ss;
    for(vector<string>::const_iterator i = v1.begin();i!=v1.end();++i){
        if(i != v1.begin())
            ss << delim;
        ss << *i;
    }
    //if(!(v1.empty()||v2.empty()))
        ss << "/";
    for(vector<string>::const_iterator i = v2.begin();i!=v2.end();++i){
        if(i != v2.begin())
            ss << delim;
        ss << *i;
    }
    return string(ss.str());
}

inline string join_vector(const vector<string> &v, char delim)
{
    std::stringstream ss;
    for(vector<string>::const_iterator i = v.begin();
        i!=v.end();++i)
    {
        if(i != v.begin())
            ss << delim;
        ss << *i;
    }
    return ss.str();
}

void Cdr::serialize_media_stats(cJSON *j, const string &local_tag, AmRtpStream::MediaStats &m)
{
#define serialize_math_stat(j, PREFIX, STAT) \
    if(STAT.n) { \
        cJSON_AddNumberToObject(j, PREFIX "_min", STAT.min/1000.0); \
        cJSON_AddNumberToObject(j, PREFIX "_max", STAT.max/1000.0); \
        cJSON_AddNumberToObject(j, PREFIX "_mean", STAT.mean/1000.0); \
        cJSON_AddNumberToObject(j, PREFIX "_std", STAT.sd()/1000.0); \
    } else { \
        cJSON_AddNullToObject(j, PREFIX "_min"); \
        cJSON_AddNullToObject(j, PREFIX "_max"); \
        cJSON_AddNullToObject(j, PREFIX "_mean"); \
        cJSON_AddNullToObject(j, PREFIX "_std"); \
    }

    cJSON_AddStringToObject(j, "local_tag", local_tag.c_str());

    //common
    serialize_math_stat(j, "rtcp_rtt",m.rtt);

    cJSON_AddStringToObject(j, "time_start", timeval2str_usec(m.time_start).c_str());
    cJSON_AddStringToObject(j, "time_end",timeval2str_usec(m.time_end).c_str());

    cJSON_AddNumberToObject(j,"rx_out_of_buffer_errors",m.out_of_buffer_errors);
    cJSON_AddNumberToObject(j,"rx_rtp_parse_errors",m.rtp_parse_errors);
    cJSON_AddNumberToObject(j,"rx_dropped_packets",m.dropped);
    cJSON_AddNumberToObject(j,"rx_srtp_decrypt_errors",m.srtp_decript_errors);

    cJSON_AddNumberToObject(j,"rtcp_rr_sent",m.rtcp_rr_sent);
    cJSON_AddNumberToObject(j,"rtcp_rr_recv",m.rtcp_rr_recv);
    cJSON_AddNumberToObject(j,"rtcp_sr_sent",m.rtcp_sr_sent);
    cJSON_AddNumberToObject(j,"rtcp_sr_recv",m.rtcp_sr_recv);

    cJSON *rx_arr = cJSON_CreateArray();

    for(auto& rx : m.rx) {
        cJSON* rx_json = cJSON_CreateObject();

        //RX
        cJSON_AddNumberToObject(rx_json, "rx_ssrc",rx.ssrc);
        cJSON_AddStringToObject(rx_json, "remote_host",get_addr_str(&rx.addr).c_str());
        cJSON_AddNumberToObject(rx_json, "remote_port",am_get_port(&rx.addr));
        cJSON_AddNumberToObject(rx_json, "rx_packets",rx.pkt);
        cJSON_AddNumberToObject(rx_json, "rx_bytes",rx.bytes);
        cJSON_AddNumberToObject(rx_json, "rx_total_lost",rx.total_lost);
        cJSON_AddStringToObject(rx_json, "rx_payloads_transcoded",
            join_vector(rx.payloads_transcoded,',').c_str());
        cJSON_AddStringToObject(rx_json, "rx_payloads_relayed",
            join_vector(rx.payloads_relayed,',').c_str());

        cJSON_AddNumberToObject(rx_json,"rx_decode_errors",rx.decode_errors);
        serialize_math_stat(rx_json, "rx_packet_delta",rx.delta);
        serialize_math_stat(rx_json, "rx_packet_jitter",rx.jitter);
        serialize_math_stat(rx_json, "rx_rtcp_jitter",rx.rtcp_jitter);
        cJSON_AddItemToArray(rx_arr, rx_json);
    }
    cJSON_AddItemToObject(j, "rx", rx_arr);

    //TX
    cJSON_AddNumberToObject(j, "tx_packets",m.tx.pkt);
    cJSON_AddNumberToObject(j, "tx_bytes",m.tx.bytes);
    cJSON_AddNumberToObject(j, "tx_ssrc",m.tx.ssrc);
    cJSON_AddStringToObject(j, "local_host",get_addr_str(&m.tx.addr).c_str());
    cJSON_AddNumberToObject(j, "local_port",am_get_port(&m.tx.addr));

    if(m.rtcp_rr_recv) {
        cJSON_AddNumberToObject(j, "tx_total_lost",m.tx.total_lost);
    } else {
        cJSON_AddNullToObject(j,"tx_total_lost");
    }

    cJSON_AddStringToObject(j, "tx_payloads_transcoded",
        join_vector(m.tx.payloads_transcoded,',').c_str());
    cJSON_AddStringToObject(j, "tx_payloads_relayed",
        join_vector(m.tx.payloads_relayed,',').c_str());

    serialize_math_stat(j, "tx_rtcp_jitter",m.tx.jitter);

#undef serialize_math_stat
}

char* Cdr::serialize_rtp_stats()
{
#define merge_payloads(input, output) \
    for(auto& p : input) { \
            if(std::find(output.begin(),output.end(), p) == output.end()) \
                    output.push_back(p); \
        }

    vector<string> aleg_rx_payloads_transcoded, aleg_rx_payloads_relayed;
    vector<string> aleg_tx_payloads_transcoded, aleg_tx_payloads_relayed;
    vector<string> bleg_rx_payloads_transcoded, bleg_rx_payloads_relayed;
    vector<string> bleg_tx_payloads_transcoded, bleg_tx_payloads_relayed;
    int aleg_tx_bytes = 0, bleg_tx_bytes = 0;
    int aleg_rx_bytes = 0, bleg_rx_bytes = 0;
    int aleg_decode_errors = 0, bleg_decode_errors = 0;
    int aleg_out_of_buffer_errors = 0, bleg_out_of_buffer_errors = 0;
    int aleg_rtp_parse_errors = 0, bleg_rtp_parse_errors = 0;

    for(auto& leg_media_stats : aleg_media_stats) {
        aleg_tx_bytes += leg_media_stats.tx.bytes;
        aleg_out_of_buffer_errors += leg_media_stats.out_of_buffer_errors;
        aleg_rtp_parse_errors += leg_media_stats.rtp_parse_errors;
        merge_payloads(leg_media_stats.tx.payloads_transcoded, aleg_tx_payloads_transcoded);
        merge_payloads(leg_media_stats.tx.payloads_relayed, aleg_tx_payloads_relayed);
        for(auto& rx : leg_media_stats.rx) {
            merge_payloads(rx.payloads_transcoded, aleg_rx_payloads_transcoded);
            merge_payloads(rx.payloads_relayed, aleg_rx_payloads_relayed);
            aleg_decode_errors += rx.decode_errors;
            aleg_rx_bytes += rx.bytes;
        }
    }

    for(auto& leg_media_stats : bleg_media_stats) {
        bleg_tx_bytes += leg_media_stats.tx.bytes;
        bleg_out_of_buffer_errors += leg_media_stats.out_of_buffer_errors;
        bleg_rtp_parse_errors += leg_media_stats.rtp_parse_errors;
        merge_payloads(leg_media_stats.tx.payloads_transcoded, bleg_tx_payloads_transcoded);
        merge_payloads(leg_media_stats.tx.payloads_relayed, bleg_tx_payloads_relayed);
        for(auto& rx : leg_media_stats.rx) {
            merge_payloads(rx.payloads_transcoded, bleg_rx_payloads_transcoded);
            merge_payloads(rx.payloads_relayed, bleg_rx_payloads_relayed);
            bleg_decode_errors += rx.decode_errors;
            bleg_rx_bytes += rx.bytes;
        }
    }

#define field_name fields[i++]
#define add_str2json(value) cJSON_AddStringToObject(j,field_name,value)
#define add_num2json(value) cJSON_AddNumberToObject(j,field_name,value)
#define add_tv2json(value) \
    if(timerisset(&value)) cJSON_AddNumberToObject(j,field_name,timeval2double(value)); \
    else cJSON_AddNullToObject(j,field_name)

    int i = 0;
    cJSON *j;
    char *s;
    static const char *fields[] = {
        "lega_rx_payloads",
        "lega_tx_payloads",

        "legb_rx_payloads",
        "legb_tx_payloads",

        "lega_rx_bytes",
        "lega_tx_bytes",

        "legb_rx_bytes",
        "legb_tx_bytes",

        "lega_rx_decode_errs",
        "lega_rx_no_buf_errs",
        "lega_rx_parse_errs",

        "legb_rx_decode_errs",
        "legb_rx_no_buf_errs",
        "legb_rx_parse_errs",
    };

    j = cJSON_CreateObject();

    //tx/rx uploads
    add_str2json(join_str_vector2(
                    aleg_rx_payloads_transcoded,
                    aleg_rx_payloads_relayed,","
                ).c_str());

    add_str2json(join_str_vector2(
                    aleg_tx_payloads_transcoded,
                    aleg_tx_payloads_relayed,","
                ).c_str());

    add_str2json(join_str_vector2(
                    bleg_rx_payloads_transcoded,
                    bleg_rx_payloads_relayed,","
                ).c_str());

    add_str2json(join_str_vector2(
                    bleg_tx_payloads_transcoded,
                    bleg_tx_payloads_relayed,","
                ).c_str());

    //tx/rx bytes
    add_num2json(aleg_rx_bytes);
    add_num2json(aleg_tx_bytes);
    add_num2json(bleg_rx_bytes);
    add_num2json(bleg_tx_bytes);

    //tx/rx rtp errors
    add_num2json(aleg_decode_errors);
    add_num2json(aleg_out_of_buffer_errors);
    add_num2json(aleg_rtp_parse_errors);
    add_num2json(bleg_decode_errors);
    add_num2json(bleg_out_of_buffer_errors);
    add_num2json(bleg_rtp_parse_errors);

    s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    return s;

}

char *Cdr::serialize_media_stats()
{
    cJSON *j = nullptr, *i;
    char *s;

    if(aleg_sdp_completed)
    {
        if(!j) j = cJSON_CreateArray();
        for(auto& leg_media_stats : aleg_media_stats) {
            i = cJSON_CreateObject();
            cJSON_AddItemToArray(j,i);
            serialize_media_stats(i,local_tag,leg_media_stats);
        }
    }

    if(bleg_sdp_completed)
    {
        if(!j) j = cJSON_CreateArray();
        for(auto& leg_media_stats : bleg_media_stats) {
            i = cJSON_CreateObject();
            cJSON_AddItemToArray(j,i);
            serialize_media_stats(i,bleg_local_tag,leg_media_stats);
        }
    }

    if(!j) return strdup("[]");

    s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);

    /*FILE *f = fopen("/tmp/stats.json","w+");
    fprintf(f,"%s",s);
    fflush(f);
    fclose(f);*/

    return s;
}


char *Cdr::serialize_timers_data()
{
    int i = 0;
    cJSON *j;
    char *s;

    static const char *fields[] = {
        "time_start",
        "leg_b_time",
        "time_connect",
        "time_end",
        "time_1xx",
        "time_18x",
        "time_limit",
        "isup_propagation_delay"
    };

    j = cJSON_CreateObject();

    add_tv2json(start_time);
    add_tv2json(bleg_invite_time);
    add_tv2json(connect_time);
    add_tv2json(end_time);
    add_tv2json(sip_10x_time);
    add_tv2json(sip_18x_time);
    add_num2json(time_limit);
    add_num2json(isup_propagation_delay);

    s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    return s;
}

void Cdr::add_dtmf_event(
    bool aleg, int event,
    struct timeval &now,
    int rx_proto, int tx_proto)
{
    std::queue<dtmf_event_info> &q = aleg ? dtmf_events_a2b : dtmf_events_b2a;
    if(q.size() >= DTMF_EVENTS_MAX) return;
    q.push(dtmf_event_info(event,now,rx_proto,tx_proto));
}

cJSON *Cdr::dtmf_event_info::serialize2json(const struct timeval *t)
{
    struct timeval offset;

    cJSON *j = cJSON_CreateObject();

    cJSON_AddNumberToObject(j,"e",event);
    cJSON_AddNumberToObject(j,"r",rx_proto);
    cJSON_AddNumberToObject(j,"t",tx_proto);

    timersub(&time,t,&offset);
    cJSON_AddNumberToObject(j,"o",timeval2double(offset));

    return j;
}

char *Cdr::serialize_dtmf_events()
{
    cJSON *j, *a;

    const struct timeval *t = timerisset(&connect_time) ? &connect_time : &end_time;

    j = cJSON_CreateObject();

    a = cJSON_CreateArray();
    while(!dtmf_events_a2b.empty()){
        cJSON_AddItemToArray(
            a, dtmf_events_a2b.front().serialize2json(t));
        dtmf_events_a2b.pop();
    }
    cJSON_AddItemToObject(j,"a2b",a);

    a = cJSON_CreateArray();
    while(!dtmf_events_b2a.empty()){
        cJSON_AddItemToArray(
            a, dtmf_events_b2a.front().serialize2json(t));
        dtmf_events_b2a.pop();
    }
    cJSON_AddItemToObject(j,"b2a",a);

    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);

    return s;
}

char *Cdr::serialize_dynamic(const DynFieldsT &df) {
    cJSON *j;
    char *s;

    j = cJSON_CreateObject();

    for(auto const &f: df) {

        const string &name = f.name;
        const char *namep = name.c_str();
        const AmArg &arg = dyn_fields[name];

        switch(arg.getType()) {
        case AmArg::Int:
            cJSON_AddItemToObject(j, namep, cJSON_CreateNumber(static_cast<double>(arg.asInt())));
            break;
        case AmArg::LongLong:
            cJSON_AddItemToObject(j, namep, cJSON_CreateNumber(static_cast<double>(arg.asLongLong())));
            break;
        case AmArg::Bool:
            cJSON_AddBoolToObject(j,namep,arg.asBool());
            break;
        case AmArg::CStr:
            cJSON_AddStringToObject(j,namep,arg.asCStr());
            break;
        case AmArg::Double:
            cJSON_AddNumberToObject(j,namep,arg.asDouble());
            break;
        case AmArg::Array:
            cJSON_AddStringToObject(j,namep, arg2json(arg).data());
        case AmArg::Undef:
            cJSON_AddNullToObject(j,namep);
            break;
        default:
            ERROR("invoc_AmArg. unhandled AmArg type %s",
                  arg.t2str(arg.getType()));
            cJSON_AddNullToObject(j,namep);
        } //switch
    } //for

    s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    return s;
}

char * Cdr::serialize_versions() const
{
    cJSON *j;
    int i,n;
    char *s;
    string joined_versions;

    j = cJSON_CreateObject();

    cJSON_AddStringToObject(j,"core",get_sems_version());
    cJSON_AddStringToObject(j,"yeti",YETI_VERSION);

    if(aleg_versions.empty()) {
        cJSON_AddNullToObject(j,"bleg");
    } else {
        n = aleg_versions.size();
        joined_versions.reserve(n*32);
        i = 1;
        for(const auto &agent : aleg_versions) {
            joined_versions += agent;
            if(i++!=n) joined_versions+=", ";
        }
        cJSON_AddStringToObject(j,"aleg",joined_versions.c_str());
    }

    if(bleg_versions.empty()) {
        cJSON_AddNullToObject(j,"bleg");
    } else {
        joined_versions.clear();
        n = bleg_versions.size();
        joined_versions.reserve(n*32);
        i = 1;
        for(const auto &agent : bleg_versions) {
            joined_versions += agent;
            if(i++!=n) joined_versions+=", ";
        }
        cJSON_AddStringToObject(j,"bleg",joined_versions.c_str());
    }

    s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    return s;
}

void Cdr::add_versions_to_amarg(AmArg &arg) const
{
    AmArg &v = arg["versions"];
    v["core"] = get_sems_version();
    v["yeti"] = YETI_VERSION;

    AmArg &a = v["aleg"];
    a.assertArray();
    for(const auto &agent : aleg_versions)
        a.push(agent);

    AmArg &b = v["bleg"];
    b.assertArray();
    for(const auto &agent : bleg_versions)
        b.push(agent);
}

#undef add_str2json
#undef add_tv2json
#undef add_num2json
#undef field_name

static string cdr_sql_statement_name("writecdr");

void Cdr::apply_params(
    QueryInfo &query_info,
    const DynFieldsT &df)
{
#define invoc(field_value) \
    query_info.addParam(field_value);

#define invoc_typed(type,field_value)\
    query_info.addTypedParam(type, field_value);

#define invoc_null() \
    query_info.addParam(AmArg());

#define invoc_cond(field_value,condition)\
    if(condition) { invoc(field_value); }\
    else { invoc_null(); }

#define invoc_cond_typed(type, field_value,condition)\
    if(condition) { invoc_typed(type, field_value); }\
    else { invoc_null(); }


#define invoc_json(func) do { \
    char *s = func; \
    invoc(s); \
    free(s); \
} while(0)

    const auto &cfg = Yeti::instance().config;

    invoc(true); //is_master
    invoc(AmConfig.node_id);
    invoc(cfg.pop_id);

    invoc(attempt_num);
    invoc(is_last);

    invoc_cond_typed("smallint", legA_transport_protocol_id,legA_transport_protocol_id!=0);
    //invoc_cond(legA_transport_protocol_id,legA_transport_protocol_id!=0);

    invoc(legA_local_ip);
    invoc(legA_local_port);
    invoc(legA_remote_ip);
    invoc(legA_remote_port);

    invoc_cond_typed("smallint", legB_transport_protocol_id,legB_transport_protocol_id!=0);
    //invoc_cond(legB_transport_protocol_id,legB_transport_protocol_id!=0);

    invoc(legB_local_ip);
    invoc(legB_local_port);
    invoc(legB_remote_ip);
    invoc(legB_remote_port);
    invoc(ruri);
    invoc(outbound_proxy);

    invoc_json(serialize_timers_data());

    invoc(sip_early_media_present);
    invoc(disconnect_code);
    invoc(disconnect_reason);
    invoc(disconnect_initiator);
    invoc(disconnect_internal_code);
    invoc(disconnect_internal_reason);

    if(is_last){
        invoc(disconnect_rewrited_code);
        invoc(disconnect_rewrited_reason);
    } else {
        invoc(0);
        invoc("");
    }

    if(cfg.write_internal_disconnect_code) {
        invoc_cond_typed(
            "smallint", disconnect_internal_code_id,
            disconnect_internal_code_id!=0);
    }

    invoc(orig_call_id);
    invoc(term_call_id);
    invoc(local_tag);
    invoc(bleg_local_tag);
    invoc(msg_logger_path);
    invoc_typed("smallint", dump_level_id);

    invoc(audio_record_enabled);

    invoc_json(serialize_rtp_stats());
    invoc_json(serialize_media_stats());

    invoc(global_tag);

    invoc(resources);
    invoc(active_resources);

    invoc_cond_typed("smallint", failed_resource_type_id, failed_resource_type_id!=-1);
    invoc_cond_typed("bigint", failed_resource_id, failed_resource_id!=-1);

    if(dtmf_events_a2b.empty() && dtmf_events_b2a.empty()) {
        invoc_null();
    } else {
        invoc_json(serialize_dtmf_events());
    }

    invoc_json(serialize_versions());

    invoc(is_redirected);

    /* invocate dynamic fields  */
    invoc(arg2json(dyn_fields));
    //invoc_json(serialize_dynamic(df));

    /*if(Yeti::instance().config.aleg_cdr_headers.enabled()) {*/
    //aleg_reasons.serialize()
    if(aleg_reasons.has_data(cfg.headers_processing.aleg)) {
        aleg_headers_amarg.assertStruct();
        aleg_reasons.serialize_flat(
            aleg_headers_amarg["reason"],
            cfg.headers_processing.aleg,
            local_tag);
    }
    invoc_cond(arg2json(aleg_headers_amarg), isArgStruct(aleg_headers_amarg) && aleg_headers_amarg.size());
    //}

    /* invocate trusted hdrs  */
    /*for(const auto &h : trusted_hdrs)
        invoc_AmArg(invoc,h);*/
    if(bleg_reasons.has_data(cfg.headers_processing.bleg)) {
        bleg_reply_headers_amarg.assertStruct();
        bleg_reasons.serialize_flat(
            bleg_reply_headers_amarg["reason"],
            cfg.headers_processing.bleg,
            local_tag);
    }
    invoc_cond(arg2json(bleg_reply_headers_amarg), isArgStruct(bleg_reply_headers_amarg) && bleg_reply_headers_amarg.size());

    //i_lega_identity  will be here
    invoc_cond(arg2json(identity_data), isArgArray(identity_data) && identity_data.size());

#undef invoc_json
#undef invoc_cond_typed
#undef invoc_cond
#undef invoc_null
#undef invoc_typed
#undef invoc
}

void Cdr::snapshot_info(AmArg &s, const DynFieldsT &df) const
{
   static char strftime_buf[64] = {0};
   static struct tm tt;

#define add_field(val) s[#val] = val;
#define add_field_as(name,val) s[name] = val;
#define add_timeval_field(val) s[#val] = timerisset(&val) ? timeval2str(val) : AmArg();

    add_timeval_field(cdr_born_time);
    add_timeval_field(start_time);
    add_timeval_field(connect_time);


    localtime_r(&start_time.tv_sec,&tt);
    int len = strftime(strftime_buf, sizeof strftime_buf, "%F", &tt);
    s["start_date"] = string(strftime_buf,len);

    add_field(legB_remote_port);
    add_field(legB_local_port);
    add_field(legA_remote_port);
    add_field(legA_local_port);
    add_field(legB_remote_ip);
    add_field(legB_local_ip);
    add_field(legA_remote_ip);
    add_field(legA_local_ip);

    add_field(orig_call_id);
    add_field(term_call_id);
    add_field(local_tag);
    add_field(global_tag);

    add_field(time_limit);
    add_field(dump_level_id);
    add_field_as("audio_record_enabled", audio_record_enabled ? 1 : 0);

    add_field(attempt_num);

    add_field(resources);
    add_field(active_resources);
    if(isArgStruct(active_resources_clickhouse))
        for(const auto &a : *active_resources_clickhouse.asStruct())
            s[a.first] = a.second;

    for(const auto &d: df) {
        const string &fname = d.name;
        AmArg &f = dyn_fields[fname];

        //cast bool to int
        if(d.type_id==DynField::BOOL) {
            if(!isArgBool(f)) continue;
            add_field_as(fname,(f.asBool() ? 1 : 0));
            continue;
        }

        add_field_as(fname,f);
    }

#undef add_field
#undef add_field_as
#undef add_timeval_field
}

void Cdr::snapshot_info_filtered(AmArg &s, const DynFieldsT &df,
                                 const unordered_set<string> &wanted_fields) const
{
    static char strftime_buf[64] = {0};
    static struct tm tt;

#define filter(name)\
    static const string name ## _key( #name ); \
    if(wanted_fields.count( name  ## _key )>0)
#define add_field(val) \
    filter(val) s[ val  ## _key ] = val;
#define add_field_as(name,val) \
    filter(name) s[ name  ## _key ] = val;
#define add_timeval_field(val) \
    filter(val) s[ val  ## _key ] = timerisset(&val) ? timeval2str(val) : AmArg();

    add_timeval_field(cdr_born_time);
    add_timeval_field(start_time);
    add_timeval_field(connect_time);

    localtime_r(&start_time.tv_sec,&tt);
    int len = strftime(strftime_buf, sizeof strftime_buf, "%F", &tt);
    s["start_date"] = string(strftime_buf,len);

    add_field(legB_remote_port);
    add_field(legB_local_port);
    add_field(legA_remote_port);
    add_field(legA_local_port);
    add_field(legB_remote_ip);
    add_field(legB_local_ip);
    add_field(legA_remote_ip);
    add_field(legA_local_ip);

    add_field(orig_call_id);
    add_field(term_call_id);
    add_field(local_tag);
    add_field(global_tag);

    add_field(time_limit);
    add_field(dump_level_id);
    add_field_as(audio_record_enabled, audio_record_enabled ? 1 : 0);

    add_field(attempt_num);

    add_field(resources);
    filter(active_resources) {
        add_field_as(active_resources_key,active_resources);
        if(isArgStruct(active_resources_clickhouse))
            for(const auto &a : *active_resources_clickhouse.asStruct())
                s[a.first] = a.second;
    }

    for(const auto &d: df) {
        const string &fname = d.name;
        AmArg &f = dyn_fields[fname];

        //cast bool to int
        if(d.type_id==DynField::BOOL) {
            if(!isArgBool(f)) continue;
            if(!wanted_fields.count(fname)) continue;
            s[fname] = f.asBool() ? 1 : 0;
            continue;
        }

        if(wanted_fields.count(fname))
            s[fname] = f;
    }

#undef add_field
#undef add_field_as
#undef add_timeval_field
#undef filter
}

#define add_field(val)\
    a[#val] = val;
#define add_field_as(name,val)\
    a[name] = val;
#define add_timeval_field(val)\
    a[#val] = timerisset(&val) ? timeval2double(val) : AmArg();

void Cdr::serialize_for_http_common(AmArg &a, const DynFieldsT &df) const
{
    a["node_id"] = AmConfig.node_id;
    a["pop_id"] = Yeti::instance().config.pop_id;

    add_timeval_field(cdr_born_time);
    add_timeval_field(start_time);

    add_field(legA_remote_port);
    add_field(legA_local_port);
    add_field(legA_remote_ip);
    add_field(legA_local_ip);

    add_field(orig_call_id);
    add_field(global_tag);

    add_field(time_limit);
    add_field(dump_level_id);
    add_field(audio_record_enabled);

    add_field(resources);

    add_field_as("aleg_headers", aleg_headers_amarg);

    AmArg &routing = a["routing"];
    for(const auto &dit: df) {
        const string &fname = dit.name;
        //AmArg &f = dyn_fields[fname];
        /*if(f.getType()==AmArg::Undef && (dit.type_id==DynField::VARCHAR))
            a[fname] = "";*/
        routing[fname] = dyn_fields[fname];
    }
}

void Cdr::serialize_for_http_connected(AmArg &a) const
{
    add_field_as("active_resources", active_resources_amarg);
    add_field(attempt_num);
    add_field(sip_early_media_present);
    add_field(term_call_id);
    add_field(bleg_local_tag);

    add_field(legB_remote_port);
    add_field(legB_local_port);
    add_field(legB_remote_ip);
    add_field(legB_local_ip);

    add_timeval_field(connect_time);
    add_timeval_field(bleg_invite_time);
    add_timeval_field(bleg_connect_time);
    add_timeval_field(sip_10x_time);
    add_timeval_field(sip_18x_time);
}

void Cdr::serialize_for_http_disconnected(AmArg &a) const
{
    add_field(is_redirected);
    add_timeval_field(end_time);

    add_field(disconnect_initiator);
    add_field(disconnect_code);
    add_field(disconnect_reason);
    add_field(disconnect_internal_code);
    add_field(disconnect_internal_reason);
    add_field(disconnect_rewrited_code);
    add_field(disconnect_rewrited_reason);

}

#undef add_field
#undef add_field_as
#undef add_timeval_field

void Cdr::info(AmArg &s)
{
    s["dump_level"] = dump_level2str(dump_level_id);
    if(dump_level_id)
        s["logger_path"] = msg_logger_path;
    s["local_tag"] = local_tag;
    s["internal_reason"] = disconnect_internal_reason;
    s["internal_code"] = disconnect_internal_code;
    s["initiator"] = DisconnectInitiator2Str(disconnect_initiator);
    s["start_time"] = timeval2double(start_time);
    s["connect_time"] = timeval2double(connect_time);
    s["end_time"] = timeval2double(end_time);
    s["10x_time"] = timeval2double(sip_10x_time);
    s["18x_time"] = timeval2double(sip_18x_time);
    s["resources"] = resources;
    s["active_resources"] = active_resources;
}
