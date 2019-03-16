#include "Cdr.h"
#include "AmUtils.h"
#include "AmSipMsg.h"
#include "log.h"
#include "CoreRpc.h"
#include "TrustedHeaders.h"
#include "jsonArg.h"
#include "sip/defs.h"
#include "sems.h"
#include "../yeti_version.h"
#include "../RTPParameters.h"

#define DTMF_EVENTS_MAX 50

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
        case Write: return "Write";
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
    snapshoted(false),
    sip_early_media_present(false),
    trusted_hdrs_gw(false),
    inserted2list(false),
    disconnect_initiator(DisconnectUndefined),
    disconnect_initiator_writed(false),
    aleg_reason_writed(false),
    bleg_reason_writed(false),
    disconnect_code(0),
    disconnect_internal_reason("Unhandled sequence"),
    disconnect_internal_code(0),
    disconnect_rewrited_code(0),
    legB_transport_protocol_id(0),
    legB_remote_port(0),
    legB_local_port(0),
    legA_remote_port(0),
    legA_local_port(0),
    legA_transport_protocol_id(0),
    dump_level_id(0),
    time_limit(0),
    attempt_num(1),
    active_resources("[]"),
    failed_resource_type_id(-1),
    failed_resource_id(-1),
    legA_bytes_recvd(0),
    legB_bytes_recvd(0),
    legA_bytes_sent(0),
    legB_bytes_sent(0),
    isup_propagation_delay(0),
    audio_record_enabled(false),
    is_redirected(false),
    writed(false)
{
    DBG("Cdr[%p]()",this);

    timerclear(&start_time);
    timerclear(&bleg_invite_time);
    timerclear(&connect_time);
    timerclear(&bleg_connect_time);
    timerclear(&end_time);
    timerclear(&sip_10x_time);
    timerclear(&sip_18x_time);

    TrustedHeaders::instance()->init_hdrs(trusted_hdrs);

    active_resources_amarg.assertArray();
    active_resources_clickhouse.assertStruct();
}

Cdr::Cdr(const Cdr& cdr,const SqlCallProfile &profile)
  : Cdr()
{
    DBG("Cdr[%p](cdr = %p,profile = %p)", this, &cdr, &profile);

    update_sql(profile);

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
}

Cdr::Cdr(const SqlCallProfile &profile)
  : Cdr()
{
    DBG("Cdr[%p](profile = %p)", this, &profile);

    update_sql(profile);
}

Cdr::Cdr(const Cdr& cdr)
  : CdrBase(CdrBase::Call)
{
    DBG("Cdr[%p](cdr = %p)", this, &cdr);
    operator=(cdr);
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
    outbound_proxy = profile.outbound_proxy;
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

void Cdr::update(const AmSipRequest &req)
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

    if(req.method==SIP_METH_INVITE){
        const AmMimeBody *body = req.body.hasContentType(SIP_APPLICATION_ISUP);
        if(body){
            AmISUP isup;
            if(0==isup.parse(body)){
                update(isup);
            }
        }
    }
}

void Cdr::update(const AmISUP &isup)
{
    DBG("Cdr::%s(AmISUP)",FUNC_NAME);
    isup_propagation_delay = isup.propagation_delay;
}

void Cdr::update(const AmSipReply &reply){
    size_t pos1,pos2,pos;

    DBG("Cdr::%s(AmSipReply)",FUNC_NAME);

    if(writed) return;

    AmLock l(*this);

    if(reply.code == 200 && trusted_hdrs_gw){ //try to fill trusted headers from 200 OK reply
        TrustedHeaders::instance()->parse_reply_hdrs(reply,trusted_hdrs);
    }

    if(reply.remote_port==0)
        return; //local reply

    legB_transport_protocol_id = reply.transport_id;
    legB_remote_ip = reply.remote_ip;
    legB_remote_port = reply.remote_port;
    legB_local_ip = reply.actual_ip;
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

void Cdr::update_init_aleg(
    const string &leg_local_tag,
    const string &leg_global_tag,
    const string &leg_orig_call_id)
{
    if(writed) return;

    AmLock l(*this);

    local_tag = leg_local_tag;
    global_tag = leg_global_tag;
    orig_call_id = leg_orig_call_id;
}

void Cdr::update_init_bleg(const string &leg_term_call_id)
{
    if(writed) return;
    AmLock l(*this);
    term_call_id = leg_term_call_id;
}

void Cdr::update(UpdateAction act)
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
        gettimeofday(&connect_time, NULL);
        break;
    case BlegConnect:
        gettimeofday(&bleg_connect_time, NULL);
        break;
    case End:
        if(end_time.tv_sec==start_time.tv_sec)
            gettimeofday(&end_time, NULL);
        break;
    case Write:
        writed = true;
        break;
    }
}

void Cdr::update(const ResourceList &rl)
{
    if(rl.empty()) return;

    string clickhouse_key_prefix;
    cJSON *j = cJSON_CreateArray(),*i;

    active_resources_amarg.clear();
    active_resources_clickhouse.clear();
    active_resources_clickhouse.assertStruct();

    for(auto const &r: rl) {

        if(!r.active) continue;

        active_resources_amarg.push(AmArg());
        AmArg &a = active_resources_amarg.back();

        clickhouse_key_prefix = "active_resource_" + int2str(r.type);

        AmArg &id_arg = active_resources_clickhouse[clickhouse_key_prefix + "_id"];
        if(isArgUndef(id_arg)) id_arg = r.id;

        AmArg &limit_arg = active_resources_clickhouse[clickhouse_key_prefix + "_limit"];
        if(isArgUndef(limit_arg)) limit_arg = r.limit;

        AmArg &used_arg = active_resources_clickhouse[clickhouse_key_prefix + "_used"];
        if(isArgUndef(used_arg)) used_arg = r.takes;

        i = cJSON_CreateObject();

        cJSON_AddNumberToObject(i,"type",r.type);
        a["type"] = r.type;
        cJSON_AddNumberToObject(i,"id",r.id);
        a["id"] = r.id;
        cJSON_AddNumberToObject(i,"takes",r.takes);
        a["takes"] = r.takes;
        cJSON_AddNumberToObject(i,"limit",r.limit);
        a["limit"] = r.limit;

        cJSON_AddItemToArray(j,i);
    }
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

    AmLock l(*this);

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

    AmLock l(*this);

    disconnect_rewrited_reason = reason;
    disconnect_rewrited_code = code;
    aleg_reason_writed = true;
}

void Cdr::update_internal_reason(DisconnectInitiator initiator,string reason, int code)
{
    DBG("Cdr[%p]::%s(initiator = %d,reason = '%s',code = %d) cdr.disconnect_initiator_writed = %d",
        this,FUNC_NAME,initiator,reason.c_str(),code,disconnect_initiator_writed);

    if(writed) return;

    AmLock l(*this);

    update(End);

    if(!disconnect_initiator_writed) {
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
    AmLock l(*this);
    suppress = s;
}

void Cdr::refuse(const SBCCallProfile &profile)
{
    if(writed) return;

    AmLock l(*this);

    unsigned int refuse_with_code;
    string refuse_with = profile.refuse_with;
    size_t spos = refuse_with.find(' ');
    disconnect_initiator = DisconnectByDB;
    if (spos == string::npos || spos == refuse_with.size() ||
        str2i(refuse_with.substr(0, spos), refuse_with_code))
    {
        ERROR("can't parse refuse_with in profile");
        disconnect_reason = refuse_with;
        disconnect_code = 0;
    } else {
        disconnect_reason = refuse_with.substr(spos+1);
        disconnect_code = refuse_with_code;
    }
    disconnect_rewrited_reason = disconnect_reason;
    disconnect_rewrited_code = disconnect_code;
}

void Cdr::refuse(int code, string reason)
{
    if(writed) return;
    AmLock l(*this);

    disconnect_code = code;
    disconnect_reason = reason;
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

#define field_name fields[i++]
#define add_str2json(value) cJSON_AddStringToObject(j,field_name,value)
#define add_num2json(value) cJSON_AddNumberToObject(j,field_name,value)
#define add_tv2json(value) \
    if(timerisset(&value)) cJSON_AddNumberToObject(j,field_name,timeval2double(value)); \
    else cJSON_AddNullToObject(j,field_name)

char *Cdr::serialize_rtp_stats()
{
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
                    legA_payloads.incoming,
                    legA_payloads.incoming_relayed,","
                ).c_str());

    add_str2json(join_str_vector2(
                    legA_payloads.outgoing,
                    legA_payloads.outgoing_relayed,","
                ).c_str());

    add_str2json(join_str_vector2(
                    legB_payloads.incoming,
                    legB_payloads.incoming_relayed,","
                ).c_str());

    add_str2json(join_str_vector2(
                    legB_payloads.outgoing,
                    legB_payloads.outgoing_relayed,","
                ).c_str());

    //tx/rx bytes
    add_num2json(legA_bytes_recvd);
    add_num2json(legA_bytes_sent);
    add_num2json(legB_bytes_recvd);
    add_num2json(legB_bytes_sent);

    //tx/rx rtp errors
    add_num2json(legA_stream_errors.decode_errors);
    add_num2json(legA_stream_errors.out_of_buffer_errors);
    add_num2json(legA_stream_errors.rtp_parse_errors);
    add_num2json(legB_stream_errors.decode_errors);
    add_num2json(legB_stream_errors.out_of_buffer_errors);
    add_num2json(legB_stream_errors.rtp_parse_errors);

    s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
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
            cJSON_AddNumberToObject(j,namep,arg.asInt());
            break;
        case AmArg::LongLong:
            cJSON_AddNumberToObject(j,namep,arg.asLongLong());
            break;
        case AmArg::Bool:
            cJSON_AddBoolToObject(j,namep,arg.asBool());
            break;
        case AmArg::CStr:
            cJSON_AddStringToObject(j,namep,arg.asCStr());
            break;
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

static inline void invoc_AmArg(pqxx::prepare::invocation &invoc,const AmArg &arg)
{
    short type = arg.getType();
    switch(type) {
    case AmArg::Int:
        invoc(arg.asInt());
        break;
    case AmArg::LongLong:
        invoc(arg.asLongLong());
        break;
    case AmArg::Bool:
        invoc(arg.asBool());
        break;
    case AmArg::CStr:
        invoc(arg.asCStr());
        break;
    case AmArg::Undef:
        invoc();
        break;
    default:
        ERROR("invoc_AmArg. unhandled AmArg type %s",arg.t2str(type));
        invoc();
    }
}

pqxx::prepare::invocation Cdr::get_invocation(cdr_transaction &tnx)
{
    return tnx.prepared(cdr_sql_statement_name);
}

void Cdr::invoc(
    pqxx::prepare::invocation &invoc,
    const DynFieldsT &df,
    bool serialize_dynamic_fields)
{
#define invoc_cond(field_value,condition)\
    if(condition) { invoc(field_value); }\
    else { invoc(); }

#define invoc_json(func) do { \
    char *s = func; \
    invoc(s); \
    free(s); \
} while(0)

    invoc(attempt_num);
    invoc(is_last);
    invoc_cond(legA_transport_protocol_id,legA_transport_protocol_id!=0);
    invoc(legA_local_ip);
    invoc(legA_local_port);
    invoc(legA_remote_ip);
    invoc(legA_remote_port);
    invoc_cond(legB_transport_protocol_id,legB_transport_protocol_id!=0);
    invoc(legB_local_ip);
    invoc(legB_local_port);
    invoc(legB_remote_ip);
    invoc(legB_remote_port);

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

    invoc(orig_call_id);
    invoc(term_call_id);
    invoc(local_tag);
    invoc(msg_logger_path);
    invoc(dump_level_id);
    invoc(audio_record_enabled);

    invoc_json(serialize_rtp_stats());

    invoc(global_tag);

    invoc(resources);
    invoc(active_resources);

    invoc_cond(failed_resource_type_id, failed_resource_type_id!=-1);
    invoc_cond(failed_resource_id, failed_resource_id!=-1);

    if(dtmf_events_a2b.empty() && dtmf_events_b2a.empty()) {
        invoc();
    } else {
        invoc_json(serialize_dtmf_events());
    }

    invoc_json(serialize_versions());

    invoc(is_redirected);

    /* invocate dynamic fields  */
    if(serialize_dynamic_fields){
        invoc_json(serialize_dynamic(df));
    } else {
        for(const auto &f : df)
            invoc_AmArg(invoc, dyn_fields[f.name]);
    }
    /* invocate trusted hdrs  */
    for(const auto &h : trusted_hdrs)
        invoc_AmArg(invoc,h);

#undef invoc_json
#undef invoc_cond
}

template<class T>
static void join_csv(ofstream &s, const T &a)
{
    if(!a.size())
        return;

    int n = a.size()-1;

    s << ",";
    for(int k = 0;k<n;k++)
        s << "'" << AmArg::print(a[k]) << "',";
    s << "'" << AmArg::print(a[n]) << "'";
}

void Cdr::to_csv_stream(ofstream &s, const DynFieldsT &df)
{

#define add_value(v) s << "'"<<v<< "'" << ','

#define add_json(func) do { \
    char *jstr = func; \
    add_value(jstr); \
    free(jstr); \
} while(0)

    add_value(attempt_num);
    add_value(is_last);
    add_value(legA_local_ip); add_value(legA_local_port);
    add_value(legA_remote_ip); add_value(legA_remote_port);
    add_value(legB_local_ip); add_value(legB_local_port);
    add_value(legB_remote_ip); add_value(legB_remote_port);
    add_value(sip_early_media_present);
    add_json(serialize_timers_data());

    add_value(disconnect_code); add_value(disconnect_reason);
    add_value(disconnect_initiator);
    add_value(disconnect_internal_code); add_value(disconnect_internal_reason);

    if(is_last){
        add_value(disconnect_rewrited_code);
        add_value(disconnect_rewrited_reason);
    } else {
        add_value(0);
        add_value("");
    }

    add_value(orig_call_id); add_value(term_call_id);
    add_value(local_tag); add_value(msg_logger_path);
    add_value(dump_level_id);

    add_json(serialize_rtp_stats());

    add_value(global_tag);

    add_value(resources);
    add_value(active_resources);

    //dynamic fields
    if(dyn_fields.size()){
        s << ",";
        for(DynFieldsT_const_iterator it = df.begin();
            it!=df.end();++it)
        {
            if(it!=df.begin()) s << ",";
            s << "'" << AmArg::print(dyn_fields[it->name]) << "'";
        }
    }

    //trusted fields
    join_csv(s,trusted_hdrs);

#undef add_json
#undef add_value
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

