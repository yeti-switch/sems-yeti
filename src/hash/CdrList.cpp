#include "AmSessionProcessor.h"
#include "CdrList.h"
#include "log.h"

#include "../yeti.h"
#include "../cfg/yeti_opts.h"
#include "../cfg/statistics_opts.h"
#include "../SBCCallLeg.h"

#include "jsonArg.h"
#include "AmSessionContainer.h"
#include "AmEventDispatcher.h"
#include "ampi/HttpClientAPI.h"

#define EPOLL_MAX_EVENTS 2048

CdrList::CdrList()
  : epoll_fd(0),
    snapshots_enabled(false),
    snapshots_buffering(false),
    snapshots_interval(0),
    last_snapshot_ts(0),
    stopped(false)
{
    snapshot_id.fields.sign = 0;
    snapshot_id.fields.node_id = AmConfig.node_id;
    snapshot_id.fields.counter = 0;
}

CdrList::~CdrList()
{ }

void CdrList::onSessionFinalize(Cdr *cdr)
{
    if(snapshots_buffering) {
        AmLock l(*this);
        postponed_active_calls.emplace(*cdr);
    }
}

long int CdrList::getCallsCount()
{
    /*AmLock l(*this);
    return size();*/

    long int calls_count = 0;
    AmEventDispatcher::instance()->iterate(
        [&](const string &,
            const AmEventDispatcher::QueueEntry &entry)
    {
        auto leg = dynamic_cast<SBCCallLeg *>(entry.q);
        if(!leg) return;

        if(!leg->isALeg()) return;

        calls_count++;

    });
    return calls_count;
}

bool CdrList::getCall(SBCCallLeg* leg, AmArg& call, const SqlRouter *router) {
    auto &gc = Yeti::instance().config;
    const get_calls_ctx ctx(AmConfig.node_id,gc.pop_id,router);

    if(!leg->isALeg()) return false;

    auto call_ctx = leg->getCallCtx();
    if(!call_ctx) return false;

    if(!call_ctx->cdr) return false;
    cdr2arg(call,call_ctx->cdr.get(),ctx);
    return true;
}

bool CdrList::getCallsFields(SBCCallLeg* leg, AmArg &call,
                             const SqlRouter *router,
                             cmp_rules& filter_rules,
                             const vector<string>& fields)
{
    auto &gc = Yeti::instance().config;
    const get_calls_ctx ctx(AmConfig.node_id,gc.pop_id,router,&fields);

    if(!leg) return false;
    if(!leg->isALeg()) return false;

    auto call_ctx = leg->getCallCtx();
    if(!call_ctx) return false;

    if(call_ctx->cdr && !call_ctx->profiles.empty()) {
        if(apply_filter_rules(call_ctx->cdr.get(),filter_rules)) {
            cdr2arg_filtered(call,call_ctx->cdr.get(),ctx);
            return true;
        }
    }
    return false;
}

void CdrList::getFields(AmArg &ret,SqlRouter *r)
{
    ret.assertStruct();

    for(const static_call_field *f = static_call_fields; f->name; f++){
        AmArg &a = ret[f->name];
        a["type"] = f->type;
        a["is_dynamic"] = false;
    }

    const DynFieldsT &router_dyn_fields = r->getDynFields();
    for(const auto &df : router_dyn_fields) {
        AmArg &a = ret[df.name];
        a["type"] = df.type_name;
        a["is_dynamic"] = true;
    }
}

void CdrList::validate_fields(const vector<string> &wanted_fields, const SqlRouter *router){
    bool ret = true;
    AmArg failed_fields;
    const DynFieldsT &df = router->getDynFields();
    for(const auto &f: wanted_fields) {
        int k = static_call_fields_count - 1;
        for(;k>=0;k--) {
            if(f==static_call_fields[k].name)
                break;
        }
        if(k<0) {
            //not present in static fields. search in dynamic
            DynFieldsT::const_iterator it = df.begin();
            for(;it!=df.end();++it)
                if(f==it->name)
                    break;
            if(it==df.end()){ //not found in dynamic fields too
                ret = false;
                failed_fields.push(f);
            }
        }
    }
    if(!ret) {
        throw std::string(
            string("passed one or more unknown fields:") +
            AmArg::print(failed_fields));
    }
}

int CdrList::configure(cfg_t *confuse_cfg)
{
    auto statistics_sec = cfg_getsec(confuse_cfg, section_name_statistics);
    if(!statistics_sec) return 0;

    auto active_calls_sec = cfg_getsec(statistics_sec, section_name_active_calls);
    if(!active_calls_sec) return 0;

    auto clickhouse_sec = cfg_getsec(active_calls_sec, section_name_clickhouse);
    if(!clickhouse_sec) return 0;

    if(!cfg_size(clickhouse_sec, opt_name_destinations) ||
       !cfg_size(clickhouse_sec, opt_name_table))
    {
        DBG("need both 'table' and 'destinations' parameters "
            "to enable active calls snapshots for clickhouse");
        return 0;
    }

    snapshots_enabled = true;
    router = &Yeti::instance().router;

    snapshots_interval = cfg_getint(active_calls_sec, opt_name_period);
    if(0==snapshots_interval) {
        ERROR("invalid active calls snapshots period: %d", snapshots_interval);
        return -1;
    }

    snapshots_table = cfg_getstr(clickhouse_sec, opt_name_table);
    snapshots_buffering = cfg_getbool(clickhouse_sec, opt_name_buffering);

    for(unsigned int i = 0; i < cfg_size(clickhouse_sec, opt_name_destinations); i++) {
        snapshots_destinations.emplace_back(
            cfg_getnstr(clickhouse_sec, opt_name_destinations, i));
    }

    for(unsigned int i = 0; i < cfg_size(clickhouse_sec, opt_name_allowed_fields); i++) {
        snapshots_fields_whitelist.emplace(
            cfg_getnstr(clickhouse_sec, opt_name_allowed_fields, i));
    }

    DBG("use table '%s' for active calls snapshots "
        "with interval %d (seconds). "
        "buffering is %sabled",
        snapshots_table.c_str(),
        snapshots_interval,
        snapshots_buffering?"en":"dis");

    for(const auto &f: snapshots_destinations) {
        DBG("clickhouse destination: %s",f.c_str());
    }

    for(const auto &f: snapshots_fields_whitelist) {
        DBG("clickhouse allowed_field: %s",f.c_str());
    }

    snapshots_body_header = "INSERT INTO ";
    snapshots_body_header += snapshots_table + " FORMAT JSONEachRow\n";

    if((epoll_fd = epoll_create(2)) == -1) {
        ERROR("epoll_create() call failed");
        return -1;
    }
    timer.link(epoll_fd);
    stop_event.link(epoll_fd);

    return 0;
}

void CdrList::run()
{
    if(!snapshots_enabled) return;

    int ret;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("calls-snapshots");

    u_int64_t now = wheeltimer::instance()->unix_clock.get();
    unsigned int first_interval = snapshots_interval - (now % snapshots_interval);
    timer.set(first_interval*1000000,snapshots_interval*1000000);

    running = true;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);
        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s",strerror(errno));
        }
        if(ret < 1)
            continue;
        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];

            if(!(e.events & EPOLLIN)){
                continue;
            }

            if(e.data.fd==timer) {
                timer.read();
                onTimer();
            } else if(e.data.fd==stop_event){
                stop_event.read();
                running = false;
                break;
            }
        }
    } while(running);

    close(epoll_fd);
    stopped.set(true);
}

void CdrList::on_stop()
{
    if(!snapshots_enabled) return;

    stop_event.fire();
    stopped.wait_for();
}

void CdrList::onTimer()
{
    int len;
    time_t ts;
    char strftime_buf[64];
    static const string end_time_key("end_time");

    PostponedCdrsContainer local_postponed_calls;

    static struct tm t;
    //static struct timeval tv; //fake call interval end value
    u_int64_t now = wheeltimer::instance()->unix_clock.get();
    u_int64_t snapshot_ts = now - (now % snapshots_interval);

    string snapshot_timestamp_str, snapshot_date_str;

    if(last_snapshot_ts && last_snapshot_ts==snapshot_ts){
        ERROR("duplicate snapshot %lu timestamp. "
              "ignore timer event (can lead to time gap between snapshots)",
              snapshot_ts);
        return;
    }

    last_snapshot_ts = snapshot_ts;

    /*tv.tv_usec = 0;
    tv.tv_sec = snapshot_ts;*/
    ts = snapshot_ts;
    localtime_r(&ts,&t);

    len = strftime(strftime_buf, sizeof strftime_buf, "%F %T", &t);
    snapshot_timestamp_str = string(strftime_buf, len);

    len = strftime(strftime_buf, sizeof strftime_buf, "%F", &t);
    snapshot_date_str = string(strftime_buf, len);

    auto &gc = Yeti::instance().config;
    const DynFieldsT &df = router->getDynFields();

    struct SnapshotInfo
    {
        AmArg calls;
        string snapshot_timestamp_str;
        string snapshot_date_str;
        CdrList* cdr_list;
    };
    SnapshotInfo *info = new SnapshotInfo;
    AmArg &calls = info->calls;
    info->snapshot_timestamp_str = snapshot_timestamp_str;
    info->snapshot_date_str = snapshot_date_str;
    info->cdr_list = this;

    snapshot_id.fields.timestamp = snapshot_ts;

    if(snapshots_buffering) {
        {
            AmLock l(*this);
            if(snapshots_buffering)
                local_postponed_calls.swap(postponed_active_calls);
        }
        while(!local_postponed_calls.empty()) {
            const Cdr &cdr = local_postponed_calls.front();

            calls.push(AmArg());
            AmArg &call = calls.back();

            snapshot_id.fields.counter++;
            call["id"] = snapshot_id.v;

            call["snapshot_timestamp"] = snapshot_timestamp_str;
            call["snapshot_date"] = snapshot_date_str;
            call["node_id"] = AmConfig.node_id;
            call["pop_id"] = gc.pop_id;
            call["buffered"] = true;

            if(snapshots_fields_whitelist.empty()) {
                cdr.snapshot_info(call,df);
                call[end_time_key] =
                    timerisset(&cdr.end_time) ?
                    timeval2str(cdr.end_time) : AmArg();
            } else {
                cdr.snapshot_info_filtered(call,df,snapshots_fields_whitelist);
                if(snapshots_fields_whitelist.count(end_time_key))
                    call[end_time_key] =
                        timerisset(&cdr.end_time) ?
                        timeval2str(cdr.end_time) : AmArg();
            }

            local_postponed_calls.pop();
        }
    }

    AmSessionProcessor::sendIterateRequest([](AmSession* session, void* user_data, AmArg& ret)
    {
        ret.assertArray();

        SnapshotInfo* info = (SnapshotInfo*)user_data;
        SBCCallLeg* leg = dynamic_cast<SBCCallLeg*>(session);
        if(!leg) return;

        if(!leg->isALeg()) return;

        auto call_ctx = leg->getCallCtx();
        if(!call_ctx) return;
        if(!call_ctx->cdr) return;

        info->cdr_list->snapshot_id.fields.counter++;
        auto &gc = Yeti::instance().config;
        ret.push(AmArg());
        AmArg &call = ret.back();
        call["id"] = info->cdr_list->snapshot_id.v;

        call["snapshot_timestamp"] = info->snapshot_timestamp_str;
        call["snapshot_date"] = info->snapshot_date_str;
        call["node_id"] = AmConfig.node_id;
        call["pop_id"] = gc.pop_id;

        if(info->cdr_list->snapshots_buffering)
            call["buffered"] = false;

        const DynFieldsT &df = info->cdr_list->router->getDynFields();
        if(info->cdr_list->snapshots_fields_whitelist.empty()) {
            call_ctx->cdr->snapshot_info(call,df);
            call[end_time_key] = info->snapshot_timestamp_str;
        } else {
            call_ctx->cdr->snapshot_info_filtered(call,df,info->cdr_list->snapshots_fields_whitelist);
            if(info->cdr_list->snapshots_fields_whitelist.count(end_time_key))
                call[end_time_key] = info->snapshot_timestamp_str;
        }
    }, [](const AmArg& ret, void* user_data)
	{
        SnapshotInfo* info = (SnapshotInfo*)user_data;
		for(int i = 0 ; i < ret.size(); i++) {
			for(int j = 0 ; j < ret[i].size(); j++)
			info->calls.push(ret[i][j]);
		}
        info->cdr_list->sendSnapshot(info->calls);
        delete info;
    }, info);
}

void CdrList::sendSnapshot(const AmArg& calls) {
    //serialize to json body for clickhouse
    string data = snapshots_body_header;
    for(unsigned int i = 0;i < calls.size();i++)
        data+=arg2json(calls[i])+"\n";

    //DBG("data:\n%s",data.c_str());

    for(const auto &destination: snapshots_destinations) {
        if(!AmSessionContainer::instance()->postEvent(
            HTTP_EVENT_QUEUE,
            new HttpPostEvent(
                destination,
                data,
                string())))
        {
            ERROR("can't post http event. disable active calls snapshots or add http_client module loading");
        }
    }
}

void CdrList::cdr2arg(AmArg& arg, const Cdr *cdr, const get_calls_ctx &ctx) const noexcept
{
    #define add_field(val)\
        arg[#val] = cdr->val;
    #define add_timeval_field(val)\
        arg[#val] = timeval2double(cdr->val);

    struct timeval duration;
    double duration_double;

    arg.assertStruct();

    arg["node_id"] = ctx.node_id;
    arg["pop_id"] = ctx.pop_id;

    //!added for compatibility with old versions of web interface
    arg["local_time"] = timeval2double(ctx.now);

    add_timeval_field(cdr_born_time);
    add_timeval_field(start_time);
    add_timeval_field(end_time);

    const struct timeval &connect_time = cdr->connect_time;
    arg["connect_time"] = timeval2double(connect_time);
    if(timerisset(&connect_time)) {
        timersub(&ctx.now,&connect_time,&duration);
        duration_double = timeval2double(duration);
        if(duration_double<0) duration_double = 0;
        arg["duration"] = duration_double;
    } else {
        arg["duration"] = AmArg();
    }

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
    add_field(audio_record_enabled);

    add_field(attempt_num);

    add_field(resources);
    add_field(active_resources);
    arg["active_resources_json"] = cdr->active_resources_amarg;

    add_field(disconnect_initiator);
    add_field(disconnect_code);
    add_field(disconnect_reason);
    add_field(disconnect_internal_code);
    add_field(disconnect_internal_reason);

    //cdr->add_versions_to_amarg(arg);

    const DynFieldsT &df = ctx.router->getDynFields();
    for(const auto &dit: df) {
        const string &fname = dit.name;
        AmArg &f = cdr->dyn_fields[fname];
        if(f.getType()==AmArg::Undef && (dit.type_id==DynField::VARCHAR))
            arg[fname] = "";
        arg[fname] = f;
    }

    #undef add_timeval_field
    #undef add_field
}

void CdrList::cdr2arg_filtered(AmArg& arg, const Cdr *cdr, const get_calls_ctx &ctx) const noexcept
{
    #define filter(val)\
        if(::find(wanted_fields.begin(),wanted_fields.end(),val)!=wanted_fields.end())
    #define add_field(val)\
        filter(#val)\
        arg[#val] = cdr->val;
    #define add_timeval_field(val)\
        filter(#val)\
            arg[#val] = timeval2double(cdr->val);

    struct timeval duration;
    double duration_double;
    const vector<string> &wanted_fields = *ctx.fields;
    (void)wanted_fields;

    arg.assertStruct();

    if(ctx.fields->empty())
        return;

    filter("node_id") arg["node_id"] = ctx.node_id;
    filter("pop_id") arg["pop_id"] = ctx.pop_id;

    //!added for compatibility with old versions of web interface
    filter("local_time") arg["local_time"] = timeval2double(ctx.now);


    add_timeval_field(cdr_born_time);
    add_timeval_field(start_time);
    add_timeval_field(end_time);

    const struct timeval &connect_time = cdr->connect_time;
    filter("connect_time") arg["connect_time"] = timeval2double(connect_time);
    filter("duration") {
        if(timerisset(&connect_time)){
            timersub(&ctx.now,&connect_time,&duration);
            duration_double = timeval2double(duration);
            if(duration_double<0) duration_double = 0;
            arg["duration"] = duration_double;
        } else {
            arg["duration"] = AmArg();
        }
    }

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
    add_field(audio_record_enabled);

    add_field(attempt_num);

    add_field(resources);
    add_field(active_resources);
    filter("active_resources_json") arg["active_resources_json"] = cdr->active_resources_amarg;

    //filter("versions") cdr->add_versions_to_amarg(arg);

    const DynFieldsT &df = ctx.router->getDynFields();
    for(const auto &dit: df) {
        const string &fname = dit.name;
        filter(fname) {
            AmArg &f = cdr->dyn_fields[fname];
            if(f.getType()==AmArg::Undef && (dit.type_id==DynField::VARCHAR))
                arg[fname] = "";
            arg[fname] = f;
        }
    }

    #undef add_timeval_field
    #undef add_field
    #undef filter
}
