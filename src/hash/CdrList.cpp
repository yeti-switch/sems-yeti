#include "CdrList.h"
#include "log.h"
#include "../yeti.h"
#include "jsonArg.h"
#include "AmSessionContainer.h"
#include "ampi/HttpClientAPI.h"

#define SNAPSHOTS_PERIOD_DEFAULT 60
#define EPOLL_MAX_EVENTS 2048

CdrList::CdrList()
  : stopped(false),
    epoll_fd(0),
    snapshots_enabled(false),
    snapshots_buffering(false),
    snapshots_interval(0),
    last_snapshot_ts(0)
{ }

CdrList::~CdrList()
{ }

int CdrList::insert(Cdr *cdr)
{
    if(!cdr) {
        ERROR("%s() cdr = NULL",FUNC_NAME);
        log_stacktrace(L_ERR);
        return 1;
    }

    DBG("insert(%p, %s)",cdr,cdr->local_tag.c_str());

    AmLock l(*cdr);

    lock();
    auto i = emplace(cdr->local_tag,cdr);
    unlock();

    if(!i.second) {
        ERROR("attempt to double insert cdr with local_tag '%s' "
              "into active calls list. integrity threat",
              cdr->local_tag.c_str());
        log_stacktrace(L_ERR);
        return 1;
    }
    cdr->inserted2list = true;
    return 0;
}

bool CdrList::remove(Cdr *cdr)
{
    if(!cdr) {
        WARN("nullptr passed as active call to remove");
        return false;
    }

    DBG("remove(%p, %s)",cdr,cdr->local_tag.c_str());

    AmLock cdr_lock(*cdr);

    if(!cdr->inserted2list) {
        DBG("attempt to remove active call with cleared inserted2list flag: %s",
             cdr->local_tag.c_str());
        return false;
    }

    AmLock l(*this);

    if(erase(cdr->local_tag)) {
        if(snapshots_buffering)
            postponed_active_calls.emplace(*cdr);
        cdr->inserted2list = false;
        return true;
    } else {
        WARN("attempt to remove unknown active call: %s",
             cdr->local_tag.c_str());
    }

    return false;
}

long int CdrList::getCallsCount()
{
    AmLock l(*this);
    return size();
}

int CdrList::getCall(const string &local_tag,AmArg &call,const SqlRouter *router)
{
    Yeti::global_config &gc = Yeti::instance().config;
    const get_calls_ctx ctx(gc.node_id,gc.pop_id,router);

    AmLock l(*this);

    auto it = find(local_tag);
    if(it == end()) return 0;

    cdr2arg(call,it->second,ctx);
    return 1;
}

void CdrList::getCalls(AmArg &calls,int limit,const SqlRouter *router)
{
    int i = limit;
    Yeti::global_config &gc = Yeti::instance().config;

    const get_calls_ctx ctx(gc.node_id,gc.pop_id,router);

    calls.assertArray();

    PROF_START(calls_serialization);

    lock();
    for(const auto &it: *this) {
        if(!i--) {
            ERROR("active calls serialization reached limit: %d. calls count: %zd",
                  limit,size());
            break;
        }
        calls.push(AmArg());
        cdr2arg(calls.back(),it.second,ctx);
    }
    unlock();

    PROF_END(calls_serialization);
    PROF_PRINT("active calls serialization",calls_serialization);
}

void CdrList::getCallsFields(
    AmArg &calls,int limit,
    const SqlRouter *router, const AmArg &params)
{
    calls.assertArray();
    int i = limit;
    Yeti::global_config &gc = Yeti::instance().config;

    cmp_rules filter_rules;
    vector<string> fields;

    parse_fields(filter_rules, params, fields);

    validate_fields(fields,router);

    const get_calls_ctx ctx(gc.node_id,gc.pop_id,router,&fields);

    PROF_START(calls_serialization);

    lock();
    for(const auto &it: *this) {
        if(!i--) {
            ERROR("active calls serialization reached limit: %d. calls count: %zd",
                  limit,size());
            break;
        }
        if(apply_filter_rules(it.second,filter_rules)) {
            calls.push(AmArg());
            cdr2arg_filtered(calls.back(),it.second,ctx);
        }
    }
    unlock();

    PROF_END(calls_serialization);
    PROF_PRINT("active calls serialization",calls_serialization);
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

int CdrList::configure(AmConfigReader &cfg)
{
    if(!cfg.hasParameter("active_calls_clickhouse_queue")
       || !cfg.hasParameter("active_calls_clickhouse_table"))
    {
        DBG("need both table and queue parameters "
            "to enable active calls snapshots for clickhouse");
        return 0;
    }

    snapshots_enabled = true;
    router = &Yeti::instance().router;

    snapshots_destination = cfg.getParameter("active_calls_clickhouse_queue");
    snapshots_table = cfg.getParameter("active_calls_clickhouse_table","active_calls");
    snapshots_interval = cfg.getParameterInt("active_calls_period",
                                             SNAPSHOTS_PERIOD_DEFAULT);
    snapshots_buffering = 1==cfg.getParameterInt("active_calls_clickhouse_buffering");

    if(0==snapshots_interval) {
        ERROR("invalid active calls snapshots period: %d",snapshots_interval);
        return -1;
    }

    auto allowed_fields = explode(cfg.getParameter("active_calls_clickhouse_allowed_fields"),",");
    for(const auto &f: allowed_fields)
        snapshots_fields_whitelist.emplace(f);

    DBG("use queue '%s', table '%s' for active calls snapshots "
        "with interval %d (seconds). "
        "buffering is %sabled",
        snapshots_destination.c_str(),
        snapshots_table.c_str(),
        snapshots_interval,
        snapshots_buffering?"en":"dis");

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
            ERROR("epoll_wait: %s\n",strerror(errno));
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
    static struct timeval tv; //fake call interval end value
    u_int64_t now = wheeltimer::instance()->unix_clock.get();
    u_int64_t snapshot_ts = now - (now % snapshots_interval);

    string data, snapshot_timestamp_str, snapshot_date_str;

    if(last_snapshot_ts && last_snapshot_ts==snapshot_ts){
        ERROR("duplicate snapshot %lu timestamp. "
              "ignore timer event (can lead to time gap between snapshots)",
              snapshot_ts);
        return;
    }

    last_snapshot_ts = snapshot_ts;

    tv.tv_usec = 0;
    tv.tv_sec = snapshot_ts;
    ts = snapshot_ts;
    localtime_r(&ts,&t);

    len = strftime(strftime_buf, sizeof strftime_buf, "%F %T", &t);
    snapshot_timestamp_str = string(strftime_buf, len);

    len = strftime(strftime_buf, sizeof strftime_buf, "%F", &t);
    snapshot_date_str = string(strftime_buf, len);

    Yeti::global_config &gc = Yeti::instance().config;
    const DynFieldsT &df = router->getDynFields();

    AmArg calls;
    calls.assertArray();

    lock();

    if(snapshots_buffering)
        local_postponed_calls.swap(postponed_active_calls);

    if(empty() &&
       (!snapshots_buffering || local_postponed_calls.empty()))
    {
        unlock();
        return;
    }

    //serialize to AmArg
    for(const auto &it: *this) {
        Cdr &cdr = *(it.second);
        calls.push(AmArg());
        AmArg &call = calls.back();

        call["snapshot_timestamp"] = snapshot_timestamp_str;
        call["snapshot_date"] = snapshot_date_str;
        call["node_id"] = gc.node_id;
        call["pop_id"] = gc.pop_id;

        if(snapshots_buffering)
            call["buffered"] = false;

        if(snapshots_fields_whitelist.empty()) {
            cdr.snapshot_info(call,df);
            call[end_time_key] = snapshot_timestamp_str;
        } else {
            cdr.snapshot_info_filtered(call,df,snapshots_fields_whitelist);
            if(snapshots_fields_whitelist.count(end_time_key))
                call[end_time_key] = snapshot_timestamp_str;
        }
    }

    unlock();

    if(snapshots_buffering) {
        while(!local_postponed_calls.empty()) {
            const Cdr &cdr = local_postponed_calls.front();

            calls.push(AmArg());
            AmArg &call = calls.back();

            call["snapshot_timestamp"] = snapshot_timestamp_str;
            call["snapshot_date"] = snapshot_date_str;
            call["node_id"] = gc.node_id;
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

    //serialize to json body for clickhouse
    data = snapshots_body_header;
    for(int i = 0;i< calls.size();i++)
        data+=arg2json(calls[i])+"\n";

    //DBG("data:\n%s",data.c_str());

    if(!AmSessionContainer::instance()->postEvent(
      HTTP_EVENT_QUEUE,
      new HttpPostEvent(
        snapshots_destination,
        data,
        string())))
    {
        ERROR("can't post http event. disable active calls snapshots or add http_client module loading");
    }
}

inline void CdrList::cdr2arg(AmArg& arg, const Cdr *cdr, const get_calls_ctx &ctx) const
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

inline void CdrList::cdr2arg_filtered(AmArg& arg, const Cdr *cdr, const get_calls_ctx &ctx) const
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
