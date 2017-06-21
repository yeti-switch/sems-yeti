#include "CdrList.h"
#include "log.h"
#include "../yeti.h"
#include "jsonArg.h"
#include "AmSessionContainer.h"
#include "ampi/HttpClientAPI.h"

#define SNAPSHOTS_PERIOD_DEFAULT 60
#define EPOLL_MAX_EVENTS 2048

CdrList::CdrList(unsigned long buckets)
  : MurmurHash<string,string,Cdr>(buckets),
    stopped(false),
    epoll_fd(0),
    snapshots_enabled(false),
    snapshots_interval(0),
    last_snapshot_ts(0)
{ }

CdrList::~CdrList()
{ }

uint64_t CdrList::hash_lookup_key(const string *key){
	//!got segfault due to invalid key->size() value. do not trust it
	//return hashfn(key->c_str(),key->size());
	const char *s = key->c_str();
	return hashfn(s,strlen(s));
}

bool CdrList::cmp_lookup_key(const string *k1,const string *k2){
	return *k1 == *k2;
}

void CdrList::init_key(string **dest,const string *src){
	*dest = new string;
	(*dest)->assign(*src);
}

void CdrList::free_key(string *key){
	delete key;
}

int CdrList::insert(Cdr *cdr){
	int err = 1;
	if(cdr){
		DBG("%s() local_tag = %s",FUNC_NAME,cdr->local_tag.c_str());
		cdr->lock();
			if(!cdr->inserted2list && MurmurHash::insert(&cdr->local_tag,cdr,true,true)){
				err = 0;
				cdr->inserted2list = true;
			} else {
				ERROR("attempt to double insert cdr with local_tag '%s' into active calls list. integrity threat",
					  cdr->local_tag.c_str());
				log_stacktrace(L_ERR);
			}
		cdr->unlock();
	} else {
		ERROR("%s() cdr = NULL",FUNC_NAME);
		log_stacktrace(L_ERR);
	}
	return err;
}

void CdrList::erase_unsafe(const string &local_tag, bool locked){
	erase_lookup_key(&local_tag, locked);
}

int CdrList::erase(Cdr *cdr){
	int err = 1;
	if(cdr){
		//DBG("%s() local_tag = %s",FUNC_NAME,cdr->local_tag.c_str());
		cdr->lock();
			if(cdr->inserted2list){
				//erase_lookup_key(&cdr->local_tag);
				erase_unsafe(cdr->local_tag);
				err = 0;
			} else {
				//ERROR("attempt to erase not inserted cdr local_tag = %s",cdr->local_tag.c_str());
				//log_stacktrace(L_ERR);
			}
		cdr->unlock();
	} else {
		//ERROR("CdrList::%s() cdr = NULL",FUNC_NAME);
		//log_stacktrace(L_ERR);
	}
	return err;
}

Cdr *CdrList::get_by_local_tag(string local_tag){
	return at_data(&local_tag,false);
}

int CdrList::getCall(const string &local_tag,AmArg &call,const SqlRouter *router){
	Cdr *cdr;
	int ret = 0;
	lock();
	if((cdr = get_by_local_tag(local_tag))){
		Yeti::global_config &gc = Yeti::instance().config;
		const get_calls_ctx ctx(gc.node_id,gc.pop_id,router);
		cdr2arg<Unfiltered>(call,cdr,ctx);
		ret = 1;
	}
	unlock();
	return ret;
}

void CdrList::getCalls(AmArg &calls,int limit,const SqlRouter *router){
	entry *e;
	int i = limit;
	Yeti::global_config &gc = Yeti::instance().config;

	const get_calls_ctx ctx(gc.node_id,gc.pop_id,router);

	calls.assertArray();

	PROF_START(calls_serialization);
	lock();
		e = first;
		while(e&&i--){
			calls.push(AmArg());
			cdr2arg<Unfiltered>(calls.back(),e->data,ctx);
			e = e->list_next;
		}
	unlock();
	PROF_END(calls_serialization);
	PROF_PRINT("active calls serialization",calls_serialization);
}

void CdrList::getCallsFields(AmArg &calls,int limit,const SqlRouter *router, const AmArg &params){
	entry *e;

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
		e = first;
		while(e&&i--){
			Cdr *cdr = e->data;
			if(apply_filter_rules(cdr,filter_rules)){
				calls.push(AmArg());
				cdr2arg<Filtered>(calls.back(),e->data,ctx);
			}
			e = e->list_next;
		}
	unlock();
	PROF_END(calls_serialization);
	PROF_PRINT("active calls serialization",calls_serialization);
}

void CdrList::getFields(AmArg &ret,SqlRouter *r){
	ret.assertStruct();

	for(const static_call_field *f = static_call_fields; f->name; f++){
		AmArg &a = ret[f->name];
		a["type"] = f->type;
		a["is_dynamic"] = false;
	}

	const DynFieldsT &router_dyn_fields = r->getDynFields();
	for(DynFieldsT::const_iterator it = router_dyn_fields.begin();
			it!=router_dyn_fields.end();++it)
	{
		AmArg &a = ret[it->name];
		a["type"] = it->type_name;
		a["is_dynamic"] = true;
	}
}

void CdrList::validate_fields(const vector<string> &wanted_fields, const SqlRouter *router){
	bool ret = true;
	AmArg failed_fields;
	const DynFieldsT &df = router->getDynFields();
	for(vector<string>::const_iterator i = wanted_fields.begin();
			i!=wanted_fields.end();++i){
		const string &f = *i;
		int k = static_call_fields_count-1;
		for(;k>=0;k--){
			if(f==static_call_fields[k].name)
				break;
		}
		if(k<0){
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
	if(!ret){
		throw std::string(string("passed one or more unknown fields:")+AmArg::print(failed_fields));
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

    router = &Yeti::instance().router;

    snapshots_destination = cfg.getParameter("active_calls_clickhouse_queue");
    snapshots_table = cfg.getParameter("active_calls_clickhouse_table","active_calls");
    snapshots_interval = cfg.getParameterInt("active_calls_period",
                                             SNAPSHOTS_PERIOD_DEFAULT);

    if(0==snapshots_interval) {
        ERROR("invalid active calls snapshots period: %d",snapshots_interval);
        return -1;
    }

    auto allowed_fields = explode(cfg.getParameter("active_calls_clickhouse_allowed_fields"),",");
    for(const auto &f: allowed_fields)
        snapshots_fields_whitelist.emplace(f);

    DBG("use queue '%s', table '%s' for active calls snapshots with interval %d (seconds)",
        snapshots_destination.c_str(),
        snapshots_table.c_str(),
        snapshots_interval);

    for(const auto &f: snapshots_fields_whitelist) {
        DBG("clickhouse allowed_field: %s",f.c_str());
    }

    snapshots_enabled = true;

    snapshots_body_header = "INSERT INTO ";
    snapshots_body_header += snapshots_table + " FORMAT JSONEachRow\n";

    if((epoll_fd = epoll_create(2)) == -1)
    {
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
    string data;
    string snapshot_timestamp_str, snapshot_date_str;
    u_int64_t now = wheeltimer::instance()->unix_clock.get();
    u_int64_t snapshot_ts = now - (now % snapshots_interval);

    if(last_snapshot_ts && last_snapshot_ts==snapshot_ts){
        ERROR("duplicate snapshot %llu timestamp. "
              "ignore timer event (can lead to time gap between snapshots)",
              snapshot_ts);
        return;
    }

    last_snapshot_ts = snapshot_ts;

    {
        int len;
        char s[64];
        static struct tm t;

        time_t ts = snapshot_ts;
        localtime_r(&ts,&t);

        len = strftime(s, sizeof s, "%F %T", &t);
        snapshot_timestamp_str = string(s, len);

        len = strftime(s, sizeof s, "%F", &t);
        snapshot_date_str = string(s, len);
    }

    Yeti::global_config &gc = Yeti::instance().config;
    const DynFieldsT &df = router->getDynFields();

    AmArg calls;
    calls.assertArray();

    lock();
    entry *e = first;
    if(!e) {
        unlock();
        return;
    }
    data = snapshots_body_header;
    //serialize to AmArg
    if(snapshots_fields_whitelist.empty()) {
        for(; e; e = e->list_next) {
            calls.push(AmArg());
            AmArg &call = calls.back();
            call["snapshot_timestamp"] = snapshot_timestamp_str;
            call["snapshot_date"] = snapshot_date_str;
            call["node_id"] = gc.node_id;
            call["pop_id"] = gc.pop_id;
            e->data->snapshot_info(call,df);
        }
    } else {
        for(; e; e = e->list_next) {
            calls.push(AmArg());
            AmArg &call = calls.back();
            call["snapshot_timestamp"] = snapshot_timestamp_str;
            call["snapshot_date"] = snapshot_date_str;
            call["node_id"] = gc.node_id;
            call["pop_id"] = gc.pop_id;
            e->data->snapshot_info_filtered(call,df,snapshots_fields_whitelist);
        }
    }
    unlock();

    //serialize to json body for clickhouse
    data = snapshots_body_header;
    for(int i = 0;i< calls.size();i++)
        data+=arg2json(calls[i])+"\n";

    DBG("data:\n%s",data.c_str());
    return;
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

