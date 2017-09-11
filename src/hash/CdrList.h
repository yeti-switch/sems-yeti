#ifndef _CdrList_H
#define _CdrList_H

#include <AmThread.h>
#include "../cdr/Cdr.h"
#include "../SqlRouter.h"
#include "CdrFilter.h"
#include "MurmurHash.h"
#include "sems.h"
#include "../yeti_version.h"

#include <unordered_set>

class CdrList:
  public MurmurHash<string,string,Cdr>,
  public AmThread
{
  public:
    CdrList(unsigned long buckets = 65000);
	~CdrList();
	
	Cdr *get_by_local_tag(string local_tag);

	struct get_calls_ctx {
		struct timeval now;
		int node_id, pop_id;
		const SqlRouter *router;
		const vector<string> *fields;
		get_calls_ctx(
			int node_id, int pop_id,
			const SqlRouter *router,
			const vector<string> *fields = NULL) :
			node_id(node_id), pop_id(pop_id),
			router(router),
			fields(fields)
		{
			gettimeofday(&now,NULL);
		}
	};
	void getCalls(AmArg &calls,int limit,const SqlRouter *router);
	void getCallsFields(AmArg &calls,int limit,const SqlRouter *router, const AmArg &params);
	int getCall(const string &local_tag,AmArg &call,const SqlRouter *router);
	int insert(Cdr *cdr);
	int erase(Cdr *cdr);
	bool erase_unsafe(Cdr *cdr);

	void getFields(AmArg &ret,SqlRouter *r);
	void validate_fields(const vector<string> &wanted_fields, const SqlRouter *router);

    int configure(AmConfigReader &cfg);
    void run();
    void on_stop();
    void onTimer();

    bool getSnapshotsEnabled() { return snapshots_enabled; }

  protected:

	uint64_t hash_lookup_key(const string *key);
	bool cmp_lookup_key(const string *k1,const string *k2);
	void init_key(string **dest,const string *src);
	void free_key(string *key);

  private:

    int epoll_fd;
    bool snapshots_enabled;
    bool snapshots_timelines;
    unsigned int snapshots_interval;
    string snapshots_destination;
    string snapshots_table;
    string snapshots_body_header;
    unordered_set<string> snapshots_fields_whitelist;
    u_int64_t last_snapshot_ts;
    AmEventFd stop_event;
    AmTimerFd timer;
    AmCondition<bool> stopped;
    SqlRouter *router;

    typedef vector<Cdr> PostponedCdrsContainer;
    PostponedCdrsContainer postponed_active_calls;
    AmMutex postponed_active_calls_mutex;

	enum get_calls_type {
		Unfiltered, Filtered
	};

	template <int get_type>
	void cdr2arg(AmArg& arg, const Cdr *cdr, const get_calls_ctx &ctx) const;

	void parse_field(const AmArg &field);
};

template <>
inline void CdrList::cdr2arg<CdrList::Filtered>(AmArg& arg, const Cdr *cdr, const get_calls_ctx &ctx) const
{
	#define filter(val)\
		if(find(wanted_fields.begin(),wanted_fields.end(),val)!=wanted_fields.end())
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
	for(DynFieldsT::const_iterator dit = df.begin(); dit!=df.end(); dit++){
		const string &fname = (*dit).name;
		filter(fname) {
			AmArg &f = cdr->dyn_fields[fname];
			if(f.getType()==AmArg::Undef && ((*dit).type_id==DynField::VARCHAR))
				arg[fname] = "";
			arg[fname] = f;
		}
	}

	#undef add_field
	#undef add_timeval_field
	#undef filter
}

template <>
inline void CdrList::cdr2arg<CdrList::Unfiltered>(AmArg& arg, const Cdr *cdr, const get_calls_ctx &ctx) const
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
	if(timerisset(&connect_time)){
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
	for(DynFieldsT::const_iterator dit = df.begin(); dit!=df.end(); dit++){
		const string &fname = (*dit).name;
		AmArg &f = cdr->dyn_fields[fname];
		if(f.getType()==AmArg::Undef && ((*dit).type_id==DynField::VARCHAR))
			arg[fname] = "";
		arg[fname] = f;
	}

	#undef add_field
	#undef add_timeval_field
}

#endif

