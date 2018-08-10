#pragma once

#include <AmThread.h>
#include <sems.h>
#include "CdrFilter.h"
#include "../cdr/Cdr.h"
#include "../SqlRouter.h"
#include "../yeti_version.h"

#include <unordered_set>
#include <unordered_map>

class CdrList
  : public AmThread,
    private AmMutex,
    private std::unordered_map<string, Cdr *>
{
    int epoll_fd;
    bool snapshots_enabled;
    bool snapshots_buffering;
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

    typedef queue<Cdr> PostponedCdrsContainer;
    PostponedCdrsContainer postponed_active_calls;
    AmMutex postponed_active_calls_mutex;

    enum get_calls_type {
      Unfiltered, Filtered
    };

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
    void cdr2arg(AmArg& arg, const Cdr *cdr, const get_calls_ctx &ctx) const;
    void cdr2arg_filtered(AmArg& arg, const Cdr *cdr, const get_calls_ctx &ctx) const;

    void parse_field(const AmArg &field);

  public:
    CdrList();
    ~CdrList();

    long int getCallsCount();
    void getCalls(AmArg &calls, int limit, const SqlRouter *router);
    void getCallsFields(AmArg &calls, int limit,const SqlRouter *router, const AmArg &params);
    int getCall(const string &local_tag, AmArg &call, const SqlRouter *router);

    int insert(Cdr *cdr);
    bool remove(Cdr *cdr);

    void getFields(AmArg &ret,SqlRouter *r);
    void validate_fields(const vector<string> &wanted_fields, const SqlRouter *router);

    int configure(AmConfigReader &cfg);
    void run();
    void on_stop();
    void onTimer();

    bool getSnapshotsEnabled() { return snapshots_enabled; }
};
