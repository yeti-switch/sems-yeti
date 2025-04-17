#pragma once

#include <AmThread.h>
#include <sems.h>
#include <yeti_version.h>

#include "CdrFilter.h"
#include "../cdr/Cdr.h"
#include "../SqlRouter.h"

#include <unordered_set>
#include <unordered_map>

class SBCCallLeg;

class CdrList
  : public AmThread,
    private AmMutex/*,
    private std::unordered_map<string, Cdr *>*/
{
    int epoll_fd;
    bool snapshots_enabled;
    bool snapshots_buffering;
    unsigned int snapshots_interval;
    vector<string> snapshots_destinations;
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

    union {
        uint64_t v;
        struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
            uint64_t counter:23;
            uint64_t timestamp:32;
            uint64_t node_id:8;
            uint64_t sign:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
            uint64_t sign:1;
            uint64_t node_id:8;
            uint64_t timestamp:32;
            uint64_t counter:23;
#else
# error "Please fix <bits/endian.h>"
#endif
        } fields;
    } snapshot_id;

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
    void cdr2arg(AmArg& arg, const Cdr *cdr, const get_calls_ctx &ctx) const noexcept;
    void cdr2arg_filtered(AmArg& arg, const Cdr *cdr, const get_calls_ctx &ctx) const noexcept;

    void parse_field(const AmArg &field);

  public:
    CdrList();
    ~CdrList();

    long int getCallsCount();
    bool getCall(SBCCallLeg* leg, AmArg& call, const SqlRouter *router);
    bool getCallsFields(SBCCallLeg* leg, AmArg &calls, const SqlRouter *router,
                        const cmp_rules& rules, const vector<string>& fields);

    void onSessionFinalize(Cdr *cdr);

    void getFields(AmArg &ret,SqlRouter *r);
    void validate_fields(const vector<string> &wanted_fields, const SqlRouter *router);
    void sendSnapshot(const AmArg& calls);

    int configure(cfg_t *confuse_cfg);
    void run();
    void on_stop();
    void onTimer();

    bool getSnapshotsEnabled() { return snapshots_enabled; }
};
