#pragma once

#include "SqlRouter.h"
#include "HttpSequencer.h"
#include "OptionsProberManager.h"
#include "hash/CdrList.h"
#include "resources/ResourceControl.h"
#include "CertCache.h"
#include "OriginationPreAuth.h"
#include "GatewaysCache.h"
#include "cdr/CdrHeaders.h"
#include "cfg/YetiCfg.h"

#include "AmConfigReader.h"

#include <ctime>

#include "log.h"

static const string YETI_QUEUE_NAME(MOD_NAME);
extern const string yeti_routing_pg_worker;
extern const string yeti_cdr_pg_worker;
extern const string yeti_auth_log_pg_worker;
bool yeti_routing_db_query(const string &query, const string &token);

#define YETI_ENABLE_PROFILING 1

#define YETI_CALL_DURATION_TIMER SBC_TIMER_ID_CALL_TIMERS_START
#define YETI_RINGING_TIMEOUT_TIMER (SBC_TIMER_ID_CALL_TIMERS_START+1)
#define YETI_RADIUS_INTERIM_TIMER (SBC_TIMER_ID_CALL_TIMERS_START+2)
#define YETI_FAKE_RINGING_TIMER (SBC_TIMER_ID_CALL_TIMERS_START+3)
#define YETI_REFER_TIMEOUT_TIMER (SBC_TIMER_ID_CALL_TIMERS_START+4)

#if YETI_ENABLE_PROFILING

#define PROF_START(var) timeval prof_start_ ## var; gettimeofday(&prof_start_ ## var,nullptr);
#define PROF_END(var) timeval prof_end_ ## var; gettimeofday(&prof_end_ ## var,nullptr);
#define PROF_DIFF(var) timeval prof_diff_ ## var; timersub(&prof_end_ ## var,&prof_start_ ## var,&prof_diff_ ## var);
#define PROF_PRINT(descr,var) PROF_DIFF(var); DBG("PROFILING: " descr " took %s",timeval2str_usec(prof_diff_ ## var).c_str());

#else

#define PROF_START(var) ;
#define PROF_END(var) ;
#define PROF_DIFF(var) (-1)
#define PROF_PRINT(descr,var) ;

#endif

class YetiComponentInited : public AmEvent
{
public:
    enum ComponentType
    {
        Resource = 0,
        MaxType
    } type;
    YetiComponentInited(ComponentType type) : AmEvent(0), type(type) {}
};

struct YetiBase {
    YetiBase()
      : configuration_finished(false),
        confuse_cfg(nullptr),
        orig_pre_auth(config)
    { 
        memset(component_inited, 0, sizeof(bool)*YetiComponentInited::MaxType); 
    }

    bool component_inited[YetiComponentInited::MaxType];
    SqlRouter router;
    CdrList cdr_list;
    ResourceControl rctl;

    bool configuration_finished;

    YetiCfg config;
    AmArg db_cfg_states;
    //DbConfigStates db_cfg_states;

    cfg_t *confuse_cfg;
    AmConfigReader cfg;
    time_t start_time;

    HttpSequencer http_sequencer;
    OptionsProberManager options_prober_manager;
    CertCache cert_cache;
    OriginationPreAuth orig_pre_auth;
    GatewaysCache gateways_cache;

    //fields to provide synchronous configuration for DB-related entities
    struct sync_db {
        enum DbReplyResult {
            DB_REPLY_WAITING = 0,
            DB_REPLY_RESULT,
            DB_REPLY_ERROR,
            DB_REPLY_TIMEOUT
        };
        AmCondition<DbReplyResult> db_reply_condition;
        string db_reply_token;
        AmArg db_reply_result;

        int exec_query(const string &query, const string &token);
    } sync_db;
};
