#ifndef RESOURCECONTROL_H
#define RESOURCECONTROL_H

#include "AmConfigReader.h"
#include "ResourceRedisConnection.h"
#include "AmArg.h"
#include <map>
#include "log.h"
#include "../db/DbConfig.h"

using namespace std;

#define ANY_VALUE -1

#define ResourceAction_Reject    1
#define ResourceAction_NextRoute 2
#define ResourceAction_Accept    3

struct ResourceConfig {
    int    id;
    string name;
    int    internal_code_id;
    enum ActionType { Reject = 0, NextRoute, Accept } action;
    string str_action;
    enum ResourceType { ResLimit, ResRateLimit } type;

    ResourceConfig(int i, string n, int internal_code_id, int a, ResourceType type)
        : id(i)
        , name(n)
        , internal_code_id(internal_code_id)
        , type(type)
    {
        set_action(a);
    }
    ResourceConfig()
        : id(0)
        , internal_code_id(0)
    {
    }
    void   set_action(int a);
    string print() const;
};

enum ResourceCtlResponse { RES_CTL_OK, RES_CTL_NEXT, RES_CTL_REJECT, RES_CTL_ERROR };

class ResourceControl {
    ResourceRedisConnection  redis_conn;
    map<int, ResourceConfig> type2cfg;

    struct handlers_entry {
        ResourceList   resources;
        string         owner_tag;
        struct timeval created_at;
        bool           valid;

        handlers_entry(const ResourceList &l, const string &tag)
            : resources(l)
            , owner_tag(tag)
            , valid(true)
        {
            gettimeofday(&created_at, NULL);
        }
        void invalidate() { valid = false; }
        bool is_valid() { return valid; }
        void info(AmArg &a, const struct timeval &now) const;
    };
    typedef map<string, handlers_entry> Handlers;
    typedef Handlers::const_iterator    HandlersIt;

    void handler_info(const HandlersIt &i, const struct timeval &now, AmArg &a) const;

    Handlers          handlers;
    AmMutex           handlers_mutex;
    AmCondition<bool> container_ready;

    void replace(string &s, const string &from, const string &to);
    int  load_resources_config();
    int  reject_on_error;

    struct {
        unsigned int hits;
        unsigned int overloaded;
        unsigned int rejected;
        unsigned int nextroute;
        unsigned int errors;
        void         clear()
        {
            hits       = 0;
            overloaded = 0;
            rejected   = 0;
            nextroute  = 0;
            errors     = 0;
        }
        void get(AmArg &arg)
        {
            arg["hits"]       = (long)hits;
            arg["overloaded"] = (long)overloaded;
            arg["rejected"]   = (long)rejected;
            arg["nextroute"]  = (long)nextroute;
            arg["errors"]     = (long)errors;
        }
    } stat;

  public:
    ResourceControl();

    int  configure(cfg_t *confuse_cfg, AmConfigReader &cfg);
    void start();
    void stop();
    void invalidate_resources();
    bool invalidate_resources_rpc();
    void on_resources_initialized();
    void on_resources_disconnected();

    void eval_resources(ResourceList &rl) const;

    void replace(string &s, Resource &r, const ResourceConfig &rc);

    ResourceCtlResponse get(ResourceList &rl, string &handler, const string &owner_tag, ResourceConfig &resource_config,
                            ResourceList::iterator &rli);

    // void put(ResourceList &rl);
    void put(const string &handler);

    void GetConfig(AmArg &ret, bool types_only = false);
    void clearStats();
    void getStats(AmArg &ret);
    bool getResourceState(const string &connection_id, const AmArg &request_id, const AmArg &params);
    void showResources(AmArg &ret);
    void showResourceByHandler(const string &h, AmArg &ret);
    void showResourceByLocalTag(const string &tag, AmArg &ret);
    void showResourcesById(int id, AmArg &ret);
    const ResourceRedisConnection &getRedisConn() { return redis_conn; };
};

#endif // RESOURCECONTROL_H
