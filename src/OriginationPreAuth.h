#pragma once

#include "cfg/YetiCfg.h"
#include "IPTree.h"
#include "DbConfigStates.h"

#include <pqxx/pqxx>

#include <chrono>
#include <cstdint>

class OriginationPreAuth final
{
    YetiCfg &ycfg;

    struct LoadBalancerData {
        unsigned long id;
        string name;
        string signalling_ip;

        LoadBalancerData(const pqxx::row &r);
        operator AmArg() const;
    };
    using LoadBalancersContainer = vector<LoadBalancerData>;

    struct IPAuthData {
        string ip;
        AmSubnet subnet;
        string x_yeti_auth;
        bool require_incoming_auth;
        bool require_identity_parsing;

        IPAuthData(const pqxx::row &r);
        operator AmArg() const;
    };
    using IPAuthDataContainer = vector<IPAuthData>;

    LoadBalancersContainer load_balancers;
    IPAuthDataContainer ip_auths;
    AmMutex mutex;
    IPTree subnets_tree;

  public:
    struct Reply {
        string orig_ip;
        string x_yeti_auth;
        bool require_incoming_auth;
        bool require_identity_parsing;
    };

    OriginationPreAuth(YetiCfg &cfg);
    void reloadDatabaseSettings(pqxx::connection &c,
                                bool reload_load_balancers,
                                bool reload_ip_auth) noexcept;

    void ShowTrustedBalancers(AmArg& ret);
    void ShowIPAuth(const AmArg &arg, AmArg& ret);

    bool onInvite(const AmSipRequest &req, Reply &reply);
};
