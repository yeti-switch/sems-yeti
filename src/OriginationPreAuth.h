#pragma once

#include "cfg/YetiCfg.h"
#include "IPTree.h"

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
        /*string orig_ip;
        int orig_port;
        int orig_proto;*/
        bool require_incoming_auth;
        bool require_identity_parsing;
    };

    OriginationPreAuth(YetiCfg &cfg);
    void reloadDatabaseSettings(pqxx::connection &c) noexcept;

    void ShowTrustedBalancers(AmArg& ret);
    void ShowIPAuth(AmArg& ret);

    bool onInvite(const AmSipRequest &req, Reply &reply);
};
