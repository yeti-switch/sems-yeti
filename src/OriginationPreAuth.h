#pragma once

#include "cfg/YetiCfg.h"
#include "IPTree.h"
#include "DbConfigStates.h"

#include <chrono>
#include <cstdint>

class OriginationPreAuth final {
    YetiCfg &ycfg;

    struct LoadBalancerData {
        unsigned long id;
        string        name;
        string        signalling_ip;

        LoadBalancerData(const AmArg &r);
        operator AmArg() const;
    };
    using LoadBalancersContainer = vector<LoadBalancerData>;

    struct IPAuthData {
        string   ip;
        AmSubnet subnet;
        string   x_yeti_auth;
        bool     require_incoming_auth;
        bool     require_identity_parsing;

        IPAuthData(const AmArg &r);
        operator AmArg() const;
    };
    using IPAuthDataContainer = vector<IPAuthData>;

    LoadBalancersContainer load_balancers;
    IPAuthDataContainer    ip_auths;
    AmMutex                mutex;
    IPTree                 subnets_tree;

  public:
    struct Reply {
        string orig_ip;
        string x_yeti_auth;
        string x_default_realm;
        bool   require_incoming_auth;
        bool   require_identity_parsing;
        bool   request_is_from_trusted_lb;
    };

    OriginationPreAuth(YetiCfg &cfg);
    void reloadLoadBalancers(const AmArg &data);
    void reloadLoadIPAuth(const AmArg &data);

    void ShowTrustedBalancers(AmArg &ret);
    void ShowIPAuth(const AmArg &arg, AmArg &ret);

    bool onRequest(const AmSipRequest &req, bool match_subnet, Reply &reply);
};
