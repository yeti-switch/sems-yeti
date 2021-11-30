#include "OriginationPreAuth.h"
#include "AmLcConfig.h"
#include "HeaderFilter.h"
#include <exception>

OriginationPreAuth::OriginationPreAuth(YetiCfg &ycfg)
  : ycfg(ycfg)
{}

OriginationPreAuth::LoadBalancerData::LoadBalancerData(const pqxx::row &r)
{
    id = r["id"].as<unsigned long>();
    name = r["name"].c_str();
    signalling_ip = r["signalling_ip"].c_str();
}

OriginationPreAuth::LoadBalancerData::operator AmArg() const
{
    AmArg a;
    a["id"] = id;
    a["name"] = name;
    a["signalling_ip"] = signalling_ip;
    return a;
}

OriginationPreAuth::IPAuthData::IPAuthData(const pqxx::row &r)
{
    ip = r["ip"].c_str();
    x_yeti_auth = r["x_yeti_auth"].c_str();
    require_incoming_auth = r["require_incoming_auth"].as<bool>();
    require_identity_parsing = r["require_identity_parsing"].as<bool>();
    if(!subnet.parse(ip))
        throw string("failed to parse IP");
}

OriginationPreAuth::IPAuthData::operator AmArg() const
{
    AmArg a;
    a["ip"] = ip;
    a["subnet"] = subnet;
    a["x_yeti_auth"] = x_yeti_auth;
    a["require_incoming_auth"] = require_incoming_auth;
    a["require_identity_parsing"] = require_identity_parsing;
    return a;
}

void OriginationPreAuth::reloadDatabaseSettings(pqxx::connection &c,
                                                bool reload_load_balancers,
                                                bool reload_ip_auth) noexcept
{
    //TODO: async DB request
    LoadBalancersContainer tmp_load_balancers;
    IPAuthDataContainer tmp_ip_auths;
    try {
        pqxx::nontransaction t(c);

        if(reload_load_balancers) {
            auto r = t.exec("SELECT * FROM load_trusted_lb()");
            for(const auto &row: r)
                tmp_load_balancers.emplace_back(row);
        }

        if(reload_ip_auth) {
            auto r =  t.exec_params("SELECT * FROM load_ip_auth($1,$2)",
                           AmConfig.node_id, ycfg.pop_id);
            for(const auto &row: r)
                tmp_ip_auths.emplace_back(row);
        }

        {
            AmLock l(mutex);

            if(reload_load_balancers)
                load_balancers.swap(tmp_load_balancers);

            if(reload_ip_auth) {
                ip_auths.swap(tmp_ip_auths);

                subnets_tree.clear();
                int idx = 0;
                for(const auto &auth: ip_auths)
                    subnets_tree.addSubnet(auth.subnet, idx++);
            }
        }
    } catch(const pqxx::pqxx_exception &e) {
        ERROR("OriginationPreAuth pqxx_exception: %s ",e.base().what());
    } catch(...) {
        ERROR("OriginationPreAuth unexpected exception");
    }
}

void OriginationPreAuth::ShowTrustedBalancers(AmArg& ret)
{
    ret.assertArray();
    AmLock lock(mutex);
    for(const auto &lb : load_balancers)
        ret.push(lb);
}

void OriginationPreAuth::ShowIPAuth(AmArg& ret)
{
    auto &entries = ret["entries"];
    AmLock lock(mutex);
    for(const auto &ip_auth : ip_auths)
        entries.push(ip_auth);
    //ret["tree"] = subnets_tree;
}

bool OriginationPreAuth::onInvite(const AmSipRequest &req, Reply &reply)
{
    /* determine src IP to match:
     * use X-AUTH-IP header value if exists
     * and req.remote_ip within trusted load balancers list.
     * use req.remote_ip otherwise */

    static string x_yeti_auth_hdr("X-YETI-AUTH");

    size_t start_pos = 0;
    while (start_pos<req.hdrs.length()) {
        size_t name_end, val_begin, val_end, hdr_end;
        int res;
        if ((res = skip_header(req.hdrs, start_pos, name_end, val_begin,
            val_end, hdr_end)) != 0)
        {
            break;
        }
        if(0==strncasecmp(req.hdrs.c_str() + start_pos,
                          ycfg.ip_auth_hdr.c_str(), name_end-start_pos))
        {
            //req.hdrs.substr(val_begin, val_end-val_begin);
            if(reply.orig_ip.empty()) {
                DBG("found first %s hdr. checking for trusted balancer",
                    ycfg.ip_auth_hdr.data());
                AmLock l(mutex);
                for(const auto &lb : load_balancers) {
                    if(lb.signalling_ip==req.remote_ip) {
                        reply.orig_ip = req.hdrs.substr(val_begin, val_end-val_begin);
                        DBG("remote IP %s matched with load balancer %lu/%s. "
                            "use %s value %s as source IP",
                            req.remote_ip.data(), lb.id, lb.name.data(),
                            ycfg.ip_auth_hdr.data(),
                            reply.orig_ip.data());
                        break;
                    }
                }
            }
        /*} else if(0==strncasecmp(req.hdrs.c_str() + start_pos,
                                 x_orig_port_hdr.c_str(), name_end-start_pos))
        {
            str2int(req.hdrs.substr(val_begin, val_end-val_begin), reply.orig_port);
        } else if(0==strncasecmp(req.hdrs.c_str() + start_pos,
                                 x_orig_proto_hdr.c_str(), name_end-start_pos))
        {
            str2int(req.hdrs.substr(val_begin, val_end-val_begin), reply.orig_proto);*/
        } else if(0==strncasecmp(req.hdrs.c_str() + start_pos,
                                 x_yeti_auth_hdr.c_str(), name_end-start_pos))
        {
            if(reply.x_yeti_auth.empty()) {
                reply.x_yeti_auth = req.hdrs.substr(val_begin, val_end-val_begin);
                DBG("found first X-YETI-AUTH hdr with value: %s", reply.x_yeti_auth.data());
            }
        }
        start_pos = hdr_end;
    }

    if(reply.orig_ip.empty()) {
        DBG("no %s hdr or request was from not trusted balancer",
            ycfg.ip_auth_hdr.data());
        reply.orig_ip = req.remote_ip;
    }

    DBG("use address %s for matching", reply.orig_ip.data());

    sockaddr_storage addr;
    memset(&addr,0,sizeof(sockaddr_storage));
    if(!am_inet_pton(reply.orig_ip.c_str(), &addr)) {
        ERROR("failed to parse IP address: %s", reply.orig_ip.data());
        return false;
    }

    IPTree::MatchResult match_result;
    AmLock l(mutex);
    subnets_tree.match(addr, match_result);
    if(match_result.empty()) {
        DBG("no matching IP Auth entry for src ip: %s", reply.orig_ip.data());
        return false;
    }

    DBG("IP matched with %ld auth entries", match_result.size());

    /* iterate over all matched subnets
     * from the one with the longest mask to the shortest */
    for(auto it = match_result.rbegin();
        it != match_result.rend(); ++it)
    {
        const auto &auth = ip_auths[*it];

        //check for x-yeti-auth
        DBG("check against matched auth: %s(%s)",
            auth.ip.data(), auth.x_yeti_auth.data());
        if(auth.x_yeti_auth != reply.x_yeti_auth) {
            continue;
        }

        DBG("fully matched with auth: %s(%s) sip_auth:%d, identity:%d",
            auth.ip.data(), auth.x_yeti_auth.data(),
            auth.require_incoming_auth, auth.require_identity_parsing);

        reply.require_incoming_auth = auth.require_incoming_auth;
        reply.require_identity_parsing = auth.require_identity_parsing;

        return true;
    }

    /* keep old behavior for no matched failover */
    reply.require_incoming_auth = false;
    reply.require_identity_parsing = true;

    return false;
}
