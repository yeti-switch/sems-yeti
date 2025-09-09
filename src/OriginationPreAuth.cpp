#include "OriginationPreAuth.h"
#include "HeaderFilter.h"
#include "db/DbHelpers.h"

OriginationPreAuth::OriginationPreAuth(YetiCfg &ycfg)
    : ycfg(ycfg)
{
}

OriginationPreAuth::LoadBalancerData::LoadBalancerData(const AmArg &r)
{
    id            = r["id"].asInt();
    name          = r["name"].asCStr();
    signalling_ip = r["signalling_ip"].asCStr();
}

OriginationPreAuth::LoadBalancerData::operator AmArg() const
{
    AmArg a;
    a["id"]            = id;
    a["name"]          = name;
    a["signalling_ip"] = signalling_ip;
    return a;
}

OriginationPreAuth::IPAuthData::IPAuthData(const AmArg &r)
    : ip(DbAmArg_hash_get_str(r, "ip"))
    , x_yeti_auth(DbAmArg_hash_get_str(r, "x_yeti_auth"))
    , require_incoming_auth(DbAmArg_hash_get_bool(r, "require_incoming_auth"))
    , require_identity_parsing(DbAmArg_hash_get_bool(r, "require_identity_parsing"))
{
    if (!subnet.parse(ip))
        throw string("failed to parse IP");
}

OriginationPreAuth::IPAuthData::operator AmArg() const
{
    AmArg a;
    a["ip"]                       = ip;
    a["subnet"]                   = subnet;
    a["x_yeti_auth"]              = x_yeti_auth;
    a["require_incoming_auth"]    = require_incoming_auth;
    a["require_identity_parsing"] = require_identity_parsing;
    return a;
}

void OriginationPreAuth::reloadLoadBalancers(const AmArg &data)
{
    LoadBalancersContainer tmp_load_balancers;
    if (isArgArray(data)) {
        for (size_t i = 0; i < data.size(); i++) {
            tmp_load_balancers.emplace_back(data[i]);
        }
    }

    AmLock l(mutex);

    load_balancers.swap(tmp_load_balancers);
}

void OriginationPreAuth::reloadLoadIPAuth(const AmArg &data)
{
    IPAuthDataContainer tmp_ip_auths;
    if (isArgArray(data)) {
        for (size_t i = 0; i < data.size(); i++) {
            tmp_ip_auths.emplace_back(data[i]);
        }
    }

    DBG("loaded %zd IP auth data entries", tmp_ip_auths.size());

    AmLock l(mutex);

    ip_auths.swap(tmp_ip_auths);

    subnets_tree.clear();
    int idx = 0;
    for (const auto &auth : ip_auths)
        subnets_tree.addSubnet(auth.subnet, idx++);
}

void OriginationPreAuth::ShowTrustedBalancers(AmArg &ret)
{
    ret.assertArray();
    AmLock lock(mutex);
    for (const auto &lb : load_balancers)
        ret.push(lb);
}

void OriginationPreAuth::ShowIPAuth(const AmArg &arg, AmArg &ret)
{
    auto &entries = ret["entries"];
    entries.assertArray();

    AmLock lock(mutex);

    if (0 == arg.size()) {
        for (const auto &ip_auth : ip_auths)
            entries.push(ip_auth);
    } else {
        arg.assertArrayFmt("s");
        sockaddr_storage addr;
        memset(&addr, 0, sizeof(sockaddr_storage));
        if (!am_inet_pton(arg[0].asCStr(), &addr))
            return;
        IPTree::MatchResult match_result;
        subnets_tree.match(addr, match_result);
        for (const auto &m : match_result) {
            entries.push(ip_auths[m]);
        }
    }
    // ret["tree"] = subnets_tree;
}

bool OriginationPreAuth::onRequest(const AmSipRequest &req, bool match_subnet, Reply &reply)
{
    /* determine src IP to match:
     * use X-AUTH-IP header value if exists
     * and req.remote_ip within trusted load balancers list.
     * use req.remote_ip otherwise */

    reply.request_is_from_trusted_lb = false;

    /* keep old behavior for no matched failover */
    reply.require_incoming_auth    = false;
    reply.require_identity_parsing = true;

    {
        AmLock l(mutex);
        auto   lb_it = std::find_if(load_balancers.begin(), load_balancers.end(),
                                    [&req](const auto &e) { return e.signalling_ip == req.remote_ip; });
        if (lb_it != load_balancers.end()) {
            DBG("remote IP %s matched with load balancer %lu/%s. ", req.remote_ip.data(), lb_it->id,
                lb_it->name.data());
            reply.request_is_from_trusted_lb = true;
        }
    }

    static string x_yeti_auth_hdr("X-YETI-AUTH");

    size_t start_pos = 0;
    while (start_pos < req.hdrs.length()) {
        size_t name_end, val_begin, val_end, hdr_end, hdr_length;
        int    res;
        if ((res = skip_header(req.hdrs, start_pos, name_end, val_begin, val_end, hdr_end)) != 0) {
            break;
        }
        const char *hdr = req.hdrs.c_str() + start_pos;
        hdr_length      = name_end - start_pos;
        if (hdr_length == ycfg.ip_auth_hdr.size() && 0 == strncasecmp(hdr, ycfg.ip_auth_hdr.c_str(), hdr_length)) {
            // req.hdrs.substr(val_begin, val_end-val_begin);
            if (reply.orig_ip.empty()) {
                DBG3("found first %s hdr", ycfg.ip_auth_hdr.data());
                if (reply.request_is_from_trusted_lb) {
                    reply.orig_ip = req.hdrs.substr(val_begin, val_end - val_begin);
                    DBG("use %s value %s as source IP", ycfg.ip_auth_hdr.data(), reply.orig_ip.data());
                }
            }
        } else if (hdr_length == x_yeti_auth_hdr.size() && 0 == strncasecmp(hdr, x_yeti_auth_hdr.c_str(), hdr_length)) {
            if (reply.x_yeti_auth.empty()) {
                reply.x_yeti_auth = req.hdrs.substr(val_begin, val_end - val_begin);
                DBG("found first X-YETI-AUTH hdr with value: %s", reply.x_yeti_auth.data());
            }
        } else if (!ycfg.auth_default_realm_header.empty() && hdr_length == ycfg.auth_default_realm_header.size() &&
                   0 == strncasecmp(hdr, ycfg.auth_default_realm_header.c_str(), hdr_length))
        {
            if (reply.x_default_realm.empty()) {
                DBG3("found first %s hdr", ycfg.auth_default_realm_header.c_str());
                if (reply.request_is_from_trusted_lb) {
                    reply.x_default_realm = req.hdrs.substr(val_begin, val_end - val_begin);
                    DBG("use %s value %s as default realm", ycfg.auth_default_realm_header.c_str(),
                        reply.x_default_realm.data());
                }
            }
        }
        start_pos = hdr_end;
    }

    if (reply.orig_ip.empty()) {
        DBG("no %s hdr or request was from not trusted balancer", ycfg.ip_auth_hdr.data());
        reply.orig_ip = req.remote_ip;
    }

    if (!match_subnet)
        return false;

    DBG("use address %s for matching", reply.orig_ip.data());

    sockaddr_storage addr;
    memset(&addr, 0, sizeof(sockaddr_storage));
    if (!am_inet_pton(reply.orig_ip.c_str(), &addr)) {
        ERROR("failed to parse IP address: %s", reply.orig_ip.data());
        return false;
    }

    IPTree::MatchResult match_result;
    AmLock              l(mutex);
    subnets_tree.match(addr, match_result);
    if (match_result.empty()) {
        DBG("no matching IP Auth entry for src ip: %s", reply.orig_ip.data());
        return false;
    }

    DBG("IP matched with %ld auth entries", match_result.size());

    /* iterate over all matched subnets
     * from the one with the longest mask to the shortest */
    for (auto it = match_result.rbegin(); it != match_result.rend(); ++it) {
        const auto &auth = ip_auths[*it];

        // check for x-yeti-auth
        DBG("check against matched auth: %s(%s)", auth.ip.data(), auth.x_yeti_auth.data());
        if (auth.x_yeti_auth != reply.x_yeti_auth) {
            continue;
        }

        DBG("fully matched with auth: %s(%s) sip_auth:%d, identity:%d", auth.ip.data(), auth.x_yeti_auth.data(),
            auth.require_incoming_auth, auth.require_identity_parsing);

        reply.require_incoming_auth    = auth.require_incoming_auth;
        reply.require_identity_parsing = auth.require_identity_parsing;

        return true;
    }

    return false;
}
