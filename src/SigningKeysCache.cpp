#include "SigningKeysCache.h"
#include <AmSession.h>
#include <log.h>
#include <format_helper.h>

/* SigningKeysCacheMetricGroup */

struct SigningKeysCacheMetricGroup : public StatCountersGroupsInterface {
    static vector<string> metrics_keys_names;
    static vector<string> metrics_help_strings;
    enum metric_keys_idx { SIGNING_KEY_NOT_AFTER_TIMESTAMP = 0, MAX_KEY_IDX };
    struct signing_key_info {
        map<string, string> labels;
        unsigned long long  value;
    };
    vector<signing_key_info> signing_keys;
    int                      idx;

    SigningKeysCacheMetricGroup()
        : StatCountersGroupsInterface(Gauge)
    {
    }

    void add_signing_key(const string &id, const string &name, const string &cn, unsigned long long value)
    {
        signing_keys.emplace_back();

        auto &labels   = signing_keys.back().labels;
        labels["id"]   = id;
        labels["name"] = name;
        labels["cn"]   = cn;

        signing_keys.back().value = value;
    }

    void serialize(StatsCountersGroupsContainerInterface::iterate_groups_callback_type callback)
    {
        for (int i = 0; i < MAX_KEY_IDX; i++) {
            idx = i;
            setHelp(metrics_help_strings[idx]);
            callback(metrics_keys_names[idx], *this);
        }
    }

    void iterate_counters(iterate_counters_callback_type callback) override
    {
        for (const auto &cert : signing_keys)
            callback(cert.value, cert.labels);
    }
};

vector<string> SigningKeysCacheMetricGroup::metrics_keys_names   = { MOD_NAME "_signing_key_cert_not_after_timestamp" };
vector<string> SigningKeysCacheMetricGroup::metrics_help_strings = { "" };

/* SigningKeysCache */

SigningKeysCache::SigningKeysCache()
{
    statistics::instance()->add_groups_container(MOD_NAME, this, false);
}

SigningKeysCache::~SigningKeysCache() {}

std::optional<std::string> SigningKeysCache::getIdentityHeader(AmIdentity &identity, unsigned long signing_key_id) const
{
    std::shared_lock lock(signing_keys_mutex);

    auto it = signing_keys.find(signing_key_id);
    if (it == signing_keys.end()) {
        AmArg orig, dest;
        identity.get_orig().serialize(orig, false);
        identity.get_dest().serialize(dest, true);
        ERROR("no signing key %lu on signing identity: %s -> %s", signing_key_id, orig.print().data(),
              dest.print().data());

        return std::nullopt;
    }

    const auto &key_data = it->second;
    identity.set_x5u_url(key_data.x5u);
    try {
        return identity.generate(key_data.key.get());
    } catch (Botan::Exception &e) {
        throw AmSession::Exception(500, format("failed to generate Identity header: {}", e.what()));
    }
}

void SigningKeysCache::reloadSigningKeys(const AmArg &data)
{
    std::unique_lock lock(signing_keys_mutex);

    signing_keys.clear();
    if (!isArgArray(data))
        return;
    for (size_t i = 0; i < data.size(); i++) {
        AmArg &a = data[i];

        auto   id   = a["id"].asNumber<unsigned long>();
        string name = a["name"].asCStr();
        try {
            Botan::DataSource_Memory key_data(a["key"].asCStr());
            auto                     key = Botan::PKCS8::load_key(key_data, std::string_view());
            auto                     ret = signing_keys.try_emplace(id, name, a["x5u"].asCStr(), key);
            Botan::DataSource_Memory in(a["certificate"].asCStr());
            while (!in.end_of_data())
                ret.first->second.cert_chain.emplace_back(in);
        } catch (Botan::Exception &e) {
            ERROR("SigningKeysCache signing entry %lu '%s' Botan::exception: %s", id, name.data(), e.what());
        }
    }
}

/* StatsCountersGroupsContainerInterface */

void SigningKeysCache::operator()(const string &, iterate_groups_callback_type callback)
{
    AmArg ret;
    ret.assertArray();

    SigningKeysCacheMetricGroup g;
    {
        std::shared_lock lock(signing_keys_mutex);
        g.signing_keys.reserve(signing_keys.size());
        for (const auto &[id, entry] : signing_keys)
            for (const auto &cert : entry.cert_chain)
                g.add_signing_key(std::to_string(id), entry.name, cert.subject_dn().to_string(),
                                  cert.not_after().time_since_epoch());
    }

    g.serialize(callback);
}

/* rpc methods */

void SigningKeysCache::ShowSigningKeys(AmArg &ret) const
{
    ret.assertArray();

    std::shared_lock lock(signing_keys_mutex);

    for (const auto &it : signing_keys) {
        const auto &key_entry = it.second;

        ret.push(AmArg());
        auto &a = ret.back();

        a["id"]                 = it.first;
        a["name"]               = key_entry.name;
        a["x5u"]                = key_entry.x5u;
        a["fingerprint_sha256"] = key_entry.key->fingerprint_public();
        a["fingerprint_sha1"]   = key_entry.key->fingerprint_public("SHA-1");
        a["algorithm_name"]     = key_entry.key->algo_name();
    }
}
