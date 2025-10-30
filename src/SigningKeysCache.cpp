#include "SigningKeysCache.h"
#include <AmSession.h>
#include <log.h>
#include <format_helper.h>

SigningKeysCache::SigningKeysCache() {}

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
            signing_keys.try_emplace(id, name, a["x5u"].asCStr(), key);
        } catch (Botan::Exception &e) {
            ERROR("SigningKeysCache signing entry %lu '%s' Botan::exception: %s", id, name.data(), e.what());
        }
    }
}

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
