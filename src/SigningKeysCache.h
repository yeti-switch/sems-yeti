#pragma once

#include <AmIdentity.h>

#include <shared_mutex>

using namespace std;

class SigningKeysCache {

    struct SigningKeyEntry {
        string                              name;
        string                              x5u;
        std::unique_ptr<Botan::Private_Key> key;

        SigningKeyEntry(const string &name, const string &x5u, std::unique_ptr<Botan::Private_Key> &key)
            : name(name)
            , x5u(x5u)
            , key(std::move(key))
        {
        }
    };
    std::map<unsigned long, SigningKeyEntry> signing_keys;
    mutable std::shared_mutex                signing_keys_mutex;


  public:
    SigningKeysCache();
    ~SigningKeysCache();

    std::optional<std::string> getIdentityHeader(AmIdentity &identity, unsigned long signing_key_id) const;
    void                       reloadSigningKeys(const AmArg &data);

    // rpc methods
    void ShowSigningKeys(AmArg &ret) const;
};
