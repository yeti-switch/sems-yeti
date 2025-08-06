#pragma once

#include <ampi/HttpClientAPI.h>
#include <AmSipMsg.h>
#include <AmConfigReader.h>
#include <AmIdentity.h>

#include "db/DbConfig.h"
#include "cfg/YetiCfg.h"
#include "DbConfigStates.h"

#include "confuse.h"

#include <botan/x509_ca.h>
#include <botan/certstor.h>
#include <botan/pkcs8.h>

#include <unordered_map>
#include <regex>
#include <shared_mutex>

using namespace std;

struct CertCacheEntry {
    enum cert_state { LOADING, LOADED, UNAVAILABLE };

    std::chrono::system_clock::time_point expire_time;
    string                                response_data;
    vector<Botan::X509_Certificate>       cert_chain;
    string                                error_str;
    int                                   error_code;
    int                                   error_type;
    cert_state                            state;

    bool   validation_sucessfull;
    string validation_result;
    string trust_root_cert;

    set<string> defer_sessions;

    CertCacheEntry()
        : error_code(0)
        , error_type(0)
        , state(LOADING)
    {
    }

    ~CertCacheEntry() {}

    void reset()
    {
        error_type = 0;
        error_code = 0;
        error_str.clear();
        response_data.clear();
        cert_chain.clear();
        state = LOADING;
    }

    static string to_string(cert_state state)
    {
        switch (state) {
        case LOADING:     return "loading";
        case LOADED:      return "loaded";
        case UNAVAILABLE: return "unavailable";
        }
        return "";
    }

    void getInfo(AmArg &a, const std::chrono::system_clock::time_point &now) const;
};

class CertCache {
    int                  expires;
    string               http_destination;
    std::chrono::seconds cert_cache_ttl;
    std::chrono::seconds cert_cache_failed_ttl;
    std::chrono::seconds cert_cache_failed_verify_ttl;

    mutable std::shared_mutex mutex; // tmp to generate errors

    using HashType = unordered_map<string, CertCacheEntry>;
    HashType certificates;

    struct TrustedCertEntry {
        unsigned long                               id;
        string                                      name;
        vector<shared_ptr<Botan::X509_Certificate>> certs;
        TrustedCertEntry(unsigned long id, string name)
            : id(id)
            , name(name)
        {
        }
    };
    vector<TrustedCertEntry>           trusted_certs;
    Botan::Certificate_Store_In_Memory trusted_certs_store;

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

    std::chrono::system_clock::time_point db_refresh_expire;

    struct TrustedRepositoryEntry {
        unsigned long id;
        string        url_pattern;
        bool          validate_https_certificate;
        std::regex    regex;
        TrustedRepositoryEntry(unsigned long id, string url_pattern, bool validate_https_certificate)
            : id(id)
            , url_pattern(url_pattern)
            , validate_https_certificate(validate_https_certificate)
            , regex(url_pattern)
        {
        }
    };
    vector<TrustedRepositoryEntry> trusted_repositories;

    bool isTrustedRepositoryUnsafe(const string &url) const;
    void renewCertEntry(HashType::value_type &entry);

    /* guards:
     *   certificates,
     *   trusted_certs,
     *   trusted_certs_store,
     *   trusted_repositories
     */
    mutable std::shared_mutex certificates_mutex;

  public:
    CertCache();
    ~CertCache();

    int configure(cfg_t *cfg);

    enum get_key_result { KEY_RESULT_READY, KEY_RESULT_DEFFERED, KEY_RESULT_UNAVAILABLE };

    int           getExpires() const { return expires; }
    const string &getHttpDestination() { return http_destination; }

    // returns if cert is presented in cache and ready to be used
    bool                               checkAndFetch(const string &cert_url, const string &session_id);
    std::unique_ptr<Botan::Public_Key> getPubKey(const string &cert_url, AmArg &info, bool &cert_is_valid) const;
    bool                               isTrustedRepository(const string &cert_url) const;

    std::optional<std::string> getIdentityHeader(AmIdentity &identity, unsigned long signing_key_id) const;

    void processHttpReply(const HttpGetResponseEvent &resp);
    void onTimer(const std::chrono::system_clock::time_point &now);
    void reloadTrustedCertificates(const AmArg &data);
    void reloadTrustedRepositories(const AmArg &data);
    void reloadSigningKeys(const AmArg &data);

    // rpc methods
    void ShowCerts(AmArg &ret, const std::chrono::system_clock::time_point &now) const;
    int  ClearCerts(const AmArg &args);
    int  RenewCerts(const AmArg &args);

    void ShowTrustedCerts(AmArg &ret) const;
    void ShowTrustedRepositories(AmArg &ret) const;
    void ShowSigningKeys(AmArg &ret) const;

    static void serialize_cert_tn_auth_list_to_amarg(const Botan::X509_Certificate &cert, AmArg &a);
    static void serialize_cert_to_amarg(const Botan::X509_Certificate &cert, AmArg &a);
};

struct CertCacheResponseEvent : public AmEvent {
    CertCache::get_key_result result;
    string                    cert_url;

    CertCacheResponseEvent(CertCache::get_key_result result, const string &cert_url)
        : AmEvent(E_PLUGIN)
        , result(result)
        , cert_url(cert_url)
    {
    }
    CertCacheResponseEvent(CertCacheResponseEvent &) = delete;

    virtual ~CertCacheResponseEvent() = default;
};
