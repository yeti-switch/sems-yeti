#pragma once

#include <ampi/HttpClientAPI.h>
#include <AmSipMsg.h>
#include <AmConfigReader.h>

#include "db/DbConfig.h"
#include "cfg/YetiCfg.h"

#include "confuse.h"

#include <botan/x509_ca.h>
#include <botan/certstor.h>

#include <unordered_map>
#include <regex>

using namespace std;

struct CertCacheEntry {
    enum cert_state {
        LOADING,
        LOADED,
        UNAVAILABLE
    };

    std::chrono::system_clock::time_point expire_time;
    string response_data;
    vector<Botan::X509_Certificate> cert_chain;
    string error_str;
    int error_code;
    int error_type;
    cert_state state;

    bool validation_sucessfull;
    string validation_result;
    string trust_root_cert;

    set<string> defer_sessions;

    CertCacheEntry()
      : error_code(0),
        error_type(0),
        state(LOADING){}

    ~CertCacheEntry() {}

    void reset() {
        error_type = 0;
        error_code = 0;
        error_str.clear();
        response_data.clear();
        cert_chain.clear();
        state = LOADING;
    }

    static string to_string(cert_state state) {
        switch(state){
        case LOADING: return "loading";
        case LOADED: return "loaded";
        case UNAVAILABLE: return "unavailable";
        }
        return "";
    }

    void getInfo(AmArg &a, const std::chrono::system_clock::time_point &now);
};

class CertCache
{
    int expires;
    string http_destination;
    std::chrono::seconds cert_cache_ttl;
    std::chrono::seconds db_refresh_interval;
    YetiCfg &ycfg;

    AmMutex mutex;

    using HashType = unordered_map<string, CertCacheEntry>;
    HashType entries;

    struct TrustedCertEntry {
        unsigned long id;
        string name;
        vector<shared_ptr<Botan::X509_Certificate>> certs;
        TrustedCertEntry(unsigned long id, string name)
          : id(id), name(name)
        {}
    };
    vector<TrustedCertEntry> trusted_certs;
    Botan::Certificate_Store_In_Memory trusted_certs_store;
    std::chrono::system_clock::time_point db_refresh_expire;

    struct TrustedRepositoryEntry {
        unsigned long id;
        string url_pattern;
        bool validate_https_certificate;
        std::regex regex;
        TrustedRepositoryEntry(
            unsigned long id,
            string url_pattern,
            bool validate_https_certificate)
          : id(id),
            url_pattern(url_pattern),
            validate_https_certificate(validate_https_certificate),
            regex(url_pattern)
        {}
    };
    vector<TrustedRepositoryEntry> trusted_repositories;

    bool isTrustedRepositoryUnsafe(const string &url);
    void renewCertEntry(HashType::value_type &entry);
    void reloadDatabaseSettings() noexcept;

  public:
    CertCache(YetiCfg & ycfg);
    ~CertCache();

    int configure(cfg_t *cfg);

    enum get_key_result {
        KEY_RESULT_READY,
        KEY_RESULT_DEFFERED,
        KEY_RESULT_UNAVAILABLE
    };

    int getExpires() { return expires; }

    //returns if cert is presented in cache and ready to be used
    bool checkAndFetch(const string& cert_url,
                       const string& session_id);
    Botan::Public_Key *getPubKey(const string& cert_url, bool &cert_is_valid);

    void processHttpReply(const HttpGetResponseEvent& resp);
    void onTimer();

    //rpc methods
    void ShowCerts(AmArg& ret, const std::chrono::system_clock::time_point &now);
    int ClearCerts(const AmArg& args);
    int RenewCerts(const AmArg& args);

    void ShowTrustedCerts(AmArg& ret);
    void ShowTrustedRepositories(AmArg& ret);

    static void serialize_cert_to_amarg(const Botan::X509_Certificate &cert, AmArg &a);
};

struct CertCacheResponseEvent
  : public AmEvent
{
  CertCache::get_key_result result;
  string cert_url;

  CertCacheResponseEvent(CertCache::get_key_result result, const string &cert_url)
    : AmEvent(E_PLUGIN),
      result(result),
      cert_url(cert_url)
    {}
  CertCacheResponseEvent(CertCacheResponseEvent &) = delete;

  virtual ~CertCacheResponseEvent() = default;
};
