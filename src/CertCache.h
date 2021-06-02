#pragma once

#include <unordered_map>
#include <botan/x509_ca.h>
#include <ampi/HttpClientAPI.h>
#include <AmSipMsg.h>
#include "confuse.h"

using namespace std;

struct CertCacheEntry {
    enum cert_state {
        LOADING,
        LOADED,
        EXPIRED,
        UNAVAILABLE
    };

    time_t expire_time;
    vector<uint8_t> cert_binary;
    Botan::X509_Certificate cert;
    string error_str;
    int error_code;
    int error_type;
    cert_state state;

    vector<string> defer_sessions;

    CertCacheEntry()
      : expire_time(0),
        error_code(0),
        error_type(0),
        state(LOADING){}

    ~CertCacheEntry() {}

	void reset() {
        expire_time = 0;
        error_type = 0;
        error_code = 0;
        error_str.clear();
        cert_binary.clear();
        cert = Botan::X509_Certificate();
        state = LOADING;
    }

	static string to_string(cert_state state) {
        switch(state){
        case LOADING: return "loading";
        case LOADED: return "loaded";
        case EXPIRED: return "expired";
        case UNAVAILABLE: return "unavailable";
        }
        return "";
    }
};

class CertCache
{
    int expires;
    string http_destination;
    int cert_cache_ttl;

    AmMutex mutex;
    unordered_map<string, CertCacheEntry*> entries;
  public:
    CertCache();
    ~CertCache();

    int configure(cfg_t *cfg);

    enum get_key_result {
        KEY_RESULT_READY,
        KEY_RESULT_DEFFERED,
        KEY_RESULT_UNAVAILABLE
    };
    get_key_result getCertPubKeyByUrl(const string& x5url, const string& session_id, Botan::Public_Key *key);

    void processHttpReply(const HttpGetResponseEvent& resp);

    //rpc methods
    void ShowCerts(AmArg& ret, time_t now);
    int ClearCerts(const AmArg& args);
    int RenewCerts(const AmArg& args);
};

struct CertCacheResponseEvent
  : public AmEvent
{
  CertCache::get_key_result result;
  std::unique_ptr<Botan::Public_Key> key;

  CertCacheResponseEvent(CertCache::get_key_result result, Botan::Public_Key *key)
    : AmEvent(E_PLUGIN),
      result(result),
      key(key)
    {}
  CertCacheResponseEvent(CertCacheResponseEvent &) = delete;

  ~CertCacheResponseEvent()
  { }
};
