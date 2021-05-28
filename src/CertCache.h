#ifndef CERT_CACHE_H
#define CERT_CACHE_H

#include <unordered_map>
#include <botan/x509_ca.h>
#include <ampi/HttpClientAPI.h>
#include <AmSipMsg.h>

using namespace std;

class Yeti;

struct CertCacheEntry {
    enum cert_state {
        LOADING,
        LOADED,
        EXPIRED,
        UNAVAILABLE
    };

	uint64_t expire_time;
    vector<uint8_t> cert_binary;
    Botan::X509_Certificate cert;
    string error_str;
    int error_code;
    int error_type;
    cert_state state;

    vector<string> defer_sessions;

	CertCacheEntry() : expire_time(0), error_code(0), error_type(0), state(LOADING){}
	~CertCacheEntry(){}

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
    auto_ptr<Yeti> yeti;
    AmMutex mutex;
    unordered_map<string, CertCacheEntry*> entries;
public:
    CertCache(Yeti* yeti);
    ~CertCache();

    CertCacheEntry* getCertEntry(const string& x5url, const string& session_id);
    void processHttpReply(const HttpGetResponseEvent& resp);

    //rpc methods
    void ShowCerts(AmArg& ret);
    int ClearCerts(const AmArg& args);
    int RenewCerts(const AmArg& args);
};

#endif/*CERT_CACHE_H*/
