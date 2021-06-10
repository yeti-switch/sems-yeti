#include "CertCache.h"
#include "yeti.h"
#include <AmSessionContainer.h>
#include "cfg/yeti_opts.h"
#include <botan/pk_keys.h>
#include <chrono>

void CertCacheEntry::getInfo(AmArg &a, const std::
                             chrono::system_clock::time_point &now)
{
    a["state"] = CertCacheEntry::to_string(state);

    if(state == LOADING)
        return;

    a["ttl"] = std::chrono::duration_cast<std::chrono::seconds>(expire_time - now).count();
    a["error_str"] = error_str;
    a["error_code"] = error_code;
    a["error_type"] = error_type ? Botan::to_string((Botan::ErrorType)error_type) : "";
    a["state"] = CertCacheEntry::to_string(state);
    try {
        a["cert_end_time"] = cert.not_after().readable_string();
    } catch(Botan::Exception&) {
        a["cert_end_time"] = "";
    }
    try {
        a["cert_start_time"] = cert.not_before().readable_string();
    } catch(Botan::Exception&) {
        a["cert_start_time"] = "";
    }
    /*try {
        a["cert_serial"] = cert.subject_info("X509.Certificate.serial")[0];
    } catch(Botan::Exception&) {
        a["cert_serial"] = "";
    }*/
    try {
        a["cert_subject_dn"] = cert.subject_dn().to_string();
    } catch(Botan::Exception&) {
        a["cert_subject_dn"] = "";
    }
    try {
        a["cert_issuer_dn"] = cert.issuer_dn().to_string();
    } catch(Botan::Exception&) {
        a["cert_issuer_dn"] = "";
    }
}

CertCache::CertCache()
{}

CertCache::~CertCache()
{}

int CertCache::configure(cfg_t *cfg)
{
    expires = cfg_getint(cfg, opt_identity_expires);
    cert_cache_ttl = std::chrono::seconds(cfg_getint(cfg, opt_identity_certs_cache_ttl));

    if(cfg_size(cfg, opt_identity_http_destination)) {
        http_destination = cfg_getstr(cfg, opt_identity_http_destination);
    } else {
        ERROR("missed mandatory param 'http_destination' for identity section");
        return -1;
    }

    return 0;
}

bool CertCache::checkAndFetch(const string& cert_url,
                                 const string& session_id)
{
    AmLock lock(mutex);
    auto it = entries.find(cert_url);
    if(it == entries.end()) {
        auto ret = entries.emplace(cert_url, CertCacheEntry{});
        auto &entry = ret.first;

        entry->second.defer_sessions.emplace(session_id);
        renewCertEntry(*entry);

        return false;
    }

    if(it->second.state == CertCacheEntry::LOADING) {
        return false;
    }

    return true;
}

Botan::Public_Key *CertCache::getPubKey(const string& cert_url)
{
    AmLock lock(mutex);
    auto it = entries.find(cert_url);
    if(it == entries.end()) {
        return nullptr;
    }

    if(it->second.state != CertCacheEntry::LOADED) {
        return nullptr;
    }

    return it->second.cert.subject_public_key();
}

void CertCache::processHttpReply(const HttpGetResponseEvent& resp)
{
    AmLock lock(mutex);

    auto it = entries.find(resp.token);
    if(it == entries.end()) {
        ERROR("processHttpReply: absent cache entry %s", resp.token.c_str());
        return;
    }

    it->second.expire_time = std::chrono::system_clock::now() + cert_cache_ttl;

    if(resp.mime_type.empty()) {
        it->second.state = CertCacheEntry::UNAVAILABLE;
        it->second.error_code = resp.code;
        it->second.error_type = (int)Botan::ErrorType::HttpError;
    } else {
        it->second.cert_binary.resize(resp.data.size());
        memcpy(it->second.cert_binary.data(), resp.data.c_str(), resp.data.size());
        try {
            Botan::X509_Certificate cert(it->second.cert_binary);
            const Botan::X509_Time& t = cert.not_after();
            if(t.cmp(Botan::X509_Time(std::chrono::_V2::system_clock::now())) < 0)
                throw Botan::Exception("certificate expired");
            it->second.cert = cert;
            it->second.state = CertCacheEntry::LOADED;
        } catch(const Botan::Exception& e) {
            it->second.state = CertCacheEntry::UNAVAILABLE;
            it->second.error_str = e.what();
            it->second.error_code = e.error_code();
            it->second.error_type = (int)e.error_type();
        }
    }

    auto result = it->second.state==CertCacheEntry::LOADED ?
        KEY_RESULT_READY : KEY_RESULT_UNAVAILABLE;

    for(auto& session_id : it->second.defer_sessions) {
        if(!AmSessionContainer::instance()->postEvent(
            session_id,
            new CertCacheResponseEvent(result, it->first)))
        {
            ERROR("failed to post CertCacheResponseEvent for session %s",
                session_id.c_str());
        }
    }

    it->second.defer_sessions.clear();
}

void CertCache::renewCertEntry(HashType::value_type &entry)
{
    entry.second.reset();
    AmSessionContainer::instance()->postEvent(
        HTTP_EVENT_QUEUE,
        new HttpGetEvent(http_destination, //destination
                        entry.first,       //url
                        entry.first,       //token
                        YETI_QUEUE_NAME)); //session_id
}

void CertCache::onTimer()
{
    const auto now(std::chrono::system_clock::now());
    AmLock lock(mutex);
    for(auto& entry : entries) {
        if(entry.second.state==CertCacheEntry::LOADING)
            continue;
        if(now > entry.second.expire_time) {
            renewCertEntry(entry);
        }
    }
}

void CertCache::ShowCerts(AmArg& ret, const std::chrono::system_clock::time_point &now)
{
    ret.assertArray();
    AmLock lock(mutex);

    for(auto& pair : entries) {
        ret.push(AmArg());
        auto &entry = ret.back();
        entry["url"] = pair.first;
        pair.second.getInfo(entry, now);
    }
}

int CertCache::ClearCerts(const AmArg& args)
{
    int ret = 0;
    args.assertArray();
    if(args.size() == 0) {
        ret = entries.size();
        entries.clear();
        return ret;
    }
    for(int i = 0; i < args.size(); i++) {
        AmArg& x5urlarg = args[i];
        AmLock lock(mutex);
        auto it = entries.find(x5urlarg.asCStr());
        if(it != entries.end()) {
            entries.erase(it);
            ret++;
        }
    }
    return ret;
}

int CertCache::RenewCerts(const AmArg& args)
{
    if(http_destination.empty()) {
        throw AmSession::Exception(500, "certificates cache is not configured");
    }
    args.assertArray();

    AmLock lock(mutex);

    if(args.size() == 0) {
        for(auto& entry : entries) {
            renewCertEntry(entry);
        }
        return entries.size();
    }

    int ret = 0;
    for(int i = 0; i < args.size(); i++, ret++) {
        AmArg& x5urlarg = args[i];
        auto it = entries.find(x5urlarg.asCStr());
        if(it != entries.end()) {
            renewCertEntry(*it);
        } else {
            auto ret = entries.emplace(x5urlarg.asCStr(), CertCacheEntry{});
            renewCertEntry(*ret.first);
        }
    }
    return ret;
}

