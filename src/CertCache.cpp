#include "CertCache.h"
#include "yeti.h"
#include <AmSessionContainer.h>
#include "cfg/yeti_opts.h"

CertCache::CertCache()
{}

CertCache::~CertCache()
{
    AmLock lock(mutex);
    for(auto pair : entries) {
        delete pair.second;
    }
}

int CertCache::configure(cfg_t *cfg)
{
    expires = cfg_getint(cfg, opt_identity_expires);
    cert_cache_ttl = cfg_getint(cfg, opt_identity_certs_cache_ttl);
    if(cfg_size(cfg, opt_identity_http_destination)) {
        http_destination = cfg_getstr(cfg, opt_identity_http_destination);
    } else {
        ERROR("missed mandatory param 'http_destination' for identity section");
        return -1;
    }
    return 0;
}

CertCacheEntry * CertCache::getCertEntry(const string& x5url, const string& session_id)
{
    AmLock lock(mutex);
    auto it = entries.find(x5url);
    if(it == entries.end()) {
        CertCacheEntry *entry = new CertCacheEntry;
        entry->defer_sessions.push_back(session_id);
        entries.emplace(x5url, entry);
        AmSessionContainer::instance()->postEvent(
            HTTP_EVENT_QUEUE,
            new HttpGetEvent(http_destination, //destination
                            x5url,                                   //url
                            x5url,                                   //token
                            YETI_QUEUE_NAME));                       //session_id
        return 0;
    }

    if(it->second->expire_time > time(0)) {
        it->second->state = CertCacheEntry::EXPIRED;
    }

    if(it->second->state != CertCacheEntry::LOADING) return it->second;

    it->second->defer_sessions.push_back(session_id);
    return 0;
}

void CertCache::processHttpReply(const HttpGetResponseEvent& resp)
{
    AmLock lock(mutex);
    auto it = entries.find(resp.token);
    if(it == entries.end()) {
        ERROR("processHttpReply: absent cache entry %s", resp.token.c_str());
        return;
    }

    if(resp.mime_type.empty()) {
        it->second->state = CertCacheEntry::UNAVAILABLE;
        it->second->error_code = resp.code;
        it->second->error_type = (int)Botan::ErrorType::HttpError;
    } else {
        it->second->cert_binary.resize(resp.data.size());
        memcpy(it->second->cert_binary.data(), resp.data.c_str(), resp.data.size());
        try {
            Botan::X509_Certificate cert(it->second->cert_binary);
            const Botan::X509_Time& t = cert.not_after();
            if(t.cmp(Botan::X509_Time(std::chrono::_V2::system_clock::now())) < 0)
                throw Botan::Exception("certificate expired");
            it->second->cert = cert;
            it->second->expire_time = time(0) + cert_cache_ttl;
            it->second->state = CertCacheEntry::LOADED;
        } catch(const Botan::Exception& e) {
            it->second->state = CertCacheEntry::UNAVAILABLE;
            it->second->error_str = e.what();
            it->second->error_code = e.error_code();
            it->second->error_type = (int)e.error_type();
        }
    }

    for(auto& session_id : it->second->defer_sessions) {
        if(AmSessionContainer::instance()->postEvent(session_id, 
                        new HttpGetResponseEvent(resp.code, resp.data, resp.mime_type, resp.token)))
        {
            ERROR("failed to post HttpGetResponseEvent for session %s",
                session_id.c_str());
        }
    }

    it->second->defer_sessions.clear();
}

void CertCache::ShowCerts(AmArg& ret)
{
    ret.assertArray();
    AmLock lock(mutex);
    for(auto& pair : entries) {
        AmArg entry;
        entry["url"] = pair.first;
        entry["expire_time"] = pair.second->expire_time;
        entry["error_str"] = pair.second->error_str;
        entry["error_code"] = pair.second->error_code;
        entry["error_type"] = pair.second->error_type ? Botan::to_string((Botan::ErrorType)pair.second->error_type) : "";
        entry["state"] = CertCacheEntry::to_string(pair.second->state);
        try {
            entry["cert_end_time"] = pair.second->cert.not_after().readable_string();
        } catch(Botan::Exception&) {
            entry["cert_end_time"] = "";
        }
        try {
            entry["cert_serial"] = pair.second->cert.subject_info("X509.Certificate.serial")[0];
        } catch(Botan::Exception&) {
            entry["cert_serial"] = "";
        }
        try {
            entry["cert_start_time"] = pair.second->cert.not_before().readable_string();
        } catch(Botan::Exception&) {
            entry["cert_start_time"] = "";
        }
        ret.push(entry);
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
    args.assertArray();
    if(args.size() == 0) {
        for(auto& entry : entries) {
            entry.second->reset();
            AmSessionContainer::instance()->postEvent(
                HTTP_EVENT_QUEUE,
                new HttpGetEvent(http_destination, //destination
                                entry.first,                             //url
                                entry.first,                             //token
                                YETI_QUEUE_NAME));                       //session_id
        }
        return entries.size();
    }

    int ret = 0;
    for(int i = 0; i < args.size(); i++, ret++) {
        AmArg& x5urlarg = args[i];
        AmLock lock(mutex);
        auto it = entries.find(x5urlarg.asCStr());
        if(it != entries.end()) it->second->reset();
        else {
            CertCacheEntry *entry = new CertCacheEntry;
            entries.emplace(x5urlarg.asCStr(), entry);
        }
        AmSessionContainer::instance()->postEvent(
            HTTP_EVENT_QUEUE,
            new HttpGetEvent(http_destination, //destination
                            x5urlarg.asCStr(),                       //url
                            x5urlarg.asCStr(),                       //token
                            YETI_QUEUE_NAME));                       //session_id
    }
    return ret;
}

