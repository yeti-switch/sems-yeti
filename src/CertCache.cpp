#include "CertCache.h"
#include "yeti.h"
#include <AmSessionContainer.h>
#include "cfg/yeti_opts.h"

#include <botan/pk_keys.h>
#include <botan/data_src.h>
#include <botan/x509path.h>
#include "botan/x509_ext.h"

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

    a["valid"] = validation_sucessfull;
    a["validation_result"] = validation_result;
    a["trust_root"] = trust_root_cert;

    auto &cert_chain_amarg = a["cert_chain"];
    cert_chain_amarg.assertArray();
    for(const auto &cert: cert_chain) {
        cert_chain_amarg.push(AmArg());
        CertCache::serialize_cert_to_amarg(cert, cert_chain_amarg.back());
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

    if(cfg_size(cfg, opt_identity_certs_cache_failed_ttl)) {
        cert_cache_failed_ttl =
            std::chrono::seconds(cfg_getint(cfg, opt_identity_certs_cache_failed_ttl));
    } else {
        cert_cache_failed_ttl = cert_cache_ttl;
    }

    if(cfg_size(cfg, opt_identity_certs_cache_failed_verify_ttl)) {
        cert_cache_failed_verify_ttl =
            std::chrono::seconds(cfg_getint(cfg, opt_identity_certs_cache_failed_verify_ttl));
    } else {
        cert_cache_failed_verify_ttl = cert_cache_failed_ttl;
    }

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
    bool repository_is_trusted = isTrustedRepositoryUnsafe(cert_url);
    auto it = entries.find(cert_url);
    if(it == entries.end()) {
        if(!repository_is_trusted)
            return true;

        auto ret = entries.emplace(cert_url, CertCacheEntry{});
        auto &entry = ret.first;

        entry->second.defer_sessions.emplace(session_id);
        renewCertEntry(*entry);

        return false;
    } else {
        //remove cached entries from non-trusted repositories
        if(!repository_is_trusted) {
            if(it->second.state != CertCacheEntry::LOADING) {
                entries.erase(it);
            }
            return true;
        }
    }

    if(it->second.state == CertCacheEntry::LOADING) {
        return false;
    }

    return true;
}

Botan::Public_Key *CertCache::getPubKey(const string& cert_url, bool &cert_is_valid)
{
    AmLock lock(mutex);
    auto it = entries.find(cert_url);
    if(it == entries.end()) {
        return nullptr;
    }

    if(it->second.state != CertCacheEntry::LOADED) {
        return nullptr;
    }

    cert_is_valid = it->second.validation_sucessfull;
    return it->second.cert_chain[0].subject_public_key();
}

bool CertCache::isTrustedRepository(const string& cert_url)
{
    AmLock lock(mutex);
    return isTrustedRepositoryUnsafe(cert_url);
}

void CertCache::processHttpReply(const HttpGetResponseEvent& resp)
{
    AmLock lock(mutex);

    auto it = entries.find(resp.token);
    if(it == entries.end()) {
        ERROR("processHttpReply: absent cache entry %s", resp.token.c_str());
        return;
    }

    auto &entry = it->second;
    entry.response_data = resp.data;
    entry.validation_sucessfull = false;
    try {
        Botan::DataSource_Memory in(entry.response_data);
        while(!in.end_of_data()) {
            try {
                entry.cert_chain.emplace_back(in);
                auto &t = entry.cert_chain.back().not_after();
                if(t.cmp(Botan::X509_Time(std::chrono::_V2::system_clock::now())) < 0)
                    throw Botan::Exception("certificate expired");
            } catch(...) {
                //ignore additional certs parsing exceptions
                if(entry.cert_chain.empty())
                    throw;
            }
        }

        static Botan::Path_Validation_Restrictions restrictions;
        auto validation_result = Botan::x509_path_validate(
            entry.cert_chain, restrictions, trusted_certs_store);

        entry.validation_sucessfull = validation_result.successful_validation();
        entry.validation_result = validation_result.result_string();
        if(entry.validation_sucessfull) {
            entry.trust_root_cert = validation_result.trust_root().subject_dn().to_string();
        }

        if(entry.cert_chain.size())
            it->second.state = CertCacheEntry::LOADED;

    } catch(const Botan::Exception& e) {
        entry.state = CertCacheEntry::UNAVAILABLE;
        entry.error_str = e.what();
        entry.error_code = e.error_code();
        entry.error_type = (int)e.error_type();
    }

    if(entry.state==CertCacheEntry::LOADED) {
        if(entry.validation_sucessfull) {
            entry.expire_time =
                std::chrono::system_clock::now() + cert_cache_ttl;
        } else {
            entry.expire_time =
                std::chrono::system_clock::now() + cert_cache_failed_verify_ttl;
        }
    } else {
        entry.expire_time =
            std::chrono::system_clock::now() + cert_cache_failed_ttl;
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

bool CertCache::isTrustedRepositoryUnsafe(const string &url)
{
    for(const auto &r: trusted_repositories) {
        if(std::regex_match(url, r.regex))
            return true;
    }
    return false;
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

void CertCache::reloadDatabaseSettings(pqxx::connection &c,
                                       bool reload_trusted_cetificates,
                                       bool reload_trusted_repositories) noexcept
{
    //TODO: async DB request
    try {
        pqxx::nontransaction t(c);
        if(reload_trusted_cetificates) {
            auto r = t.exec("SELECT * FROM load_stir_shaken_trusted_certificates()");

            AmLock l(mutex);
            trusted_certs.clear();
            trusted_certs_store = Botan::Certificate_Store_In_Memory();
            for(const auto &row: r) {
                try {
                    trusted_certs.emplace_back(
                        row["id"].as<unsigned long>(),
                        row["name"].c_str());
                    auto &cert_entry = trusted_certs.back();

                    string cert_data = row["certificate"].c_str();
                    //split and parse certificates
                    Botan::DataSource_Memory in(cert_data);
                    while(!in.end_of_data()) {
                        try {
                            cert_entry.certs.emplace_back(new Botan::X509_Certificate(in));
                            trusted_certs_store.add_certificate(cert_entry.certs.back());
                        } catch(Botan::Exception &e) {
                            ERROR("CertCache entry %lu '%s' Botan::exception: %s",
                                cert_entry.id, cert_entry.name.data(),
                                e.what());
                        }
                    }
                } catch(const pqxx::pqxx_exception &e) {
                    ERROR("CertCache row pqxx_exception: %s ",e.base().what());
                }
            }
        }

        if(reload_trusted_repositories) {
            auto r = t.exec("SELECT * FROM load_stir_shaken_trusted_repositories()");

            AmLock l(mutex);
            trusted_repositories.clear();
            for(const auto &row: r) {
                try {
                    trusted_repositories.emplace_back(
                        row["id"].as<unsigned long>(),
                        row["url_pattern"].c_str(),
                        row["validate_https_certificate"].as<bool>());
                } catch(const pqxx::pqxx_exception &e) {
                    ERROR("CertCache row pqxx_exception: %s ",e.base().what());
                } catch(std::regex_error& e) {
                    ERROR("CertCache row regex_error: %s", e.what());
                }
            }
        }
    } catch(const pqxx::pqxx_exception &e){
        ERROR("CertCache pqxx_exception: %s ",e.base().what());
    } catch(...) {
        ERROR("CertCache unexpected exception");
    }
}

void CertCache::onTimer(const std::chrono::system_clock::time_point &now)
{
    {
        AmLock lock(mutex);
        auto it = entries.begin();
        while(it != entries.end()) {
            if(it->second.state==CertCacheEntry::LOADING) {
                it++;
                continue;
            }
            if(isTrustedRepositoryUnsafe(it->first)) {
                if(now > it->second.expire_time) {
                    renewCertEntry(*it);
                }
                it++;
            } else {
                it = entries.erase(it);
            }
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
        auto it = entries.begin();
        while(it != entries.end()) {
            if(isTrustedRepositoryUnsafe(it->first)) {
                renewCertEntry(*it);
                it++;
            } else {
                it = entries.erase(it);
            }
        }
        return entries.size();
    }

    int ret = 0;
    for(int i = 0; i < args.size(); i++) {
        string cert_url(args[i].asCStr());
        bool repository_is_trusted = isTrustedRepositoryUnsafe(cert_url);
        auto it = entries.find(cert_url);
        if(it != entries.end()) {
            if(!repository_is_trusted) {
                entries.erase(it);
                continue;
            }
            renewCertEntry(*it);
            ret++;
        } else {
            if(!repository_is_trusted) {
                continue;
            }
            auto it = entries.emplace(cert_url, CertCacheEntry{});
            renewCertEntry(*it.first);
            ret++;
        }
    }
    return ret;
}

void CertCache::ShowTrustedCerts(AmArg& ret)
{
    AmLock lock(mutex);
    if(trusted_certs.empty()) return;

    auto &entries = ret["entries"];
    for(const auto &cert_entry : trusted_certs) {
        entries.push(AmArg());
        auto &a = entries.back();

        a["id"] = cert_entry.id;
        a["name"] = cert_entry.name;

        auto &certs = a["certs"];
        certs.assertArray();
        for(const auto &cert: cert_entry.certs) {
            certs.push(AmArg());
            CertCache::serialize_cert_to_amarg(*cert, certs.back());
        }
    }

    auto &store = ret["store"];
    for(const auto &dn : trusted_certs_store.all_subjects()) {
        store.push(AmArg());
        auto &a = store.back();
        for(const auto &c: dn.contents()) {
            a[c.first] = c.second;
        }
    }
}

void CertCache::ShowTrustedRepositories(AmArg& ret)
{
    ret.assertArray();

    AmLock lock(mutex);

    for(const auto &r: trusted_repositories) {
        ret.push(AmArg());
        auto &a = ret.back();
        a["id"] = r.id;
        a["url_pattern"] = r.url_pattern;
        a["validate_https_certificate"] = r.validate_https_certificate;
    }
}

void CertCache::serialize_cert_to_amarg(const Botan::X509_Certificate &cert, AmArg &a)
{
    a["not_after"] = cert.not_after().readable_string();
    a["not_before"] = cert.not_before().readable_string();
    a["subject"] = cert.subject_dn().to_string();
    a["issuer"] = cert.issuer_dn().to_string();
    a["fingerprint_sha1"] = cert.fingerprint("SHA-1");
    auto info_vector = cert.subject_info("X509.Certificate.serial");
    if(!info_vector.empty()) {
        a["serial"] = *info_vector.begin();
    }
    info_vector = cert.subject_info("X509v3.SubjectKeyIdentifier");
    if(!info_vector.empty()) {
        a["subject_key_identifier"] = *info_vector.begin();
    }
    info_vector = cert.issuer_info("X509v3.AuthorityKeyIdentifier");
    if(!info_vector.empty()) {
        a["authority_key_identifier"] = *info_vector.begin();
    }

    if(const Botan::Cert_Extension::TNAuthList *tn_auth_list =
       cert.v3_extensions().get_extension_object_as<Botan::Cert_Extension::TNAuthList>())
    {
        AmArg &tn_list = a["tn_auth_list"];
        tn_list.assertArray();
        for(const auto &e:  tn_auth_list->get_entries()) {
            tn_list.push(AmArg());
            auto &tn = tn_list.back();
            tn.assertStruct();
            switch(e.get_type()) {
            case Botan::Cert_Extension::TNAuthList::TNEntry::TN_ServiceProviderCode:
                tn["spc"] = e.getServiceProviderCode();
                break;
            case Botan::Cert_Extension::TNAuthList::TNEntry::TN_TelephoneNumberRange: {
                auto &ranges = tn["range"];
                ranges.assertArray();
                for(auto &range : e.getTelephoneNumberRange()) {
                    ranges.push(AmArg());
                    auto &r = ranges.back();
                    r["start"] = range.start;
                    r["count"] = range.count;
                }
            } break;
            case Botan::Cert_Extension::TNAuthList::TNEntry::TN_TelephoneNumber:
                tn["one"] = e.getTelephoneNumber();
                break;
            }
        }
    }
}
