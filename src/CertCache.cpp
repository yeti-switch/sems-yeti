#include "CertCache.h"
#include "yeti.h"
#include <AmSessionContainer.h>
#include "cfg/yeti_opts.h"
#include "format_helper.h"

#include <botan/pk_keys.h>
#include <botan/data_src.h>
#include <botan/x509path.h>
#include "botan/x509_ext.h"

#include <chrono>

void CertCacheEntry::getInfo(AmArg &a, const std::chrono::system_clock::time_point &now) const
{
    a["state"] = CertCacheEntry::to_string(state);

    if (state == LOADING)
        return;

    a["ttl"]        = std::chrono::duration_cast<std::chrono::seconds>(expire_time - now).count();
    a["error_str"]  = error_str;
    a["error_code"] = error_code;
    a["error_type"] = error_type ? Botan::to_string((Botan::ErrorType)error_type) : "";
    a["state"]      = CertCacheEntry::to_string(state);

    a["valid"]             = validation_sucessfull;
    a["validation_result"] = validation_result;
    a["trust_root"]        = trust_root_cert;

    auto &cert_chain_amarg = a["cert_chain"];
    cert_chain_amarg.assertArray();
    for (const auto &cert : cert_chain) {
        cert_chain_amarg.push(AmArg());
        CertCache::serialize_cert_to_amarg(cert, cert_chain_amarg.back());
    }
}

CertCache::CertCache() {}

CertCache::~CertCache() {}

int CertCache::configure(cfg_t *cfg)
{
    expires        = cfg_getint(cfg, opt_identity_expires);
    cert_cache_ttl = std::chrono::seconds(cfg_getint(cfg, opt_identity_certs_cache_ttl));

    if (cfg_size(cfg, opt_identity_certs_cache_failed_ttl)) {
        cert_cache_failed_ttl = std::chrono::seconds(cfg_getint(cfg, opt_identity_certs_cache_failed_ttl));
    } else {
        cert_cache_failed_ttl = cert_cache_ttl;
    }

    if (cfg_size(cfg, opt_identity_certs_cache_failed_verify_ttl)) {
        cert_cache_failed_verify_ttl =
            std::chrono::seconds(cfg_getint(cfg, opt_identity_certs_cache_failed_verify_ttl));
    } else {
        cert_cache_failed_verify_ttl = cert_cache_failed_ttl;
    }

    if (cfg_size(cfg, opt_identity_http_destination)) {
        http_destination = cfg_getstr(cfg, opt_identity_http_destination);
    } else {
        ERROR("missed mandatory param 'http_destination' for identity section");
        return -1;
    }

    return 0;
}

bool CertCache::checkAndFetch(const string &cert_url, const string &session_id)
{
    std::unique_lock lock(certificates_mutex);

    bool repository_is_trusted = isTrustedRepositoryUnsafe(cert_url);
    auto it                    = certificates.find(cert_url);
    if (it == certificates.end()) {
        if (!repository_is_trusted)
            return true;

        auto  ret   = certificates.emplace(cert_url, CertCacheEntry{});
        auto &entry = ret.first;

        entry->second.defer_sessions.emplace(session_id);
        renewCertEntry(*entry);

        return false;
    } else {
        // remove cached entries from non-trusted repositories
        if (!repository_is_trusted) {
            if (it->second.state != CertCacheEntry::LOADING) {
                certificates.erase(it);
            }
            return true;
        }
    }

    if (it->second.state == CertCacheEntry::LOADING) {
        return false;
    }

    return true;
}

std::unique_ptr<Botan::Public_Key> CertCache::getPubKey(const string &cert_url, AmArg &info, bool &cert_is_valid) const
{
    std::shared_lock lock(certificates_mutex);

    auto it = certificates.find(cert_url);
    if (it == certificates.end()) {
        return nullptr;
    }

    if (it->second.state != CertCacheEntry::LOADED) {
        return nullptr;
    }

    cert_is_valid = it->second.validation_sucessfull;

    auto const &cert = it->second.cert_chain[0];

    auto &cert_info               = info["cert"];
    cert_info["fingerprint_sha1"] = cert.fingerprint("SHA-1");
    cert_info["subject"]          = cert.subject_dn().to_string();
    serialize_cert_tn_auth_list_to_amarg(cert, cert_info);

    return cert.subject_public_key();
}

bool CertCache::isTrustedRepository(const string &cert_url) const
{
    std::shared_lock lock(certificates_mutex);
    return isTrustedRepositoryUnsafe(cert_url);
}

std::optional<std::string> CertCache::getIdentityHeader(AmIdentity &identity, unsigned long signing_key_id) const
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

void CertCache::processHttpReply(const HttpGetResponseEvent &resp)
{
    std::unique_lock lock(certificates_mutex);

    auto it = certificates.find(resp.token);
    if (it == certificates.end()) {
        ERROR("processHttpReply: absent cache entry %s", resp.token.c_str());
        return;
    }

    auto &entry                 = it->second;
    entry.response_data         = resp.data;
    entry.validation_sucessfull = false;
    try {
        Botan::DataSource_Memory in(entry.response_data);
        while (!in.end_of_data()) {
            try {
                entry.cert_chain.emplace_back(in);
                auto &t = entry.cert_chain.back().not_after();
                if (t.cmp(Botan::X509_Time(std::chrono::_V2::system_clock::now())) < 0)
                    throw Botan::Exception("certificate expired");
            } catch (...) {
                // ignore additional certs parsing exceptions
                if (entry.cert_chain.empty())
                    throw;
            }
        }

        static Botan::Path_Validation_Restrictions restrictions;
        auto validation_result = Botan::x509_path_validate(entry.cert_chain, restrictions, trusted_certs_store);

        entry.validation_sucessfull = validation_result.successful_validation();
        entry.validation_result     = validation_result.result_string();
        if (entry.validation_sucessfull) {
            entry.trust_root_cert = validation_result.trust_root().subject_dn().to_string();
        }

        if (entry.cert_chain.size())
            it->second.state = CertCacheEntry::LOADED;

    } catch (const Botan::Exception &e) {
        entry.state      = CertCacheEntry::UNAVAILABLE;
        entry.error_str  = e.what();
        entry.error_code = e.error_code();
        entry.error_type = (int)e.error_type();
    }

    if (entry.state == CertCacheEntry::LOADED) {
        if (entry.validation_sucessfull) {
            entry.expire_time = std::chrono::system_clock::now() + cert_cache_ttl;
        } else {
            entry.expire_time = std::chrono::system_clock::now() + cert_cache_failed_verify_ttl;
        }
    } else {
        entry.expire_time = std::chrono::system_clock::now() + cert_cache_failed_ttl;
    }

    auto result = it->second.state == CertCacheEntry::LOADED ? KEY_RESULT_READY : KEY_RESULT_UNAVAILABLE;

    for (auto &session_id : it->second.defer_sessions) {
        if (!AmSessionContainer::instance()->postEvent(session_id, new CertCacheResponseEvent(result, it->first))) {
            ERROR("failed to post CertCacheResponseEvent for session %s", session_id.c_str());
        }
    }

    it->second.defer_sessions.clear();
}

bool CertCache::isTrustedRepositoryUnsafe(const string &url) const
{
    for (const auto &r : trusted_repositories) {
        if (std::regex_match(url, r.regex))
            return true;
    }
    return false;
}

void CertCache::renewCertEntry(HashType::value_type &entry)
{
    entry.second.reset();
    AmSessionContainer::instance()->postEvent(HTTP_EVENT_QUEUE,
                                              new HttpGetEvent(http_destination,  // destination
                                                               entry.first,       // url
                                                               entry.first,       // token
                                                               YETI_QUEUE_NAME)); // session_id
}

void CertCache::reloadTrustedCertificates(const AmArg &data)
{
    std::unique_lock lock(certificates_mutex);

    trusted_certs.clear();
    if (!isArgArray(data))
        return;
    for (size_t i = 0; i < data.size(); i++) {
        AmArg &a = data[i];
        trusted_certs.emplace_back(a["id"].asInt(), a["name"].asCStr());
        auto  &cert_entry = trusted_certs.back();
        string cert_data  = a["certificate"].asCStr();
        // split and parse certificates
        Botan::DataSource_Memory in(cert_data);
        while (!in.end_of_data()) {
            try {
                cert_entry.certs.emplace_back(new Botan::X509_Certificate(in));
                trusted_certs_store.add_certificate(*cert_entry.certs.back().get());
            } catch (Botan::Exception &e) {
                ERROR("CertCache trusted entry %lu '%s' Botan::exception: %s", cert_entry.id, cert_entry.name.data(),
                      e.what());
            }
        }
    }
}

void CertCache::reloadTrustedRepositories(const AmArg &data)
{
    std::unique_lock lock(certificates_mutex);

    trusted_repositories.clear();
    if (!isArgArray(data))
        return;
    for (size_t i = 0; i < data.size(); i++) {
        AmArg &a = data[i];
        try {
            trusted_repositories.emplace_back(a["id"].asInt(), a["url_pattern"].asCStr(),
                                              a["validate_https_certificate"].asBool());
        } catch (std::regex_error &e) {
            ERROR("CertCache row regex_error: %s", e.what());
        }
    }
}

void CertCache::reloadSigningKeys(const AmArg &data)
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
            ERROR("CertCache signing entry %lu '%s' Botan::exception: %s", id, name.data(), e.what());
        }
    }
}

void CertCache::onTimer(const std::chrono::system_clock::time_point &now)
{
    {
        std::unique_lock lock(certificates_mutex);

        auto it = certificates.begin();
        while (it != certificates.end()) {
            if (it->second.state == CertCacheEntry::LOADING) {
                it++;
                continue;
            }
            if (isTrustedRepositoryUnsafe(it->first)) {
                if (now > it->second.expire_time) {
                    renewCertEntry(*it);
                }
                it++;
            } else {
                it = certificates.erase(it);
            }
        }
    }
}

void CertCache::ShowCerts(AmArg &ret, const std::chrono::system_clock::time_point &now) const
{
    ret.assertArray();
    std::shared_lock lock(certificates_mutex);

    for (auto &pair : certificates) {
        ret.push(AmArg());
        auto &entry  = ret.back();
        entry["url"] = pair.first;
        pair.second.getInfo(entry, now);
    }
}

int CertCache::ClearCerts(const AmArg &args)
{
    int ret = 0;
    args.assertArray();

    std::unique_lock lock(certificates_mutex);

    if (args.size() == 0) {
        ret = certificates.size();
        certificates.clear();
        return ret;
    }
    for (unsigned int i = 0; i < args.size(); i++) {
        AmArg &x5urlarg = args[i];
        auto   it       = certificates.find(x5urlarg.asCStr());
        if (it != certificates.end()) {
            certificates.erase(it);
            ret++;
        }
    }
    return ret;
}

int CertCache::RenewCerts(const AmArg &args)
{
    if (http_destination.empty()) {
        throw AmSession::Exception(500, "certificates cache is not configured");
    }
    args.assertArray();

    std::unique_lock lock(certificates_mutex);

    if (args.size() == 0) {
        auto it = certificates.begin();
        while (it != certificates.end()) {
            if (isTrustedRepositoryUnsafe(it->first)) {
                renewCertEntry(*it);
                it++;
            } else {
                it = certificates.erase(it);
            }
        }
        return certificates.size();
    }

    int ret = 0;
    for (unsigned int i = 0; i < args.size(); i++) {
        string cert_url(args[i].asCStr());
        bool   repository_is_trusted = isTrustedRepositoryUnsafe(cert_url);
        auto   it                    = certificates.find(cert_url);
        if (it != certificates.end()) {
            if (!repository_is_trusted) {
                certificates.erase(it);
                continue;
            }
            renewCertEntry(*it);
            ret++;
        } else {
            if (!repository_is_trusted) {
                continue;
            }
            auto it = certificates.emplace(cert_url, CertCacheEntry{});
            renewCertEntry(*it.first);
            ret++;
        }
    }
    return ret;
}

void CertCache::ShowTrustedCerts(AmArg &ret) const
{
    std::shared_lock lock(certificates_mutex);

    if (trusted_certs.empty())
        return;

    auto &entries = ret["entries"];
    for (const auto &cert_entry : trusted_certs) {
        entries.push(AmArg());
        auto &a = entries.back();

        a["id"]   = cert_entry.id;
        a["name"] = cert_entry.name;

        auto &certs = a["certs"];
        certs.assertArray();
        for (const auto &cert : cert_entry.certs) {
            certs.push(AmArg());
            CertCache::serialize_cert_to_amarg(*cert, certs.back());
        }
    }

    auto &store = ret["store"];
    for (const auto &dn : trusted_certs_store.all_subjects()) {
        store.push(AmArg());
        auto &a = store.back();
        for (const auto &c : dn.contents()) {
            a[c.first] = c.second;
        }
    }
}

void CertCache::ShowTrustedRepositories(AmArg &ret) const
{
    ret.assertArray();

    std::shared_lock lock(certificates_mutex);

    for (const auto &r : trusted_repositories) {
        ret.push(AmArg());
        auto &a                         = ret.back();
        a["id"]                         = r.id;
        a["url_pattern"]                = r.url_pattern;
        a["validate_https_certificate"] = r.validate_https_certificate;
    }
}

void CertCache::ShowSigningKeys(AmArg &ret) const
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

void CertCache::serialize_cert_tn_auth_list_to_amarg(const Botan::X509_Certificate &cert, AmArg &a)
{
    if (const Botan::Cert_Extension::TNAuthList *tn_auth_list =
            cert.v3_extensions().get_extension_object_as<Botan::Cert_Extension::TNAuthList>())
    {
        AmArg &tn_list = a["tn_auth_list"];
        tn_list.assertArray();
        for (const auto &e : tn_auth_list->entries()) {
            tn_list.push(AmArg());
            auto &tn = tn_list.back();
            tn.assertStruct();
            switch (e.type()) {
            case Botan::Cert_Extension::TNAuthList::Entry::ServiceProviderCode:
                tn["spc"] = e.service_provider_code();
                break;
            case Botan::Cert_Extension::TNAuthList::Entry::TelephoneNumberRange:
            {
                auto &ranges = tn["range"];
                ranges.assertArray();
                for (auto &range : e.telephone_number_range()) {
                    ranges.push(AmArg());
                    auto &r    = ranges.back();
                    r["start"] = range.start.value();
                    r["count"] = range.count;
                }
            } break;
            case Botan::Cert_Extension::TNAuthList::Entry::TelephoneNumber: tn["one"] = e.telephone_number(); break;
            }
        }
    }
}

void CertCache::serialize_cert_to_amarg(const Botan::X509_Certificate &cert, AmArg &a)
{
    a["not_after"]        = cert.not_after().readable_string();
    a["not_before"]       = cert.not_before().readable_string();
    a["subject"]          = cert.subject_dn().to_string();
    a["issuer"]           = cert.issuer_dn().to_string();
    a["fingerprint_sha1"] = cert.fingerprint("SHA-1");
    auto info_vector      = cert.subject_info("X509.Certificate.serial");
    if (!info_vector.empty()) {
        a["serial"] = *info_vector.begin();
    }
    info_vector = cert.subject_info("X509v3.SubjectKeyIdentifier");
    if (!info_vector.empty()) {
        a["subject_key_identifier"] = *info_vector.begin();
    }
    info_vector = cert.issuer_info("X509v3.AuthorityKeyIdentifier");
    if (!info_vector.empty()) {
        a["authority_key_identifier"] = *info_vector.begin();
    }

    serialize_cert_tn_auth_list_to_amarg(cert, a);
}
