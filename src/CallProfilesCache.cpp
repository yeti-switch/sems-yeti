#include "CallProfilesCache.h"
#include "yeti.h"
#include "jsonArg.h"

void CallProfilesCache::merge_cached_profile_data(AmArg &profile_data, const AmArg &cached_data)
{
    for (const auto &it : *cached_data.asStruct()) {
        if (!profile_data.hasMember(it.first))
            profile_data[it.first] = it.second;
    }
}

void CallProfilesCache::load_callprofiles(const PGResponse &e)
{
    int                                    common_profile_idx = -1;
    std::unordered_map<std::string, AmArg> new_cache;

    for (size_t i = 0; i < e.result.size(); i++) {
        const AmArg &a = e.result.get(i);

        if (Yeti::instance().config.postgresql_debug) {
            for (const auto &it : *a.asStruct()) {
                DBG("profile[%d]: %s %s", i, it.first.data(), arg2json(it.second).data());
            }
        }

        string cache_id_str;
        if (a.hasMember("cache_id")) {
            const auto &cache_id = a["cache_id"];
            if (cache_id.is<AmArg::CStr>()) {
                cache_id_str = cache_id.asCStr();
            } else if (!cache_id.is<AmArg::Undef>()) {
                ERROR("unexpected cache_id type %s at the row: %d", cache_id.getTypeStr(), i);
                continue;
            }
        }

        if (cache_id_str.empty()) {
            if (common_profile_idx < 0) {
                common_profile_idx = i;
            } else {
                ERROR("duplicate common profile at the row: %d (first occurence at: %d)", i, common_profile_idx);
            }
            continue;
        }

        if (new_cache.contains(cache_id_str)) {
            ERROR("duplicate profile for key '%s'", cache_id_str.data());
            continue;
        }

        new_cache.emplace(cache_id_str, a);
    }

    AmLock l(cache_mutex);

    cache.swap(new_cache);

    if (common_profile_idx >= 0) {
        common_profile_data = e.result.get(common_profile_idx);
    } else {
        common_profile_data.clear();
    }
}

bool CallProfilesCache::complete_profile(AmArg &profile_data)
{
    if (!profile_data.hasMember("cache_id")) {
        if (profile_data.hasMember("disconnect_code_id")) {
            const auto &disconnect_code_id = profile_data["disconnect_code_id"];
            if (disconnect_code_id.is<AmArg::Int>() && disconnect_code_id.asInt() != 0) {
                // skip common profile merging for disconnecting profile
                return true;
            }
        }
        if (!common_profile_data.is<AmArg::Undef>()) {
            merge_cached_profile_data(profile_data, common_profile_data);
        }
        return true;
    }

    const auto &cache_id = profile_data["cache_id"];

    AmLock l(cache_mutex);

    if (cache_id.is<AmArg::CStr>()) {
        // lookup cache
        const auto it = cache.find(cache_id.asCStr());
        if (it == cache.end()) {
            ERROR("no preloaded profile for cache_id: %s", cache_id.asCStr());
            return false;
        }

        merge_cached_profile_data(profile_data, it->second);
    }

    if (!common_profile_data.is<AmArg::Undef>()) {
        merge_cached_profile_data(profile_data, common_profile_data);
    }

    return true;
}
