#pragma once

#include <AmArg.h>
#include <AmThread.h>
#include <ampi/PostgreSqlAPI.h>

#include <unordered_map>

class CallProfilesCache {
  private:
    std::unordered_map<std::string, AmArg> cache;
    AmMutex                                cache_mutex;

    AmArg common_profile_data;

    static void merge_cached_profile_data(AmArg &profile_data, const AmArg &cached_data);

  public:
    void load_callprofiles(const PGResponse &e);

    bool complete_profile(AmArg &profile_Data);
};
