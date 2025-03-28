#pragma once

#include "SBCCallProfile.h"
#include <string>

#include "resources/Resource.h"
#include "resources/ResourceControl.h"
#include "db/DbTypes.h"

#define REFRESH_METHOD_INVITE					1
#define REFRESH_METHOD_UPDATE					2
#define REFRESH_METHOD_UPDATE_FALLBACK_INVITE	3

#define FILTER_TYPE_TRANSPARENT					0
#define FILTER_TYPE_BLACKLIST					1
#define FILTER_TYPE_WHITELIST					2

using std::string;

struct SqlCallProfile
  : public SBCCallProfile
#ifdef OBJECTS_COUNTER
  , ObjCounter(SqlCallProfile)
#endif
{
    int time_limit;
    int disconnect_code_id;
    int session_refresh_method_id;
    int aleg_session_refresh_method_id;
    int aleg_override_id,bleg_override_id;
    int dump_level_id;

    /** whether or not we should parse trusted headers from this gateway */
    bool trusted_hdrs_gw;

    AmArg dyn_fields;

    bool legab_res_mode_enabled;
    string lega_res;
    ResourceList lega_rl;
    /* legb_res */
    string resources;
    ResourceList rl;

    SqlCallProfile();
    ~SqlCallProfile();

    static bool is_empty_profile(const AmArg &a);
    bool readFromTuple(const AmArg &t, const string& local_tag, const DynFieldsT &df);
    ResourceList & getResourceList(bool a_leg = false);

    bool readFilter(const AmArg &t, const char* cfg_key_filter,
        vector<FilterEntry>& filter_list, bool keep_transparent_entry,
        int failover_type_id = FILTER_TYPE_TRANSPARENT);
    bool readFilterSet(const AmArg &t, const char* cfg_key_filter,
        vector<FilterEntry>& filter_list);
    bool readCodecPrefs(const AmArg &t);
    bool readDynFields(const AmArg &t,const DynFieldsT &df);
    bool eval_media_encryption();
    bool eval_resources(const ResourceControl &rctl);
    bool eval_radius();
    bool eval_transport_ids();
    bool eval_protocol_priority();
    bool eval(const ResourceControl &rctl);

    void infoPrint(const DynFieldsT &df);
    void info(AmArg &s);
    SqlCallProfile *copy();
};
