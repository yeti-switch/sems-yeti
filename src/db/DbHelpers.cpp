#include "DbHelpers.h"

bool DbAmArg_hash_get_bool(
    const AmArg &a,
    const std::string &key,
    bool default_value)
{
    if(!a.hasMember(key)) return default_value;
    AmArg &v = a[key];
    if(isArgUndef(v)) return default_value;
    if(!isArgBool(v)) {
        ERROR("not bool value by the key '%s'", key.data());
        return default_value;
    }
    return v.asBool();
}

bool DbAmArg_hash_get_bool_any(
    const AmArg &a,
    const std::string &key,
    bool default_value)
{
    if(!a.hasMember(key)) return default_value;
    AmArg &v = a[key];
    if(isArgBool(v)) return v.asBool();
    if(isArgUndef(v)) return default_value;
    if(isArgInt(v)) return 0!=v.asInt();
    if(isArgCStr(v)) {
        std::string s = v.asCStr();
        return (s=="t" || s=="yes" || s=="true" || s=="1") ? true : false;
    }
    return default_value;
}

std::string DbAmArg_hash_get_str(const AmArg &a, const std::string &key,
                            const std::string &default_string)
{
    if(!a.hasMember(key)) return default_string;
    AmArg &v = a[key];
    if(isArgUndef(v)) return default_string;
    if(!isArgCStr(v)) {
        ERROR("not str value by the key '%s'", key.data());
        return default_string;
    }
    return v.asCStr();
}

std::string DbAmArg_hash_get_str_any(
    const AmArg &a,
    const std::string &key,
    const std::string &default_string)
{
    if(!a.hasMember(key)) return default_string;
    AmArg &v = a[key];
    if(isArgUndef(v)) return default_string;
    if(isArgCStr(v)) return v.asCStr();
    return AmArg::print(v);
}

int DbAmArg_hash_get_int(const AmArg &a, const std::string &key, int default_value)
{
    if(!a.hasMember(key)) return default_value;
    AmArg &v = a[key];
    if(isArgUndef(v)) return default_value;
    if(!isArgInt(v)) {
        ERROR("not int value by the key '%s'", key.data());
        return default_value;
    }
    return v.asInt();
}

int DbAmArg_hash_get_int(
    const AmArg &a, const std::string &key,
    int default_value, int failover_value)
{
    if(!a.hasMember(key)) return failover_value;
    AmArg &v = a[key];
    if(isArgUndef(v)) return default_value;
    if(!isArgInt(v)) {
        ERROR("not int value by the key '%s'", key.data());
        return failover_value;
    }
    return v.asInt();
}

