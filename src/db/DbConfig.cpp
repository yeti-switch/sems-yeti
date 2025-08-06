#include "DbConfig.h"
#include "format_helper.h"

string DbConfig::info_str()
{
    string ret;
    ret = user + "@" + host + ":" + int2str(port) + "/" + name;
    return ret;
}

int DbConfig::cfg2dbcfg(AmConfigReader &cfg, const string &prefix, bool silent)
{
    string var;
    var = prefix + "_host";

    bool is_cdr_cfg = prefix.find("cdr") != string::npos;
    bool is_master  = prefix.find("master") != string::npos;

    const string &cdr_str             = "cdr";
    const string &yeti_str            = "yeti";
    const string &default_db_name     = is_cdr_cfg ? cdr_str : yeti_str;
    const string &default_db_user     = is_cdr_cfg ? cdr_str : yeti_str;
    const string &default_db_password = is_cdr_cfg ? cdr_str : yeti_str;

    string var_prefix =
        format("{}.{}{}", is_cdr_cfg ? "cdr" : "routing", is_master ? "master" : "slave", is_cdr_cfg ? "" : "_pool");

    if (cfg.hasParameter(var)) {
        host = cfg.getParameter(var);
    } else {
        host = "127.0.0.1";
        if (!silent)
            WARN("missed %s.host. use: %s", var_prefix.c_str(), host.c_str());
    }

    var = prefix + "_port";
    if (cfg.hasParameter(var)) {
        port = cfg.getParameterInt(var);
    } else {
        port = 5432;
        if (!silent)
            WARN("missed %s.port. use: %d", var_prefix.c_str(), port);
    }
    var = prefix + "_name";
    if (cfg.hasParameter(var)) {
        name = cfg.getParameter(var);
    } else {
        name = default_db_name;
        if (!silent)
            WARN("missed %s.name. use: %s", var_prefix.c_str(), name.c_str());
    }
    var = prefix + "_user";
    if (cfg.hasParameter(var)) {
        user = cfg.getParameter(var);
    } else {
        user = default_db_user;
        if (!silent)
            WARN("missed %s.user. use: %s", var_prefix.c_str(), user.c_str());
    }
    var = prefix + "_pass";
    if (cfg.hasParameter(var)) {
        pass = cfg.getParameter(var);
    } else {
        pass = default_db_password;
        if (!silent)
            WARN("missed %s.pass. use: %s", var_prefix.c_str(), pass.c_str());
    }
    var = prefix + "_keepalives_interval";
    if (cfg.hasParameter(var)) {
        keepalives_interval = cfg.getParameterInt(var);
    } else {
        keepalives_interval = std::nullopt;
    }

    return 0;
}
