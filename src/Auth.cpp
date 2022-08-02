#include "Auth.h"
#include "AmApi.h"
#include "AmPlugIn.h"
#include "AmSipDialog.h"
#include "sip/defs.h"
#include "md5.h"
#include "AmUriParser.h"
#include "yeti.h"

#include <unistd.h>

#define MAX_HOSTNAME_LEN 255


inline string find_attribute(const string& name, const string& header) {
    size_t pos1 = header.find(name);

    while (true) {
        if (pos1 == string::npos)
            return "";

        if (!pos1 || header[pos1-1] == ',' || header[pos1-1] == ' ')
            break;

        pos1 = header.find(name, pos1+1);
    }

    pos1+=name.length();
    pos1 = header.find_first_not_of(" =\"", pos1);
    if (pos1 != string::npos) {
        size_t pos2 = header.find_first_of(",\"", pos1);
        if (pos2 != string::npos) {
            return header.substr(pos1, pos2-pos1);
        } else {
            return header.substr(pos1); // end of hdr
        }
    }

    return "";
}

void Auth::CredentialsContainer::add(
    auth_id_type id,
    const std::string &username,
    const std::string &password)
{
    emplace(username,cred(id,username,password));
}

Auth::Auth()
  : uac_auth(nullptr)
  , skip_logging_invite_challenge(false)
  , skip_logging_invite_success(false)
{}

int Auth::auth_configure(cfg_t* cfg)
{
    char* realm_ = cfg_getstr(cfg, "realm");
    if(!realm_ || strlen(realm_) == 0) {
        //use hostname as realm if not configured
        char hostname[MAX_HOSTNAME_LEN];
        if(-1==gethostname(hostname,MAX_HOSTNAME_LEN)) {
            if(ENAMETOOLONG==errno)
                hostname[MAX_HOSTNAME_LEN-1] = 0;
        }
        realm = hostname;
    } else {
        realm = realm_;
    }

    if(cfg_size(cfg, "skip_logging_invite_success"))
        skip_logging_invite_success = cfg_getbool(cfg, "skip_logging_invite_success");

    if(cfg_size(cfg, "skip_logging_invite_challenge"))
        skip_logging_invite_challenge = cfg_getbool(cfg, "skip_logging_invite_challenge");

    DBG("auth_init: configured to use realm: '%s', skip_logging_invite_success: %s, skip_logging_invite_challenge: %s",
        realm.c_str(), skip_logging_invite_success ? "true" : "false", skip_logging_invite_challenge ? "true" : "false");
    return 0;
}

int Auth::auth_init()
{
    AmDynInvokeFactory* di_f = AmPlugIn::instance()->getFactory4Di("uac_auth");
    if (NULL==di_f) {
        ERROR("unable to get uac_auth factory");
        return -1;
    }
    uac_auth = di_f->getInstance();
    if (NULL==uac_auth) {
        ERROR("unable to get uac_auth invoke instance");
        return -1;
    }

    return 0;
}

void Auth::reload_credentials(const AmArg &data)
{
    CredentialsContainer c;

    AmLock l(credentials_mutex);

    if(isArgArray(data)) {
        for(size_t i = 0; i < data.size(); i++) {
            auto &a = data[i];
            c.add(a["id"].asInt(),
                  a["username"].asCStr(),
                  a["password"].asCStr());
        }
    }

    DBG("loaded credentials list. %zd items",c.size());

    credentials.swap(c);
}

Auth::auth_id_type Auth::check_request_auth(const AmSipRequest &req,  AmArg &ret)
{
    string auth_hdr =  getHeader(req.hdrs, SIP_HDR_AUTHORIZATION);
    if(auth_hdr.empty()) {
        //no auth header. just continue
        return NO_AUTH;
    }

    string username = find_attribute("username", auth_hdr);
    if(username.empty()) {
        DBG("no username attribute in " SIP_HDR_AUTHORIZATION " header");
        ret = "no username in Authorization header";
        return -NO_USERNAME;
    }

    credentials_mutex.lock();

    auto range = credentials.equal_range(username);
    if(range.first == credentials.end()) {
        credentials_mutex.unlock();
        DBG("no credentials for username '%s'",username.c_str());
        ret = "no credentials for username";
        return -NO_CREDENTIALS;
    }

    size_t creds_count = std::distance(range.first,range.second);
    std::vector<cred> creds;
    creds.reserve(creds_count);
    for (auto it = range.first; it != range.second; ++it)
        creds.push_back(it->second);

    credentials_mutex.unlock();

    DBG("there are %zd credentials for username '%s'. iterate over them",
        creds_count,username.c_str());

    AmArg args;
    args.push((AmObject *) &req);
    args.push(realm);
    args.push(username);
    args.push(AmArg());

    for(const auto &c: creds) {
        ret.clear();

        DBG("match against %d/%s/%s",
            c.id,c.username.c_str(),c.password.c_str());

        args[3] = c.password;
        uac_auth->invoke("checkAuth", args, ret);

        int reply_code = ret[0].asInt();
        if(reply_code==200) {
            DBG("matched. return auth_id %d",c.id);
            return c.id;
        }
    }

    //see ampi/UACAuthAPI.h: UACAuthErrorCodes
    return -(UAC_AUTH_ERROR + ret[4].asInt()); //add uac_auth internal_code
}

void Auth::send_auth_challenge(const AmSipRequest &req, const string &hdrs)
{
    AmArg args, ret;
    args.push(realm);

    ret.clear();
    uac_auth->invoke("getChallenge", args, ret);

    AmSipDialog::reply_error(req, 401, "Unauthorized", hdrs + ret.asCStr());
}

void Auth::auth_info(AmArg &ret)
{
    ret.assertArray();
    AmLock l(credentials_mutex);
    for(const auto &c_it: credentials) {
        const cred &c = c_it.second;
        ret.push(AmArg());
        AmArg &a = ret.back();
        a["id"] = c.id;
        a["user"] = c.username;
        a["pwd"] = c.password;
    }
}

void Auth::auth_info_by_user(const string &username, AmArg &ret)
{
    ret.assertArray();

    credentials_mutex.lock();

    auto range = credentials.equal_range(username);
    if(range.first == credentials.end()) {
        credentials_mutex.unlock();
        DBG("no credentials for username '%s'",username.c_str());
        return;
    }

    size_t creds_count = std::distance(range.first,range.second);
    std::vector<cred> creds;
    creds.reserve(creds_count);
    for (auto it = range.first; it != range.second; ++it)
        creds.push_back(it->second);

    credentials_mutex.unlock();

    for(const auto &c: creds) {
        ret.push(AmArg());
        AmArg &a = ret.back();
        a["id"] = c.id;
        a["user"] = c.username;
        a["pwd"] = c.password;
    }

}

void Auth::auth_info_by_id(auth_id_type id, AmArg &ret)
{
    ret.assertArray();

    AmLock l(credentials_mutex);

    for(const auto &i: credentials) {
        const cred &c = i.second;

        if(c.id!=id) continue;

        ret.push(AmArg());
        AmArg &a = ret.back();
        a["id"] = c.id;
        a["user"] = c.username;
        a["pwd"] = c.password;
    }
}

