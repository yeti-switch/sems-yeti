#include "Auth.h"
#include "AmApi.h"
#include "AmPlugIn.h"
#include "AmSipDialog.h"
#include "sip/defs.h"
#include "AmUriParser.h"
#include "AmUtils.h"
#include "AmIdentity.h"
#include "cfg/yeti_opts.h"

#include <unistd.h>
#include <botan/x509_key.h>

#define MAX_HOSTNAME_LEN 255
#define AUTH_MOCKING_ENABLED 0

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

void Auth::CredentialsContainer::add(const AmArg &data)
{
    auth_id_type id = data["id"].asInt();

    if (data.hasMember("username") && data.hasMember("password")) {
        string username = data["username"].asCStr();
        if(!username.empty()) {
            by_user.emplace(username, cred(id, username, data["password"].asCStr()));
        }
    }

    if (data.hasMember("allow_jwt_auth")) {
        auto &a = data["allow_jwt_auth"];
        if ((isArgBool(a) && a.asBool())) {
            allowed_jwt_auth.emplace(id);
            if (data.hasMember("jwt_gid")) {
                by_gid.emplace(data["jwt_gid"].asCStr(), id);
            }
        }
    }
}

void Auth::CredentialsContainer::swap(CredentialsContainer &rhs)
{
    by_user.swap(rhs.by_user);
    by_gid.swap(rhs.by_gid);
    allowed_jwt_auth.swap(rhs.allowed_jwt_auth);
}

Auth::Auth()
  : uac_auth(nullptr)
  , skip_logging_invite_challenge(false)
  , skip_logging_invite_success(false)
{}

int Auth::auth_configure(cfg_t* cfg)
{
    char* realm_ = cfg_getstr(cfg, opt_name_auth_realm);
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

    if(cfg_size(cfg, opt_name_auth_skip_logging_invite_success))
        skip_logging_invite_success = cfg_getbool(cfg, opt_name_auth_skip_logging_invite_success);

    if(cfg_size(cfg, opt_name_auth_skip_logging_invite_challenge))
        skip_logging_invite_challenge = cfg_getbool(cfg, opt_name_auth_skip_logging_invite_challenge);

    if(cfg_size(cfg, opt_name_auth_jwt_public_key)) {
        std::string_view key_path{cfg_getstr(cfg, opt_name_auth_jwt_public_key)};
        try {
            jwt_public_key = Botan::X509::load_key(key_path);
        } catch(Botan::Exception &e) {
            ERROR("failed to load pubkey from '%s': %s", key_path.data(), e.what());
            return 1;
        }
    }

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
        for(size_t i = 0; i < data.size(); i++)
            c.add(data[i]);
    }

    DBG("loaded credentials list. by_user:%zd, bt_gid:%zd, allowed_jwt_auth:%d",
        c.by_user.size(), c.by_gid.size(), c.allowed_jwt_auth.size());

    credentials.swap(c);
}

std::optional<Auth::auth_id_type> Auth::check_jwt_auth(const string &auth_hdr)
{
    //sems-jwt-tool encode --key test.key.pem --raw --claim=id:1/i --claim=iat:$(date +%s)/i

    auto scheme_pos = auth_hdr.find_first_not_of(' ');
    if(((auth_hdr.size() - scheme_pos) <= 6) ||
        0!=strncasecmp(&auth_hdr[scheme_pos], "Bearer", 6))
    {
        return std::nullopt;
    }

    if(!jwt_public_key) {
        DBG("got Bearer auth hdr and no 'auth.jwt_public_key'. return verify error");
        return -JWT_VERIFY_ERROR;
    }

    //JWT authorization
    auto jwt_value = std::string_view(auth_hdr).substr(scheme_pos + 7);

    AmIdentity jwt;
    if(!jwt.parse(jwt_value, true)) {
        DBG("failed to parse JWT: %s", jwt_value.data());
        return -JWT_PARSE_ERROR;
    }

    //verify signature
    if(!jwt.verify(jwt_public_key.get())) {
        DBG("JWT verification failed");
        return -JWT_VERIFY_ERROR;
    }

    //check 'exp' claim
    auto &jwt_data = jwt.get_payload();
    DBG("jwt payload: %s", jwt_data.print().data());

    if(jwt_data.hasMember("exp")) {
        auto &exp_arg = jwt_data["exp"];

        if(!exp_arg.isNumber())
            return -JWT_DATA_ERROR;

        auto exp = exp_arg.asNumber<time_t>();
        if(time(0) > exp) {
            DBG("JWT is expired. exp:%li", exp);
            return -JWT_EXPIRED_ERROR;
        }
    }

    //process 'gid', 'id' claims
    auth_id_type id;
    AmLock l(credentials_mutex);

    if(jwt_data.hasMember("gid")) {
        AmArg &gid = jwt_data["gid"];
        if(!isArgCStr(gid))
            return -JWT_DATA_ERROR;

        auto it = credentials.by_gid.find(gid.asCStr());
        if(it == credentials.by_gid.end()) {
            DBG("no matches for JWT gid: %s", gid.asCStr());
            return -JWT_AUTH_ERROR;
        }
        id = it->second;
        DBG("JWT gid resolved: %s -> %d", gid.asCStr(), id);
    } else if(jwt_data.hasMember("id")) {
        auto &id_arg = jwt_data["id"];
        if(!id_arg.isNumber())
            return -JWT_DATA_ERROR;
        id = id_arg.asNumber<auth_id_type>();
        DBG("JWT id: %d", id);
        if(!credentials.allowed_jwt_auth.contains(id)) {
            DBG("JWT auth is not allowed for: %d", id);
            return -JWT_AUTH_ERROR;
        }
    } else {
        return -JWT_DATA_ERROR;
    }

    return id;
}

Auth::auth_id_type Auth::check_request_auth(const AmSipRequest &req,  AmArg &ret)
{
    string auth_hdr =  getHeader(req.hdrs, SIP_HDR_AUTHORIZATION);
    if(auth_hdr.empty()) {
        //no auth header. just continue
        return NO_AUTH;
    }

    if(auto auth_id = check_jwt_auth(auth_hdr); auth_id) {
        static AmArg jwt_auth_succ_ret{
           AmArg(200),
           AmArg("OK"),
           AmArg(""),
           AmArg("JWT Auth")
        };
        ret = jwt_auth_succ_ret;
        return auth_id.value();
    }

    string username = find_attribute("username", auth_hdr);
    if(username.empty()) {
        DBG("no username attribute in " SIP_HDR_AUTHORIZATION " header");
        ret = "no username in Authorization header";
        return -NO_USERNAME;
    }

#if AUTH_MOCKING_ENABLED
    int user_to_auth_id;
    if(!str2int(username, user_to_auth_id))
        return -NO_CREDENTIALS;

    ret.push(200);
    ret.push("OK");
    ret.push("");
    ret.push("Response matched");
    ret.push(0);

    return user_to_auth_id;
#endif

    credentials_mutex.lock();

    auto range = credentials.by_user.equal_range(username);
    if(range.first == credentials.by_user.end()) {
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
    ret.assertStruct();

    AmLock l(credentials_mutex);

    auto &by_user_arg = ret["users"];
    by_user_arg.assertArray();
    for(const auto &[user, c]: credentials.by_user) {
        by_user_arg.push({
            { "id", c.id },
            { "user", user },
            { "pwd", c.password }
        });
    }

    auto &by_gid_arg = ret["jwt_gid"];
    by_gid_arg.assertStruct();
    for(const auto &[gid, id]: credentials.by_gid) {
        by_gid_arg[gid] = id;
    }

    auto &allow_jwt_auth_arg = ret["allow_jwt_auth"];
    allow_jwt_auth_arg.assertArray();
    for(auto id: credentials.allowed_jwt_auth)
        allow_jwt_auth_arg.push(id);
}

void Auth::auth_info_by_user(const string &username, AmArg &ret)
{
    ret.assertArray();

    credentials_mutex.lock();

    auto range = credentials.by_user.equal_range(username);
    if(range.first == credentials.by_user.end()) {
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
    ret.assertStruct();

    AmLock l(credentials_mutex);

    auto &by_user_arg = ret["users"];
    by_user_arg.assertArray();
    for(const auto &[user, c]: credentials.by_user) {
        if(c.id!=id) continue;
        by_user_arg.push({
            { "id", c.id },
            { "user", user },
            { "pwd", c.password }
        });
    }


    auto &by_gid_arg = ret["jwt_gid"];
    by_gid_arg.assertStruct();
    for(const auto &[gid, auth_id]: credentials.by_gid) {
        if(id!=auth_id) continue;
        by_gid_arg[gid] = id;
    }

    auto &allow_jwt_auth_arg = ret["allow_jwt_auth"];
    allow_jwt_auth_arg.assertArray();
    if(credentials.allowed_jwt_auth.contains(id))
        allow_jwt_auth_arg.push(id);
}

