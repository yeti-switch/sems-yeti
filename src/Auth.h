#pragma once

#include "AmSipMsg.h"
#include "AmConfigReader.h"
#include "AmThread.h"

#include <unordered_map>
#include <optional>

#include <confuse.h>
#include <botan/pubkey.h>

class Auth {
  public:
    enum error_type {
        NO_AUTH =        0,
        //UAC_AUTH_ERROR was here with value 1
        NO_USERNAME =    2,
        NO_CREDENTIALS = 3,
        NO_IP_AUTH =     4,  //rejected by OriginationPreAuth:onInvite()

        JWT_PARSE_ERROR =   5,
        JWT_VERIFY_ERROR =  6,
        JWT_EXPIRED_ERROR = 7,
        JWT_DATA_ERROR = 8,
        JWT_AUTH_ERROR = 9,

        UAC_AUTH_ERROR = 10
    };

    using auth_id_type = int;

  private:
    AmDynInvoke *uac_auth;
    std::string realm;
    bool skip_logging_invite_challenge;
    bool skip_logging_invite_success;
    std::unique_ptr<Botan::Public_Key> jwt_public_key;
\
    struct cred {
        auth_id_type id;
        std::string username;
        std::string password;
        cred(int id, std::string username, std::string password)
          : id(id), username(username), password(password)
        {}
    };

    struct CredentialsContainer
    {
        std::unordered_multimap<std::string, struct cred> by_user;
        std::unordered_map<std::string, auth_id_type> by_gid;
        std::set<auth_id_type> allowed_jwt_auth;

        void add(const AmArg &data);
        void swap(CredentialsContainer &rhs);
    } credentials;
    AmMutex credentials_mutex;

    std::optional<auth_id_type> check_jwt_auth(const string &auth_hdr);

  protected:

    int auth_configure(cfg_t* cfg);
    int auth_init();

    void send_auth_challenge(const AmSipRequest &req, const string &hdrs);
  public:
    Auth();
    void auth_info(AmArg &ret);
    void auth_info_by_user(const string &username, AmArg &ret);
    void auth_info_by_id(auth_id_type id, AmArg &ret);

    void reload_credentials(const AmArg &data);

    /**
    * @brief check_request_auth
    * checks auth if Authorization header is present
    * @param req INVITE request
    * @return >0 (auth_id) if succ authenticiated,
    *         =0 to continue (no Authorization header)
    *         <0 on error
    */
    auth_id_type check_request_auth(const AmSipRequest &req, AmArg &ret);

    bool is_skip_logging_invite_challenge() { return skip_logging_invite_challenge; }
    bool is_skip_logging_invite_success() { return skip_logging_invite_success; }
};

