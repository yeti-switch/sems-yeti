#pragma once

#include "AmSipMsg.h"
#include "AmConfigReader.h"
#include "AmThread.h"

#include <pqxx/pqxx>
#include <unordered_map>
#include <confuse.h>

class Auth {
  public:
    enum error_type {
        NO_AUTH =        0,
        //UAC_AUTH_ERROR was here with value 1
        NO_USERNAME =    2,
        NO_CREDENTIALS = 3,
        NO_IP_AUTH =     4,  //rejected by OriginationPreAuth:onInvite()
        UAC_AUTH_ERROR = 10
    };

    using auth_id_type = int;

  private:
    AmDynInvoke *uac_auth;
    std::string realm;
    bool skip_logging_invite_challenge;
    bool skip_logging_invite_success;

    struct cred {
        auth_id_type id;
        std::string username;
        std::string password;
        cred(int id, std::string username, std::string password)
          : id(id), username(username), password(password)
        {}
    };

    struct CredentialsContainer
      : public std::unordered_multimap<std::string, struct cred>
    {
        void add(auth_id_type id, const std::string &username, const std::string &password);
    } credentials;
    AmMutex credentials_mutex;

  protected:

    int auth_configure(cfg_t* cfg);
    int auth_init(AmConfigReader& cfg, pqxx::nontransaction &t);

    /**
     * @brief reload_credentials
     * load credentials hash from database
     * @param t transaction
     * @return 0 on success
     */
    int reload_credentials(pqxx::nontransaction &t, size_t &credentials_count);
    void send_auth_challenge(const AmSipRequest &req, const string &hdrs);
  public:
    Auth();
    void auth_info(AmArg &ret);
    void auth_info_by_user(const string &username, AmArg &ret);
    void auth_info_by_id(auth_id_type id, AmArg &ret);


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

