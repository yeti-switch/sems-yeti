#pragma once

#include "yeti_rpc.h"
#include "yeti_base.h"
#include "yeti_radius.h"
#include "HttpSequencer.h"
#include "SigningKeysCache.h"
#include "DbConfigStates.h"

#include <AmEventFdQueue.h>
#include "ampi/SipRegistrarApi.h"

extern string yeti_auth_feedback_header;

class Yeti : public YetiRpc,
             public AmThread,
             public AmEventFdQueue,
             public AmEventHandler,
             virtual public YetiBase,
             virtual public YetiRadius,
             AmObject {
    static Yeti *_instance;
    bool         stopped;
    int          epoll_fd;
    AmTimerFd    db_cfg_reload_timer;
    bool         is_registrar_availbale;
    bool         is_identity_validator_availbale;

    struct cfg_timer_mapping_entry {
        std::function<void(const string &key)>   on_reload;
        std::function<void(const PGResponse &e)> on_db_response;
        AtomicCounter                           *exceptions_counter;
        cfg_timer_mapping_entry(std::function<void(const string &key)>   on_reload,
                                std::function<void(const PGResponse &e)> on_db_response)
            : on_reload(on_reload)
            , on_db_response(on_db_response)
        {
        }

        void init_exceptions_counter(const string &key);
    };

    struct db_req_entry {
        std::function<void(const PGResponse &e)>      on_db_response;
        std::function<void(const PGResponseError &e)> on_db_error;
        std::function<void(const PGTimeout &e)>       on_db_timeout;
        db_req_entry(std::function<void(const PGResponse &e)>      on_db_response,
                     std::function<void(const PGResponseError &e)> on_db_error,
                     std::function<void(const PGTimeout &e)>       on_db_timeout)
            : on_db_response(on_db_response)
            , on_db_error(on_db_error)
            , on_db_timeout(on_db_timeout)
        {
        }
    };
    map<string, cfg_timer_mapping_entry> db_config_timer_mappings;
    map<string, db_req_entry>            db_requests;

    void initCfgTimerMappings();
    void checkStates() noexcept;
    void showStates(const JsonRpcRequestEvent &e);

    bool verifyHttpDestinations();

  public:
    Yeti();
    ~Yeti();

    static Yeti *create_instance();
    static Yeti &instance();

    int onLoad();
    int configure(const std::string &config);

    void run();
    void on_stop();
    void process(AmEvent *ev);
    bool getCoreOptionsHandling() { return config.core_options_handling; }
    bool isAllComponentsInited();
    bool isRegistrarAvailable() { return is_registrar_availbale; }
    bool isIdentityValidatorAvailbale() { return is_identity_validator_availbale; }
};
