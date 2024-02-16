#pragma once

#include "yeti_rpc.h"
#include "yeti_base.h"
#include "yeti_radius.h"
#include "HttpSequencer.h"
#include "CertCache.h"
#include "DbConfigStates.h"

#include <AmEventFdQueue.h>
#include "ampi/SipRegistrarApi.h"

extern string yeti_auth_feedback_header;

class Yeti
  : public YetiRpc,
    public AmThread,
    public AmEventFdQueue,
    public AmEventHandler,
    virtual public YetiBase,
    virtual public YetiRadius,
    AmObject
{
    static Yeti* _instance;
    bool stopped;
    int epoll_fd;
    AmTimerFd each_second_timer;
    AmTimerFd db_cfg_reload_timer;
    bool is_registrar_availbale;

    struct cfg_timer_mapping_entry {
        std::function<void (const string &key)> on_reload;
        std::function<void (const PGResponse &e)> on_db_response;
        AtomicCounter *exceptions_counter;
        cfg_timer_mapping_entry(
            std::function<void (const string &key)> on_reload,
            std::function<void (const PGResponse &e)> on_db_response)
          : on_reload(on_reload),
            on_db_response(on_db_response)
        {}

        void init_exceptions_counter(const string &key);
    };
    map<string, cfg_timer_mapping_entry> db_config_timer_mappings;

    void initCfgTimerMappings();
    void onDbCfgReloadTimer() noexcept;
    void onDbCfgReloadTimerResponse(const PGResponse &e) noexcept;

  public:

    struct Counters {
        AtomicCounter &identity_success;
        AtomicCounter &identity_failed_parse;
        AtomicCounter &identity_failed_verify_expired;
        AtomicCounter &identity_failed_verify_signature;
        AtomicCounter &identity_failed_x5u_not_trusted;
        AtomicCounter &identity_failed_cert_invalid;
        AtomicCounter &identity_failed_cert_not_available;
        Counters();
    } counters;

    Yeti();
    ~Yeti();

    static Yeti* create_instance();
    static Yeti& instance();

    int onLoad();
    int configure(const std::string& config);

    void run();
    void on_stop();
    void process(AmEvent *ev);
    bool getCoreOptionsHandling() { return config.core_options_handling; }
    bool isAllComponentsInited();
    bool isRegistrarAvailable() { return is_registrar_availbale; };
};
