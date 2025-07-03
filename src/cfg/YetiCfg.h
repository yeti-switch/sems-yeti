#pragma once

#include "../cdr/CdrHeaders.h"
#include "confuse.h"
#include "AmConfigReader.h"
#include "../db/DbConfig.h"
#include <chrono>
#include "ampi/PostgreSqlAPI.h"

struct YetiCfg {
    int pop_id;
    bool use_radius;
    bool early_100_trying;

    string routing_schema;
    DbConfig routing_db_master;

    std::chrono::seconds db_refresh_interval;

    string msg_logger_dir;
    string audio_recorder_dir;
    string audio_recorder_http_destination;
    bool audio_recorder_compress;
    string log_dir;
    bool pcap_memory_logger;
    bool auth_feedback;
    bool ip_auth_reject_if_no_matched;
    string ip_auth_hdr;
    string http_events_destination;
    vector<string> supported_tags;
    vector<string> allowed_methods;
    int max_forwards_decrement;

    cdr_headers_t aleg_cdr_headers;
    cdr_headers_t bleg_cdr_headers;
    cdr_headers_t bleg_reply_cdr_headers;

    bool core_options_handling;
    bool postgresql_debug;
    bool write_internal_disconnect_code;

    int identity_enabled;

    struct headers_processing_config {
        struct leg_reasons {
            bool add_sip_reason;
            bool add_q850_reason;
            leg_reasons()
              : add_sip_reason(false),
                add_q850_reason(false)
            {}
            bool enabled() { return add_sip_reason || add_q850_reason; }
            void configure(cfg_t *cfg);
        } aleg, bleg;
        void configure(cfg_t *cfg);
    } headers_processing;

    int configure(cfg_t *cfg, AmConfigReader &am_cfg);

private:
    void serialize_to_amconfig(cfg_t *y, AmConfigReader &out);
};
