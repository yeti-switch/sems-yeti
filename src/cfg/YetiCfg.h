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
    bool audio_recorder_compress;
    string log_dir;
    bool pcap_memory_logger;
    bool auth_feedback;
    bool ip_auth_reject_if_no_matched;
    string ip_auth_hdr;
    string http_events_destination;

    bool registrar_enabled;
    string registrar_redis_host;
    int registrar_redis_port;
    int registrar_keepalive_interval;
    int registrar_expires_min;
    int registrar_expires_max;
    int registrar_expires_default;

    cdr_headers_t aleg_cdr_headers;
    cdr_headers_t bleg_reply_cdr_headers;

    bool core_options_handling;
    bool postgresql_debug;

    int identity_enabled;

    int configure(cfg_t *cfg, AmConfigReader &am_cfg);

private:
    void serialize_to_amconfig(cfg_t *y, AmConfigReader &out);
};
