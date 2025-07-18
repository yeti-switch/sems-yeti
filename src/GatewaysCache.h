#pragma once

#include "AmArg.h"
#include "AmThread.h"
#include "AmSipMsg.h"

#include "GatewayStats.h"

#include <unordered_map>
#include <set>
#include <random>
#include <optional>

class GatewaysCache
{
  public:
    struct TelRedirectData {
        string transfer_tel_uri_host;
        list<string> transfer_append_headers_req;
    };

  private:
    using GatewayIdType = int;
    struct GatewayData {
        GatewayIdType id;

        //throttling
        bool throttling_enabled;
        int throttling_minimum_calls;
        int throttling_window;
        double throttling_threshold_start;
        double throttling_threshold_end;
        double failure_rate_multiplier;
        std::set<int> throttling_local_codes;
        std::set<int> throttling_remote_codes;

        //tel: refer
        TelRedirectData tel_redirect_data;

        GatewayStats stats;

        GatewayData(GatewayIdType gateway_id, const AmArg &r);
        operator AmArg() const;

        double getFailureRate() const;
        double getSkipRate(double failure_rate) const;
    };
    using GatewaysContainer = std::unordered_map<GatewayIdType, GatewayData>;

    AmMutex mutex;
    GatewaysContainer gateways;

    std::mt19937 random_generator;
    std::uniform_int_distribution<> random_distribution{0, 99};

  public:
    GatewaysCache();

    int configure();
    void update(const AmArg &data);
    void info(const AmArg &arg, AmArg& ret);

    void update_reply_stats(GatewayIdType gateway_id, const AmSipReply &reply);
    bool should_skip(GatewayIdType gateway_id, int now);

    std::optional<TelRedirectData> get_redirect_data(GatewayIdType gateway_id);
};
