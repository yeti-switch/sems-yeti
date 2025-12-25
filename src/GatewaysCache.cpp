#include "GatewaysCache.h"
#include "log.h"
#include "AmUtils.h"

#define SKIP_RATE_MIN 20.0
#define SKIP_RATE_MAX 100.0

GatewaysCache::GatewayData::GatewayData(GatewayIdType gateway_id, const AmArg &r)
    : id(gateway_id)
    , throttling_enabled(false)
{
    // tel: refer
    const auto &transfer_tel_uri_host_arg = r["transfer_tel_uri_host"];
    if (!isArgUndef(transfer_tel_uri_host_arg))
        tel_redirect_data.transfer_tel_uri_host = transfer_tel_uri_host_arg.asCStr();

    const auto &transfer_append_headers_req_arg = r["transfer_append_headers_req"];
    if (isArgArray(transfer_append_headers_req_arg)) {
        for (auto i = 0u; i < transfer_append_headers_req_arg.size(); i++) {
            tel_redirect_data.transfer_append_headers_req.push_back(transfer_append_headers_req_arg.get(i).asCStr());
        }
    }

    // throttling
    auto &throttling_codes = r["throttling_codes"];
    if (!isArgArray(throttling_codes))
        return;
    for (size_t i = 0; i < throttling_codes.size(); ++i) {
        auto &code_arg = throttling_codes[i];
        assertArgCStr(code_arg);
        string code_str = code_arg.asCStr();
        int    code     = 0;
        if (code_str.starts_with("local")) {
            code_str.erase(0, 5);
            if (str2int(code_str, code))
                throttling_local_codes.emplace(code);
        } else {
            if (str2int(code_str, code))
                throttling_remote_codes.emplace(code);
        }
    }

    auto throttling_minimum_calls_arg = r["throttling_minimum_calls"];
    if (isArgUndef(throttling_minimum_calls_arg))
        return;
    throttling_minimum_calls = throttling_minimum_calls_arg.asNumber<int>();

    auto throttling_window_arg = r["throttling_window"];
    if (isArgUndef(throttling_window_arg))
        return;
    throttling_window = throttling_window_arg.asNumber<int>();

    auto throttling_threshold_start_arg = r["throttling_threshold_start"];
    if (!isArgDouble(throttling_threshold_start_arg))
        return;
    throttling_threshold_start = throttling_threshold_start_arg.asDouble();

    auto throttling_threshold_end_arg = r["throttling_threshold_end"];
    if (!isArgDouble(throttling_threshold_end_arg))
        return;
    throttling_threshold_end = throttling_threshold_end_arg.asDouble();

    if (throttling_threshold_start > throttling_threshold_end)
        return;

    failure_rate_multiplier = (SKIP_RATE_MAX - SKIP_RATE_MIN) / (throttling_threshold_end - throttling_threshold_start);

    stats.set_window_size(throttling_window);

    throttling_enabled = true;
}


GatewaysCache::GatewayData::operator AmArg() const
{
    AmArg a;

    // tel: refer/redirect

    auto &transfer                        = a["transfer"];
    transfer["tel_uri_host"]              = tel_redirect_data.transfer_tel_uri_host;
    auto &transfer_append_headers_req_arg = transfer["append_headers_req"];
    transfer_append_headers_req_arg.assertArray();
    for (const auto &hdr : tel_redirect_data.transfer_append_headers_req)
        transfer_append_headers_req_arg.push(hdr);

    auto &media                    = a["media"];
    media["ice_mode_id"]           = MediaSettings::mode2str(media_settings.ice_mode_id);
    media["rtcp_mux_mode_id"]      = MediaSettings::mode2str(media_settings.rtcp_mux_mode_id);
    media["rtcp_feedback_mode_id"] = MediaSettings::mode2str(media_settings.rtcp_feedback_mode_id);

    // throttling
    auto &throttling = a["throttling"];

    throttling["enabled"] = throttling_enabled;

    if (!throttling_enabled)
        return a;

    for (auto code : throttling_local_codes)
        throttling["local_codes"].push(code);

    for (auto code : throttling_remote_codes)
        throttling["remote_codes"].push(code);

    throttling["minimum_calls"]   = throttling_minimum_calls;
    throttling["window"]          = throttling_window;
    throttling["threshold_start"] = throttling_threshold_start;
    throttling["threshold_end"]   = throttling_threshold_end;
    throttling["rate_multiplier"] = failure_rate_multiplier;

    // stats
    AmArg &s = throttling["stats"];

    auto &slots           = stats.getTimeSlots();
    auto  it              = slots.begin();
    s["oldest_time_slot"] = (it != slots.end()) ? it->first : AmArg();

    s["failed_replies"]  = stats.global.failed_replies;
    s["success_replies"] = stats.global.success_replies;

    auto failure_rate = getFailureRate();
    s["failure_rate"] = failure_rate;
    s["skip_rate"]    = getSkipRate(failure_rate);

    s["checked_requests"]            = stats.checked_requests;
    s["throttled_requests"]          = stats.throttled_requests;
    s["throttled_requests_randomly"] = stats.throttled_requests_randomly;

    return a;
}

double GatewaysCache::GatewayData::getFailureRate() const
{
    const auto &s = stats.global;
    int         n = s.failed_replies + s.success_replies;
    if (n < throttling_minimum_calls)
        return 0;

    return static_cast<double>(s.failed_replies) * 100 / n;
}

double GatewaysCache::GatewayData::getSkipRate(double failure_rate) const
{
    if (failure_rate < throttling_threshold_start)
        return 0;

    if (failure_rate >= throttling_threshold_end)
        return SKIP_RATE_MAX;

    return SKIP_RATE_MIN + (failure_rate_multiplier * (failure_rate - throttling_threshold_start));
}

GatewaysCache::GatewaysCache()
{
    std::random_device rd;
    random_generator.seed(rd());
}

int GatewaysCache::configure()
{
    return 0;
}

void GatewaysCache::update(const AmArg &data)
{
    if (!isArgArray(data))
        return;

    GatewaysContainer tmp;
    for (size_t i = 0; i < data.size(); ++i) {
        auto         &row        = data[i];
        GatewayIdType gateway_id = row["id"].asLongLong();
        try {
            tmp.try_emplace(gateway_id, gateway_id, row);
        } catch (...) {
            ERROR("got exception on gateway emplacing: %s", row.print().data());
        }
    }

    AmLock lock(mutex);
    gateways.swap(tmp);

    /* copy runtime stats data for gateways with enabled throttling
     * TODO: move stats to another container */
    for (const auto &old_gw : tmp) {
        auto it = gateways.find(old_gw.first);
        if (it != gateways.end() && it->second.throttling_enabled && old_gw.second.throttling_enabled) {
            it->second.stats = old_gw.second.stats;
            it->second.stats.set_window_size(it->second.throttling_window);
        }
    }
}

void GatewaysCache::info(const AmArg &arg, AmArg &ret)
{
    auto &entries = ret["gateways"];
    entries.assertStruct();

    AmLock lock(mutex);

    if (0 == arg.size()) {
        for (const auto &[id, gw] : gateways)
            entries[long2str(id)] = gw;
    } else {
        auto gw = gateways.find(arg2int(arg[0]));
        if (gw != gateways.end())
            entries[long2str(gw->first)] = gw->second;
    }
}

void GatewaysCache::update_reply_stats(GatewayIdType gateway_id, const AmSipReply &reply)
{
    AmLock lock(mutex);

    auto gw_it = gateways.find(gateway_id);
    if (gw_it == gateways.end())
        return;

    auto &gw = gw_it->second;
    if (!gw.throttling_enabled)
        return;

    if (reply.local_reply) {
        if (gw.throttling_local_codes.contains(reply.code)) {
            gw.stats.add_failed_reply(reply.recv_timestamp.tv_sec);
            return;
        }
    } else if (gw.throttling_remote_codes.contains(reply.code)) {
        gw.stats.add_failed_reply(reply.recv_timestamp.tv_sec);
        return;
    }

    gw.stats.add_success_reply(reply.recv_timestamp.tv_sec);
}

bool GatewaysCache::should_skip(GatewayIdType gateway_id, int now)
{
    AmLock lock(mutex);

    auto gw_it = gateways.find(gateway_id);
    if (gw_it == gateways.end())
        return false;

    auto &gw = gw_it->second;
    if (!gw.throttling_enabled)
        return false;

    auto &s = gw.stats;

    s.checked_requests++;
    s.cleanup_obsolete_time_slots(now);

    auto skip_rate = gw.getSkipRate(gw.getFailureRate());

    if (skip_rate == 0)
        return false;

    if (skip_rate >= 100) {
        s.throttled_requests++;
        return true;
    }

    auto ret = (skip_rate > random_distribution(random_generator));

    if (ret)
        s.throttled_requests_randomly++;

    return ret;
}

std::optional<GatewaysCache::TelRedirectData> GatewaysCache::get_redirect_data(GatewayIdType gateway_id)
{
    AmLock lock(mutex);

    auto gw_it = gateways.find(gateway_id);
    if (gw_it == gateways.end())
        return std::nullopt;

    return gw_it->second.tel_redirect_data;
}

std::optional<GatewaysCache::MediaSettings> GatewaysCache::get_media_settings(GatewayIdType gateway_id)
{
    AmLock lock(mutex);

    auto gw_it = gateways.find(gateway_id);
    if (gw_it == gateways.end())
        return std::nullopt;

    return gw_it->second.media_settings;
}
