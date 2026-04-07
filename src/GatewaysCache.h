#pragma once

#include "AmArg.h"
#include "AmThread.h"
#include "AmSipMsg.h"
#include "AmSipDialog.h"
#include "GatewayStats.h"

#include <unordered_map>
#include <set>
#include <random>
#include <optional>

struct GatewaysCacheDataBase {
    using GatewayIdType = int;

    struct SipSettings {
        vector<string> allowed_methods;
        vector<string> supported_tags;
    };

    struct MediaSettings {
        enum MediaModeId {
            MEDIA_MODE_DISABLED = 0,        // ignore/reject in incoming Offer, do not announce in outgoing Offer
            MEDIA_MODE_ENABLE_WHEN_OFFERED, // accept in incoming Offer, do not announce in outgoing Offer
            MEDIA_MODE_ENABLED              // accept in incoming Offer, announce in outgoing Offer
        };

        MediaModeId ice_mode_id;
        MediaModeId rtcp_mux_mode_id;
        MediaModeId rtcp_feedback_mode_id;

        MediaSettings()
            : ice_mode_id(MEDIA_MODE_ENABLE_WHEN_OFFERED)
            , rtcp_mux_mode_id(MEDIA_MODE_ENABLE_WHEN_OFFERED)
            , rtcp_feedback_mode_id(MEDIA_MODE_ENABLE_WHEN_OFFERED)
        {
        }

        static const char *mode2str(MediaModeId mode_id)
        {
            switch (mode_id) {
            case MEDIA_MODE_DISABLED:            return "disabled";
            case MEDIA_MODE_ENABLE_WHEN_OFFERED: return "enable_when_offered";
            case MEDIA_MODE_ENABLED:             return "enabled";
            }
        }
    };

    GatewayIdType id;

    SipSettings   sip_settings;
    MediaSettings media_settings;

    GatewaysCacheDataBase(GatewayIdType gateway_id, const AmArg &r);
    void    serialize_base(AmArg &ret) const;
    virtual operator AmArg() const = 0;
};

template <typename GatewayDataType> class GatewaysCacheBase {
  protected:
    using GatewaysContainer = std::unordered_map<GatewaysCacheDataBase::GatewayIdType, GatewayDataType>;
    GatewaysContainer gateways;
    AmMutex           mutex;

    virtual void merge(GatewayDataType &dst, const GatewayDataType &src) = 0;

  public:
    void update(const AmArg &data)
    {
        if (!isArgArray(data))
            return;

        GatewaysContainer tmp;
        for (size_t i = 0; i < data.size(); ++i) {
            auto                                &row        = data[i];
            GatewaysCacheDataBase::GatewayIdType gateway_id = row["id"].asLongLong();
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
            if (auto it = gateways.find(old_gw.first); it != gateways.end()) {
                merge(it->second, old_gw.second);
            }
        }
    }

    void info(const AmArg &arg, AmArg &ret)
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

    std::optional<GatewaysCacheDataBase::SipSettings> get_sip_settings(GatewaysCacheDataBase::GatewayIdType gateway_id)
    {
        AmLock lock(mutex);

        auto gw_it = gateways.find(gateway_id);
        if (gw_it == gateways.end())
            return std::nullopt;

        return gw_it->second.sip_settings;
    }

    // return [ice_enabled, rtcp_mux_enabled, rtcp_feedback_enabled]
    std::tuple<bool, bool, bool> get_media_settings_enabled(GatewaysCacheDataBase::GatewayIdType gateway_id)
    {
        AmLock lock(mutex);

        auto gw_it = gateways.find(gateway_id);
        if (gw_it == gateways.end())
            return { false, false, false };

        const auto &m = gw_it->second.media_settings;
        return { m.ice_mode_id == GatewaysCacheDataBase::MediaSettings::MEDIA_MODE_ENABLED,
                 m.rtcp_mux_mode_id == GatewaysCacheDataBase::MediaSettings::MEDIA_MODE_ENABLED,
                 m.rtcp_feedback_mode_id == GatewaysCacheDataBase::MediaSettings::MEDIA_MODE_ENABLED };
    }

    // return [ice_allowed, rtcp_mux_allowed, rtcp_feedback_allowed]
    std::tuple<bool, bool, bool> get_media_settings_allowed(GatewaysCacheDataBase::GatewayIdType gateway_id)
    {
        AmLock lock(mutex);

        auto gw_it = gateways.find(gateway_id);
        if (gw_it == gateways.end())
            return { true, true, true };

        const auto &m = gw_it->second.media_settings;
        return { m.ice_mode_id != GatewaysCacheDataBase::MediaSettings::MEDIA_MODE_DISABLED,
                 m.rtcp_mux_mode_id != GatewaysCacheDataBase::MediaSettings::MEDIA_MODE_DISABLED,
                 m.rtcp_feedback_mode_id != GatewaysCacheDataBase::MediaSettings::MEDIA_MODE_DISABLED };
    }
};

struct GatewayDataAleg : public GatewaysCacheDataBase {
  public:
    GatewayDataAleg(GatewayIdType gateway_id, const AmArg &r)
        : GatewaysCacheDataBase(gateway_id, r)
    {
    }

    operator AmArg() const final
    {
        AmArg ret;
        serialize_base(ret);
        return ret;
    }
};

struct GatewayDataBleg : public GatewaysCacheDataBase {
    // tel: refer
    struct TelRedirectData {
        string       transfer_tel_uri_host;
        list<string> transfer_append_headers_req;
    } tel_redirect_data;

    // throttling
    bool          throttling_enabled;
    int           throttling_minimum_calls;
    int           throttling_window;
    double        throttling_threshold_start;
    double        throttling_threshold_end;
    double        failure_rate_multiplier;
    std::set<int> throttling_local_codes;
    std::set<int> throttling_remote_codes;

    GatewayStats stats;

    GatewayDataBleg(GatewayIdType gateway_id, const AmArg &r);
    operator AmArg() const final;

    double getFailureRate() const;
    double getSkipRate(double failure_rate) const;
};

class GatewaysCacheALeg : public GatewaysCacheBase<GatewayDataAleg> {
    // no any Aleg specific things yet
  protected:
    void merge(GatewayDataAleg &, const GatewayDataAleg &) final {};

  public:
    GatewaysCacheALeg()
        : GatewaysCacheBase()
    {
    }
};

class GatewaysCacheBLeg : public GatewaysCacheBase<GatewayDataBleg> {
  private:
    std::mt19937                    random_generator;
    std::uniform_int_distribution<> random_distribution{ 0, 99 };

  protected:
    void merge(GatewayDataBleg &dst, const GatewayDataBleg &src) final
    {
        if (dst.throttling_enabled && src.throttling_enabled) {
            dst.stats = src.stats;
            dst.stats.set_window_size(src.throttling_window);
        }
    };

  public:
    GatewaysCacheBLeg();

    std::optional<GatewayDataBleg::TelRedirectData> get_redirect_data(GatewayDataBleg::GatewayIdType gateway_id);

    void update_reply_stats(GatewayDataBleg::GatewayIdType gateway_id, const AmSipReply &reply);
    bool should_skip(GatewayDataBleg::GatewayIdType gateway_id, int now);
};
