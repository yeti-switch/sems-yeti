#pragma once

#include "SBCCallLeg.h"
#include "cdr/Cdr.h"
#include "yeti.h"

static inline void radius_auth(SBCCallLeg *call, const Cdr &cdr, SBCCallProfile &call_profile, const AmSipRequest &req)
{
    PlaceholdersHash &v         = call->getPlaceholders();
    const string     &local_tag = call->getLocalTag();

    v["call_local_tag"]    = local_tag;
    v["call_orig_call_id"] = req.callid;

    v["call_time_start"] = timeval2str_ntp(cdr.start_time);

    v["time_start"]       = timeval2str(cdr.start_time);
    v["time_start_float"] = timeval2str_usec(cdr.start_time);
    v["time_start_int"]   = long2str(cdr.start_time.tv_sec);

    v["aleg_remote_ip"]   = cdr.legA_remote_ip;
    v["aleg_remote_port"] = int2str(cdr.legA_remote_port);

    v["aleg_local_ip"]   = cdr.legA_local_ip;
    v["aleg_local_port"] = int2str(cdr.legA_local_port);
}

static inline bool radius_auth_post_event(SBCCallLeg *call, SBCCallProfile &call_profile)
{
    PlaceholdersHash &v         = call->getPlaceholders();
    const string     &local_tag = call->getLocalTag();

    if (call_profile.radius_profile_id) {
        DBG("post auth event to the radius module with profile id: %d", call_profile.radius_profile_id);

        AmSessionContainer::instance()->postEvent(RADIUS_EVENT_QUEUE,
                                                  new RadiusRequestEvent(call_profile.radius_profile_id, local_tag, v));
        return true;
    }
    return false;
}

static inline void radius_accounting_start(SBCCallLeg *call, const Cdr &cdr, SBCCallProfile &call_profile)
{
    PlaceholdersHash &v = call->getPlaceholders();

    if (call->isALeg()) {
        v["time_connect"]       = timeval2str(cdr.connect_time);
        v["time_connect_float"] = timeval2str_usec(cdr.connect_time);
        v["time_connect_int"]   = long2str(cdr.connect_time.tv_sec);
    } else { // bleg
        v["time_connect"]       = timeval2str(cdr.bleg_connect_time);
        v["time_connect_float"] = timeval2str_usec(cdr.bleg_connect_time);
        v["time_connect_int"]   = long2str(cdr.bleg_connect_time.tv_sec);

        v["bleg_remote_ip"]   = cdr.legB_remote_ip;
        v["bleg_remote_port"] = int2str(cdr.legB_remote_port);
        v["bleg_local_ip"]    = cdr.legB_local_ip;
        v["bleg_local_port"]  = int2str(cdr.legB_local_port);
    }
}

static inline void radius_accounting_start_post_event_set_timers(SBCCallLeg *call, SBCCallProfile &call_profile)
{
    PlaceholdersHash &v = call->getPlaceholders();

    if (call->isALeg()) {
        if (call_profile.aleg_radius_acc_rules.enable_start_accounting) {
            DBG("[%s] post acc_start event to the radius module with profile id: %d", call->getLocalTag().c_str(),
                call_profile.aleg_radius_acc_profile_id);

            AmSessionContainer::instance()->postEvent(RADIUS_EVENT_QUEUE,
                                                      new RadiusRequestEvent(RadiusRequestEvent::Start,
                                                                             call_profile.aleg_radius_acc_profile_id,
                                                                             call->getLocalTag(), v));
        }
        if (call_profile.aleg_radius_acc_rules.enable_interim_accounting &&
            call_profile.aleg_radius_acc_rules.interim_accounting_interval)
        {
            call->setTimer(YETI_RADIUS_INTERIM_TIMER, call_profile.aleg_radius_acc_rules.interim_accounting_interval);
        }
    } else { // bleg
        if (call_profile.bleg_radius_acc_rules.enable_start_accounting) {
            DBG("[%s] post acc_start event to the radius module with profile id: %d", call->getLocalTag().c_str(),
                call_profile.bleg_radius_acc_profile_id);

            AmSessionContainer::instance()->postEvent(RADIUS_EVENT_QUEUE,
                                                      new RadiusRequestEvent(RadiusRequestEvent::Start,
                                                                             call_profile.bleg_radius_acc_profile_id,
                                                                             call->getLocalTag(), v));
        }
        if (call_profile.bleg_radius_acc_rules.enable_interim_accounting &&
            call_profile.bleg_radius_acc_rules.interim_accounting_interval)
        {
            call->setTimer(YETI_RADIUS_INTERIM_TIMER, call_profile.bleg_radius_acc_rules.interim_accounting_interval);
        }
    }
}


static inline void radius_accounting_interim(SBCCallLeg *call, const Cdr &cdr)
{
    const struct timeval *leg_connect_time;
    timeval               duration, now;

    // SBCCallProfile &call_profile = call->getCallProfile();
    PlaceholdersHash &v = call->getPlaceholders();

    if (call->isALeg()) {
        leg_connect_time = &cdr.connect_time;
    } else {
        leg_connect_time = &cdr.bleg_connect_time;
    }

    if (timerisset(leg_connect_time)) {
        gettimeofday(&now, NULL);
        timersub(&now, leg_connect_time, &duration);
        v["call_duration_float"] = timeval2str_usec(duration);
        v["call_duration_int"]   = long2str(duration.tv_sec);
    } else {
        v["call_duration_float"] = "0.0";
        v["call_duration_int"]   = "0";
    }
}

static inline void radius_accounting_interim_post_event_set_timer(SBCCallLeg *call)
{
    int               profile_id, interval;
    SBCCallProfile   &call_profile = call->getCallProfile();
    PlaceholdersHash &v            = call->getPlaceholders();

    if (call->isALeg()) {
        profile_id = call_profile.aleg_radius_acc_profile_id;
        interval   = call_profile.aleg_radius_acc_rules.interim_accounting_interval;
    } else {
        profile_id = call_profile.bleg_radius_acc_profile_id;
        interval   = call_profile.bleg_radius_acc_rules.interim_accounting_interval;
    }

    DBG("[%s] post acc_interim event to the radius module with profile id: %d", call->getLocalTag().c_str(),
        profile_id);

    AmSessionContainer::instance()->postEvent(
        RADIUS_EVENT_QUEUE, new RadiusRequestEvent(RadiusRequestEvent::Interim, profile_id, call->getLocalTag(), v));

    call->setTimer(YETI_RADIUS_INTERIM_TIMER, interval);
}

static inline void radius_accounting_stop(SBCCallLeg *call, const Cdr &cdr)
{
    // int profile_id;
    const struct timeval *leg_connect_time;
    timeval               duration, now;

    gettimeofday(&now, NULL);

    SBCCallProfile   &call_profile = call->getCallProfile();
    PlaceholdersHash &v            = call->getPlaceholders();

    if (call->isALeg()) {

        if (!call_profile.aleg_radius_acc_rules.enable_stop_accounting)
            return;

        leg_connect_time = &cdr.connect_time;

        v["leg_disconnect_code"]   = int2str(cdr.disconnect_rewrited_code);
        v["leg_disconnect_reason"] = cdr.disconnect_rewrited_reason;

    } else {

        if (!call_profile.bleg_radius_acc_rules.enable_stop_accounting)
            return;

        leg_connect_time = &cdr.bleg_connect_time;

        v["leg_disconnect_code"]   = int2str(cdr.disconnect_code);
        v["leg_disconnect_reason"] = cdr.disconnect_reason;
    }

    if (timerisset(leg_connect_time)) {
        timersub(&now, leg_connect_time, &duration);
        v["call_duration_float"] = timeval2str_usec(duration);
        v["call_duration_int"]   = long2str(duration.tv_sec);
    } else {
        v["call_duration_float"] = "0.0";
        v["call_duration_int"]   = "0";
        v["time_connect"]        = "";
        v["time_connect_float"]  = "0.0";
        v["time_connect_int"]    = "0";
    }

    v["time_end"]       = timeval2str(now);
    v["time_end_float"] = timeval2str_usec(now);
    v["time_end_int"]   = long2str(now.tv_sec);
}

static inline void radius_accounting_stop_post_event(SBCCallLeg *call)
{
    int               profile_id;
    PlaceholdersHash &v            = call->getPlaceholders();
    SBCCallProfile   &call_profile = call->getCallProfile();

    if (call->isALeg()) {
        if (!call_profile.aleg_radius_acc_rules.enable_stop_accounting)
            return;
        profile_id = call_profile.aleg_radius_acc_profile_id;
    } else {
        if (!call_profile.bleg_radius_acc_rules.enable_stop_accounting)
            return;
        profile_id = call_profile.bleg_radius_acc_profile_id;
    }

    DBG("[%s] post acc_stop event to the radius module with profile id: %d", call->getLocalTag().c_str(), profile_id);

    AmSessionContainer::instance()->postEvent(
        RADIUS_EVENT_QUEUE, new RadiusRequestEvent(RadiusRequestEvent::End, profile_id, call->getLocalTag(), v));
}
