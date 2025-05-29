#include "GatewayStats.h"

void GatewayStats::cleanup_obsolete_time_slots(int now)
{
    auto window_start = now - window_size;
    for(auto it = time_slots.begin();
        it != time_slots.end() && it->first < window_start;)
    {
        global.failed_replies -= it->second.failed_replies;
        global.success_replies -= it->second.success_replies;
        it = time_slots.erase(it);
    }
}

void GatewayStats::add_failed_reply(int now)
{
    auto it = time_slots.find(now);
    if(it == time_slots.end()) {
        time_slots.try_emplace(now, 1, 0);
    } else {
        it->second.failed_replies += 1;
    }
    global.failed_replies += 1;
    cleanup_obsolete_time_slots(now);
}

void GatewayStats::add_success_reply(int now)
{
    auto it = time_slots.find(now);
    if(it == time_slots.end()) {
        time_slots.try_emplace(now, 0, 1);
    } else {
        it->second.success_replies += 1;
    }
    global.success_replies += 1;
    cleanup_obsolete_time_slots(now);
}
