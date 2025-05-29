#pragma once

#include <map>

class GatewayStats {
    struct Stats {
        int failed_replies;
        int success_replies;
        Stats(int failed_replies, int success_replies)
          : failed_replies(failed_replies),
            success_replies(success_replies)
        {}
    };
    std::map<int, Stats> time_slots;
    int window_size;

  public:
    Stats global{0, 0};
    unsigned long throttled_requests{0};
    unsigned long throttled_requests_randomly{0};
    unsigned long checked_requests{0};

    void set_window_size(int window_size_seconds) { window_size = window_size_seconds; }

    void cleanup_obsolete_time_slots(int now);
    void add_failed_reply(int now);
    void add_success_reply(int now);

    const std::map<int, Stats> &getTimeSlots() const { return time_slots; }
};
