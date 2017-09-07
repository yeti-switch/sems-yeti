#pragma once

#include <ctime>
#include <vector>

class TimeLines {
    class time_line
    {
        struct time_interval {
            timeval start;
            timeval end;
            time_interval(timeval &start_time, timeval &end_time)
              : start(start_time),
                end(end_time)
            {}
            bool has_intersection(timeval &start_time, timeval &end_time) const;
        };
        std::vector<time_interval> intervals;
      public:
        time_line();
        time_line(timeval &start_time, timeval &end_time);
        /*!
         * \brief add interval to the timeline
         * \return true if succesfully added,
         *         false if has intersection with any of the existent intervals
         */
        bool add_interval(timeval &start_time, timeval &end_time);
        size_t intervals_count() { return intervals.size(); }
    };
    std::vector<time_line> timelines;
    unsigned int starting_index;
  public:
    TimeLines(unsigned int starting_index = 1);
    /*!
     * \brief get timeline id by given interval
     * \return id of the new or reused timeline
     */
    unsigned int get(timeval &start_time, timeval &end_time);
};
