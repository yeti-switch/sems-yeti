#include "TimeLines.h"
#include "AmUtils.h"
#include "log.h"

#include <sys/time.h>

#define TIME_LINE_INTERVALS_RESERVE_HINT 5
#define TIME_LINES_RESERVE_HINT 2000

bool TimeLines::time_line::time_interval::has_intersection(
    timeval &start_time, timeval &end_time) const
{
    return !(timercmp(&start_time,&end,>=) ||
             timercmp(&end_time,&start,<=));
}

TimeLines::time_line::time_line()
{
    intervals.reserve(TIME_LINE_INTERVALS_RESERVE_HINT);
}

TimeLines::time_line::time_line(timeval &start_time, timeval &end_time)
  : time_line()
{
    intervals.emplace_back(start_time,end_time);
}

bool TimeLines::time_line::add_interval(
    timeval &start_time, timeval &end_time)
{
    for(const auto &interval: intervals)
        if(interval.has_intersection(start_time,end_time))
            return false;
    intervals.emplace_back(start_time,end_time);
    return true;
}

TimeLines::TimeLines(unsigned int starting_index)
  : starting_index(starting_index)
{
    timelines.resize(TIME_LINES_RESERVE_HINT);
}

unsigned int TimeLines::get(timeval &start_time, timeval &end_time)
{
    unsigned int i = starting_index;

    for(auto &timeline: timelines) {
        if(timeline.add_interval(start_time,end_time))
            return i;
        i++;
    }
    timelines.emplace_back(start_time,end_time);
    return i;
}
