#include "CdrBase.h"

CdrBase::CdrBase(cdr_type type)
    : type(type)
    , suppress(false)
{
    gettimeofday(&cdr_born_time, NULL);
}

string timeval2str_utc(const timeval &tv)
{
    time_t    t;
    struct tm tt;
    char      s[64] = { 0 };

    t = tv.tv_sec;
    gmtime_r(&t, &tt);
    int len = strftime(s, sizeof s, "%Y-%m-%d %H:%M:%S", &tt);
    if (len > 0)
        return string(s, len);
    return string("conversion error");
}
