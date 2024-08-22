#pragma once

#include "AmArg.h"
#include "cfg/YetiCfg.h"

#include <string>

class ReasonParser
{
    struct Reason {
        bool parsed;
        int cause;
        std::string text;
        std::string params;
        Reason()
          : parsed(false),
            cause(0)
        {}
        void serialize(AmArg &ret);
    } sip_reason, q850_reason;

    void parse_reason(const std::string &hdrs, size_t reason_begin, size_t reason_end);

  public:
    void parse_headers(const std::string &hdrs);

    bool has_data(const YetiCfg::headers_processing_config::leg_reasons &cfg);

    void serialize(
        AmArg &ret,
        const YetiCfg::headers_processing_config::leg_reasons &cfg);

    void serialize_flat(
        AmArg &ret,
        const YetiCfg::headers_processing_config::leg_reasons &cfg,
        const string &local_tag);
};
