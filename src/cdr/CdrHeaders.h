#pragma once

#include <map>
#include <string>

#include "AmSipMsg.h"

class cdr_headers_t
{
    enum cdr_header_serialization_type_t {
        SerializeFirstAsString,
        SerializeAllAsArrayOfStrings
    };
    std::map<std::string,cdr_header_serialization_type_t> headers;

  public:
    bool enabled();
    int add_header(std::string header_name, const std::string &serialization_type);
    AmArg serialize_headers(const string &hdrs) const;
};
