#pragma once

#include <map>
#include <string>

#include "AmSipMsg.h"

class aleg_cdr_headers_t
{
    enum cdr_header_serialization_type_t {
        SerializeFirstAsString,
        SerializeAllAsArrayOfStrings
    };
    std::map<std::string,cdr_header_serialization_type_t> headers;

  public:
    int add_header(std::string header_name, const std::string &serialization_type);
    std::string serialize_headers_to_json(const AmSipRequest &req) const;
};
