#pragma once

#include <map>
#include <string>

#include "AmSipMsg.h"

class cdr_headers_t
{
    enum cdr_header_serialization_type_t {
        SerializeFirstAsString,
        SerializeAllAsArrayOfStrings,
        SerializeFirstAsSmallint,
        SerializeFirstAsInteger,
    };
    std::map<std::string,cdr_header_serialization_type_t> headers;

    enum cdr_header_snapshot_serialization_type_t {
        SnapshotSerializeFirstAsString,
    };
    struct SnapshotHeaderData {
        cdr_header_snapshot_serialization_type_t type;
        string snapshot_key;
        SnapshotHeaderData(
            cdr_header_snapshot_serialization_type_t type,
            string snapshot_key)
          : type(type),
            snapshot_key(snapshot_key)
        {}
    };
    using SnapshotHeaders = std::map<std::string,SnapshotHeaderData>;
    SnapshotHeaders snapshot_headers;

  public:
    bool enabled() const;

    int add_header(std::string header_name, const std::string &serialization_type);
    AmArg serialize_headers(const string &hdrs) const;

    int add_snapshot_header(
        std::string header_name,
        const std::string &snapshot_key,
        const std::string &serialization_type);
    AmArg serialize_headers_for_snapshot(const string &hdrs) const;

    const SnapshotHeaders& get_snapshot_headers() const { return snapshot_headers; }
};
