#include "CdrHeaders.h"

#include "log.h"
#include "jsonArg.h"
#include "../HeaderFilter.h"

#include <algorithm>
#include <limits>
#include "AmUtils.h"

static int normalize_aleg_header_name(int c)
{
    if (c == '-')
        return '_';
    return ::tolower(c);
}

bool cdr_headers_t::enabled() const
{
    return !headers.empty();
}

int cdr_headers_t::add_header(std::string header_name, const std::string &serialization_type)
{
    cdr_header_serialization_type_t type;
    if (serialization_type == "string") {
        type = SerializeFirstAsString;
    } else if (serialization_type == "array") {
        type = SerializeAllAsArrayOfStrings;
    } else if (serialization_type == "smallint") {
        type = SerializeFirstAsSmallint;
    } else if (serialization_type == "integer") {
        type = SerializeFirstAsInteger;
    } else if (serialization_type == "none") {
        // skip serialization to the CDRs
        return 0;
    } else {
        ERROR("unexpected serialization type '%s' for header '%s'. "
              "allowed values: string, array, smallint, integer, none",
              serialization_type.data(), header_name.data());
        return 1;
    }

    std::transform(header_name.begin(), header_name.end(), header_name.begin(), normalize_aleg_header_name);

    DBG("add aleg_cdr_header '%s' with type %s", header_name.data(), serialization_type.data());

    headers.emplace(header_name, type);

    return 0;
}

int cdr_headers_t::add_snapshot_header(std::string header_name, const std::string &snapshot_key,
                                       const std::string &serialization_type)
{
    cdr_header_snapshot_serialization_type_t type;
    if (serialization_type == "String") {
        type = SnapshotSerializeFirstAsString;
    } else {
        ERROR("activecalls_header(%s,%s) unexpected serialization type '%s'. allowed values: String",
              header_name.data(), serialization_type.data(), serialization_type.data());
        return 1;
    }

    std::transform(header_name.begin(), header_name.end(), header_name.begin(), normalize_aleg_header_name);

    DBG("add aleg_cdr_header activecalls field for header '%s' "
        "with type '%s' and key '%s'",
        header_name.data(), serialization_type.data(), snapshot_key.data());

    snapshot_headers.try_emplace(header_name, type, snapshot_key);

    return 0;
}

AmArg cdr_headers_t::serialize_headers(const string &hdrs) const
{
    AmArg  a;
    size_t start_pos = 0, name_end, val_begin, val_end, hdr_end;

    a.assertStruct();
    while (start_pos < hdrs.length()) {
        if (skip_header(hdrs, start_pos, name_end, val_begin, val_end, hdr_end) != 0) {
            break;
        }

        string hdr_name = hdrs.substr(start_pos, name_end - start_pos);
        std::transform(hdr_name.begin(), hdr_name.end(), hdr_name.begin(), normalize_aleg_header_name);

        auto it = headers.find(hdr_name);
        if (it != headers.end()) {
            auto hdr_value = hdrs.substr(val_begin, val_end - val_begin);
            switch (it->second) {
            case SerializeFirstAsString:
                if (!a.hasMember(hdr_name)) {
                    a[hdr_name] = hdr_value;
                }
                break;
            case SerializeAllAsArrayOfStrings: a[hdr_name].push(hdr_value); break;
            case SerializeFirstAsSmallint:
            {
                if (a.hasMember(hdr_name)) {
                    break;
                }

                int ret;
                if (!str2int(hdr_value, ret)) {
                    ERROR("header '%s' smallint overflow for value '%s'. failover to null", hdr_name.c_str(),
                          hdr_value.c_str());
                    a[hdr_name] = AmArg();
                    break;
                }

                // https://www.postgresql.org/docs/current/datatype-numeric.html
                // smallint  2 bytes  small-range integer  -32768 to +32767
                if (ret < std::numeric_limits<signed short>().min() || ret > std::numeric_limits<signed short>().max())
                {
                    ERROR("header '%s' smallint overflow for value '%s'. failover to null", hdr_name.c_str(),
                          hdr_value.c_str());
                    a[hdr_name] = AmArg();
                    break;
                }

                if (int2str(ret) != hdr_value) {
                    ERROR("header '%s' conversion overflow for value '%s'. failover to null", hdr_name.c_str(),
                          hdr_value.c_str());
                    a[hdr_name] = AmArg();
                    break;
                }

                a[hdr_name] = ret;
            } break;
            case SerializeFirstAsInteger:
            {
                if (a.hasMember(hdr_name)) {
                    break;
                }

                int ret;
                if (!str2int(hdr_value, ret)) {
                    ERROR("header '%s' integer overflow for value '%s'. failover to null", hdr_name.c_str(),
                          hdr_value.c_str());
                    a[hdr_name] = AmArg();
                    break;
                }

                // https://www.postgresql.org/docs/current/datatype-numeric.html
                // integer  4 bytes  typical choice for integer  -2147483648 to +2147483647

                if (int2str(ret) != hdr_value) {
                    ERROR("header '%s' conversion overflow for value '%s'. failover to null", hdr_name.c_str(),
                          hdr_value.c_str());
                    a[hdr_name] = AmArg();
                    break;
                }

                a[hdr_name] = ret;
            } break;
            } // switch
        }
        start_pos = hdr_end;
    }

    // add null entries
    /*for(const auto &hdr : headers) {
        if(!a.hasMember(hdr.first))
            a[hdr.first] = AmArg();
    }*/

    return a;
}

AmArg cdr_headers_t::serialize_headers_for_snapshot(const string &hdrs) const
{
    AmArg a;

    size_t start_pos = 0, name_end, val_begin, val_end, hdr_end;

    a.assertStruct();
    while (start_pos < hdrs.length()) {
        if (skip_header(hdrs, start_pos, name_end, val_begin, val_end, hdr_end) != 0) {
            break;
        }

        string hdr_name = hdrs.substr(start_pos, name_end - start_pos);
        std::transform(hdr_name.begin(), hdr_name.end(), hdr_name.begin(), normalize_aleg_header_name);

        auto it = snapshot_headers.find(hdr_name);
        if (it != snapshot_headers.end()) {
            auto hdr_value = hdrs.substr(val_begin, val_end - val_begin);
            switch (it->second.type) {
            case SnapshotSerializeFirstAsString:
                if (!a.hasMember(it->second.snapshot_key)) {
                    a[it->second.snapshot_key] = hdr_value;
                }
            } // switch
        }
        start_pos = hdr_end;
    }

    // add null entries
    for (const auto &it : snapshot_headers) {
        if (!a.hasMember(it.second.snapshot_key))
            a[it.second.snapshot_key] = AmArg();
    }
    return a;
}
