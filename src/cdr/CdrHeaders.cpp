#include "CdrHeaders.h"

#include "log.h"
#include "jsonArg.h"

#include "../HeaderFilter.h"

static int normalize_aleg_header_name(int c) {
    if(c=='-') return '_';
    return ::tolower(c);
}

bool cdr_headers_t::enabled()
{
    return !headers.empty();
}

int cdr_headers_t::add_header(std::string header_name, const std::string &serialization_type)
{
    cdr_header_serialization_type_t type;
    if(serialization_type=="string") {
        type = SerializeFirstAsString;
    } else if(serialization_type=="array") {
        type = SerializeAllAsArrayOfStrings;
    } else {
        ERROR("header(%s,%s) unexpected serialization type '%s'. allowed values: string, array",
              header_name.data(), serialization_type.data(), serialization_type.data());
        return 1;
    }

    std::transform(header_name.begin(), header_name.end(), header_name.begin(), normalize_aleg_header_name);

    DBG("add aleg_cdr_header '%s' with type %s",
        header_name.data(), serialization_type.data());

    headers.emplace(header_name, type);

    return 0;
}

AmArg cdr_headers_t::serialize_headers(const AmSipRequest &req) const
{
    AmArg a;
    size_t start_pos = 0, name_end, val_begin, val_end, hdr_end;

    a.assertStruct();
    while(start_pos<req.hdrs.length()) {
        if (skip_header(req.hdrs, start_pos,
            name_end, val_begin, val_end, hdr_end) != 0)
        {
            break;
        }

        string hdr_name = req.hdrs.substr(start_pos, name_end-start_pos);
        std::transform(hdr_name.begin(), hdr_name.end(), hdr_name.begin(), normalize_aleg_header_name);

        auto it = headers.find(hdr_name);
        if(it != headers.end()) {
            switch(it->second) {
            case SerializeFirstAsString:
                if(!a.hasMember(hdr_name)) {
                    a[hdr_name] = req.hdrs.substr(val_begin, val_end - val_begin);
                }
                break;
            case SerializeAllAsArrayOfStrings:
                a[hdr_name].push(req.hdrs.substr(val_begin, val_end - val_begin));
                break;
            }
        }
        start_pos = hdr_end;
    }

    //add null entries
    /*for(const auto &hdr : headers) {
        if(!a.hasMember(hdr.first))
            a[hdr.first] = AmArg();
    }*/

    return a;
}
