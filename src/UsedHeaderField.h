#ifndef USEDHEADERFIELD_H
#define USEDHEADERFIELD_H

#include "AmSipMsg.h"
#include "sip/parse_nameaddr.h"

#include <string>
#include <optional>
#include <variant>

using std::string;

class UsedHeaderField {

    enum NeededPart { uri_user, uri_domain, uri_port, uri_param, uri_json };

    enum ValueType { Raw, Uri };

    string     name;  // SIP hdr name
    string     param; // part options (e.g parameter name for uri_param)
    ValueType  type;  // type of header value
    NeededPart part;  // needed part of parsed value
    string     sql_type_name;

    // concatenate all headers values to the comma-separated list
    bool multiple_headers;

    void applyFormat(const string &format);

    bool process_uri(const sip_uri &uri, string &ret) const;
    void serialize_nameaddr(const sip_nameaddr &na, AmArg &ret) const;

  public:
    UsedHeaderField(const string &hdr_name);
    UsedHeaderField(const AmArg &a);

    std::optional<AmArg> getValue(const AmSipRequest &req) const;

    void        getInfo(AmArg &arg) const;
    const char *type2str() const;
    const char *part2str() const;

    const string &getName() const { return name; }
    const string &getSqlTypeName() const { return sql_type_name; }
};

#endif // USEDHEADERFIELD_H
