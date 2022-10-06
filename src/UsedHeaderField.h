#ifndef USEDHEADERFIELD_H
#define USEDHEADERFIELD_H

#include "AmSipMsg.h"

#include <string>

using std::string;

class UsedHeaderField {

    enum NeededPart {
        uri_user,
        uri_domain,
        uri_port,
        uri_param
    };

    enum ValueType {
        Raw,
        Uri
    };

    string name;        //SIP hdr name
    string param;       //part options (e.g parameter name for uri_param)
    ValueType type;     //type of header value
    NeededPart part;    //needed part of parsed value
    bool hashkey;       //this header used in routing logic
    string sql_type_name;

    void applyFormat(const string &format);
  public:
    UsedHeaderField(const string &hdr_name);
    UsedHeaderField(const AmArg &a);

    bool getValue(const AmSipRequest &req,string &val) const;
    void getInfo(AmArg &arg) const;
    const char*type2str() const;
    const char*part2str() const;

    const string &getName() const { return name; }
    const string &getSqlTypeName() const { return sql_type_name; }
    bool is_hashkey() const { return hashkey; }
};

#endif // USEDHEADERFIELD_H
