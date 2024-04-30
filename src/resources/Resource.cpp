#include "Resource.h"
#include "log.h"
#include "AmUtils.h"
#include <vector>
#include <sstream>

#define RES_ATOM_SEPARATOR ";"
#define RES_OPTION_SEPARATOR "|"
#define RES_FIELDS_SEPARATOR ":"

void ResourceList::parse(const std::string rs)
{
    this->clear();
    //DBG("rs = %s",rs.c_str());
    vector<string> lc = explode(rs,RES_ATOM_SEPARATOR);
    for(vector<string>::const_iterator ri = lc.begin();
        ri != lc.end(); ++ri)
    {
        //DBG("   *ri = %s",(*ri).c_str());
        vector<string> ac = explode(*ri,RES_OPTION_SEPARATOR);
        for(vector<string>::const_iterator ai = ac.begin();
            ai != ac.end(); ++ai)
        {
            //DBG("      *ai = %s",(*ai).c_str());
            Resource r;
            vector<string> vc = explode(*ai,RES_FIELDS_SEPARATOR);
            if(vc.size()!=4){
                throw ResourceParseException("invalid format: params count",(*ai));
            }
            if(	str2int(vc[0],r.type) &&
                str2int(vc[1],r.id) &&
                str2int(vc[2],r.limit) &&
                str2int(vc[3],r.takes))
            {
                if(r.takes!=0){	//skip resources without quantity
                    r.failover_to_next = true;
                    this->push_back(r);
                }
            } else {
                DBG("%s() str2int conversion error",FUNC_NAME);
                throw ResourceParseException("invalid format: str2int conversion",(*ri));
            }
        }
        if(!this->empty()) this->back().failover_to_next = false;
    }
}

string Resource::print() const{
    ostringstream s;
    s << "type: " << type << ", ";
    s << "id: " << id << ", ";
    s << "limit: " << limit << ", ";
    s << "takes: " << takes << ", ";
    s << "failover_to_next: " << failover_to_next << ", ";
    s << "active: " << active << ", ";
    s << "taken: " << taken;
    return s.str();
}
