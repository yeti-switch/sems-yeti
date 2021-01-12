#pragma on

#include "db/DbConfig.h"
#include <pqxx/pqxx>

class OptionsProberManager
{
    DbConfig dbc;
    string db_routing_schema;

    void pqxx_row_to_amarg(const pqxx::row &r, AmArg &a);
    int load_probers(AmArg &sip_probers, int prober_id = -1);

  public:
    int configure(AmConfigReader &cfg, string &cfg_routing_schema);

    int reload_probers(int prober_id = -1);
};
