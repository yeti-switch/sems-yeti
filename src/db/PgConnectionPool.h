#pragma once

#include <string>
#include "DbConfig.h"

using std::string;

/*#define PG_CONN_POOL_CHECK_TIMER_RATE 20e3	//20 seconds
#define PG_CONN_POOL_RECONNECT_DELAY  5e6	//5 seconds*/

struct PgConnectionPoolCfg {
    DbConfig dbconfig;
    string name;
    string routing_init_function;
    unsigned int size;
    unsigned int check_interval;
    unsigned int statement_timeout;

    int cfg2PgCfg(AmConfigReader& cfg);

    PgConnectionPoolCfg() = default;
    PgConnectionPoolCfg(const string &name)
      : name(name)
    {}
};
