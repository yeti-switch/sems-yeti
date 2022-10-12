#pragma once

#include "AmThread.h"

#include <string>
#include <list>
#include <vector>
#include "Cdr.h"
#include "../SBCCallProfile.h"
#include "../db/DbConfig.h"
#include "../UsedHeaderField.h"
#include "Cdr.h"
#include "../db/DbTypes.h"
#include "AmStatistics.h"

#include <fstream>
#include <sstream>
#include <cstdio>
#include <ctime>

using std::string;
using std::list;
using std::vector;

struct CdrThreadCfg
{
    unsigned int pool_size;
    bool failover_to_slave;
    int connection_lifetime;
    bool failover_to_file;
    bool failover_requeue;
    string failover_file_dir;
    int check_interval;
    int retry_interval;
    int batch_timeout;
    size_t batch_size;
    string failover_file_completed_dir;
    DbConfig masterdb,slavedb;
    PreparedQueriesT prepared_queries;
    DynFieldsT dyn_fields;
    vector<UsedHeaderField> used_header_fields;
    string db_schema;
    int cfg2CdrThCfg(AmConfigReader& cfg);
};
