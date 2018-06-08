#pragma once

#include "AmThread.h"

#include <string>
#include <list>
#include <vector>
#include <pqxx/pqxx>
#include "Cdr.h"
#include "../SBCCallProfile.h"
#include "../db/DbConfig.h"
#include "../UsedHeaderField.h"
#include "Cdr.h"
#include "../db/DbTypes.h"
#include <fstream>
#include <sstream>
#include <cstdio>
#include <ctime>

using std::string;
using std::list;
using std::vector;

class cdr_writer_connection
  : public pqxx::connection
{
  private:
    bool master;

  public:
    cdr_writer_connection(const PGSTD::string &opt,bool is_master):
        master(is_master),
        pqxx::connection(opt)
    {}
    bool isMaster() { return master; }
};

struct CdrThreadCfg
{
    bool failover_to_slave;
    bool failover_to_file;
    bool failover_requeue;
    bool serialize_dynamic_fields;
    string failover_file_dir;
    int check_interval;
    int batch_timeout;
    int batch_size;
    string failover_file_completed_dir;
    DbConfig masterdb,slavedb;
    PreparedQueriesT prepared_queries;
    DynFieldsT dyn_fields;
    vector<UsedHeaderField> used_header_fields;
    string db_schema;
    int cfg2CdrThCfg(AmConfigReader& cfg,string& prefix);
};

struct CdrWriterCfg
  : public CdrThreadCfg
{
    unsigned int poolsize;
    bool serialize_dynamic_fields;
    string name;
    int cfg2CdrWrCfg(AmConfigReader& cfg);
};

class CdrThread
  : public AmThread
{
    std::list< std::unique_ptr<CdrBase> > queue;
    AmMutex queue_mut;
    AmCondition<bool> queue_run;

    AmCondition<bool> stopped;
    bool gotostop;

    cdr_writer_connection *masterconn,*slaveconn;
    bool masteralarm,slavealarm;

    auto_ptr<ofstream> wfp;
    string write_path;
    string completed_path;

    volatile bool db_err;
    int non_batch_entries_left;
    time_t next_check_time;

    CdrThreadCfg config;

    void check_db(time_t now);
    int _connectdb(cdr_writer_connection **conn,string conn_str,bool master);
    int connectdb();
    void prepare_queries(pqxx::connection *c);
    void dbg_writecdr(AmArg &fields_values,Cdr &cdr);
    bool write_with_failover(int entries_to_write);
    int writecdr(cdr_writer_connection* conn,int entries_to_write);
    int writecdrtofile();
    bool openfile();
    void write_header();

    struct {
        int db_exceptions;
        int writed_cdrs;
        int tried_cdrs;
    } stats;

  public:
     CdrThread();
     ~CdrThread();
    void clearStats();
    void closefile();
    void getStats(AmArg &arg);
    void showOpenedFiles(AmArg &arg);
    void postcdr(CdrBase* cdr);
    int configure(CdrThreadCfg& cfg);
    void run();
    void on_stop();
};

class CdrWriter {
    vector<unique_ptr<CdrThread>> cdrthreadpool;
    vector<unique_ptr<CdrThread>> auth_log_threadpool;
    CdrWriterCfg config;
  public:
    void clearStats();
    void closeFiles();
    void getStats(AmArg &arg);
    void getConfig(AmArg &arg);
    void showOpenedFiles(AmArg &arg);
    void postcdr(CdrBase* cdr);
    void post_auth_log(CdrBase *cdr);
    int configure(CdrWriterCfg& cfg);
    void start();
    void stop();
    CdrWriter();
    ~CdrWriter();
};

