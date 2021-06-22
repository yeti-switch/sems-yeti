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
    cdr_writer_connection(const string &opt,bool is_master):
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
    int cfg2CdrThCfg(AmConfigReader& cfg,string& prefix);
};

struct CdrWriterCfg
  : public CdrThreadCfg
{
    unsigned int poolsize;
    unsigned int auth_pool_size;
    string name;
    int cfg2CdrWrCfg(AmConfigReader& cfg);
};

class CdrThread
  : public AmThread
{
    using cdr_queue_t = std::list< std::unique_ptr<CdrBase> >;

    cdr_queue_t queue;
    cdr_queue_t retry_queue;
    AmMutex queue_mut;
    AmCondition<bool> queue_run;

    bool paused;

    AmCondition<bool> stopped;
    bool gotostop;

    cdr_writer_connection *masterconn,*slaveconn;
    bool masteralarm,slavealarm;

    auto_ptr<ofstream> wfp;
    string write_path;
    string completed_path;

    volatile bool db_err;
    time_t next_check_time;
    time_t next_retry_time;

    CdrThreadCfg config;

    void check_db(time_t now);
    int _connectdb(cdr_writer_connection **conn,string conn_str,bool master);
    int connectdb();
    void prepare_queries(pqxx::connection *c);
    void dbg_writecdr(AmArg &fields_values,Cdr &cdr);
    bool write_with_failover(cdr_queue_t &cdr_queue, size_t entries_to_write,  bool retry = false);
    int writecdr(cdr_queue_t &cdr_queue, cdr_writer_connection* conn,size_t entries_to_write, bool retry);
    int writecdrtofile(cdr_queue_t &cdr_queue);
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
    void showRetryQueue(AmArg &arg);
    void postcdr(CdrBase* cdr);
    int configure(CdrThreadCfg& cfg);
    void run();
    void on_stop();

    void setPaused(bool p) { paused = p; }
    void setRetryInterval(int interval) { config.retry_interval = interval; }
};

class CdrWriter {
    vector<unique_ptr<CdrThread>> cdrthreadpool;
    vector<unique_ptr<CdrThread>> auth_log_threadpool;
    CdrWriterCfg config;
    bool paused;
  public:
    void clearStats();
    void closeFiles();
    void getStats(AmArg &arg);
    void getConfig(AmArg &arg);
    void showOpenedFiles(AmArg &arg);
    void showRetryQueues(AmArg &arg);
    void postcdr(CdrBase* cdr);
    void post_auth_log(CdrBase *cdr);
    int configure(CdrWriterCfg& cfg);
    void start();
    void stop();
    void setPaused(bool p);
    void setRetryInterval(int retry_interval);
    CdrWriter();
    ~CdrWriter();
};

