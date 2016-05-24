#ifndef _CdrWriter_h_
#define _CdrWriter_h_

#include "AmThread.h"

#include <string>
#include <list>
#include <vector>
#include <pqxx/pqxx>
#include "Cdr.h"
#include "../SBCCallProfile.h"
#include "../db/DbConfig.h"
#include "Cdr.h"
#include "../db/DbTypes.h"
#include <fstream>
#include <sstream>
#include <cstdio>
#include <ctime>

using std::string;
using std::list;
using std::vector;

class cdr_writer_connection: public pqxx::connection {
  private:
	bool master;
  public:
	cdr_writer_connection(const PGSTD::string &opt,bool is_master):
		master(is_master),
		pqxx::connection(opt) {}
	bool isMaster() { return master; }
};

struct CdrThreadCfg{
	bool failover_to_slave;
	bool failover_to_file;
	bool failover_requeue;
	bool serialize_dynamic_fields;
	string failover_file_dir;
	int check_interval;
	string failover_file_completed_dir;
	DbConfig masterdb,slavedb;
	PreparedQueriesT prepared_queries;
	DynFieldsT dyn_fields;
	string db_schema;
	int cfg2CdrThCfg(AmConfigReader& cfg,string& prefix);
};

struct CdrWriterCfg :public CdrThreadCfg{
	unsigned int poolsize;
	bool serialize_dynamic_fields;
	string name;
	int cfg2CdrWrCfg(AmConfigReader& cfg);
};

class CdrThread : public AmThread{
	list<Cdr*> queue;
	AmMutex queue_mut;
	AmCondition<bool> queue_run;
	AmCondition<bool> stopped;
	cdr_writer_connection *masterconn,*slaveconn;
	CdrThreadCfg config;
	auto_ptr<ofstream> wfp;
	string write_path;
	string completed_path;
	bool masteralarm,slavealarm;
	int _connectdb(cdr_writer_connection **conn,string conn_str,bool master);
	int connectdb();
	void prepare_queries(pqxx::connection *c);
	void dbg_writecdr(AmArg &fields_values,Cdr &cdr);
	int writecdr(cdr_writer_connection* conn,Cdr &cdr);
	int writecdrtofile(Cdr* cdr);
	bool openfile();
	void write_header();
	bool gotostop;
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
	void postcdr(Cdr* cdr);
	int configure(CdrThreadCfg& cfg);
	void run();
	void on_stop();
};

class CdrWriter{
	vector<CdrThread*> cdrthreadpool;
	AmMutex cdrthreadpool_mut;
	CdrWriterCfg config;
public:
	void clearStats();
	void closeFiles();
	void getStats(AmArg &arg);
	void getConfig(AmArg &arg);
	void showOpenedFiles(AmArg &arg);
	void postcdr(Cdr* cdr);
	int configure(CdrWriterCfg& cfg);
	void start();
	void stop();
	CdrWriter();
	~CdrWriter();
};

#endif
