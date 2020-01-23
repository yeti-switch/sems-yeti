#ifndef _PgConnectionPool_h_
#define _PgConnectionPool_h_

#include "AmThread.h"
#include "AmArg.h"

#include <string>
#include <list>
#include <vector>
#include <pqxx/pqxx>
#include "DbConfig.h"
#include <sys/time.h>
#include <unistd.h>
#include "DbTypes.h"

using std::string;
using std::list;
using std::vector;

#define PG_CONN_POOL_CHECK_TIMER_RATE 20e3	//20 seconds
#define PG_CONN_POOL_RECONNECT_DELAY  5e6	//5 seconds

class PgConnection:
	public pqxx::connection
{
  public:
	PgConnection(const string &opts);
	~PgConnection();
	unsigned int exceptions;
	struct timeval access_time;
};

struct PgConnectionPoolCfg {
	DbConfig dbconfig;
	string name;
	string routing_init_function;
	unsigned int size;
	unsigned int max_exceptions;
	unsigned int check_interval;
	unsigned int max_wait;
    unsigned int statement_timeout;
	PreparedQueriesT prepared_queries;
	int cfg2PgCfg(AmConfigReader& cfg);
};

class PgConnectionPool:
	public AmThread
{
	PgConnectionPoolCfg cfg;
	string conn_str;
	bool slave;

	list<PgConnection*> connections;

	unsigned int total_connections;
	unsigned int failed_connections;
	AmMutex connections_mut;

	AmCondition<bool> have_active_connection;
	AmCondition<bool> try_connect;

	unsigned int exceptions_count;

	bool reconnect_failed_alarm;	//skip reconnect error messages on alarm state

	AmCondition<bool> stopped;
	bool gotostop;

	time_t mi_start;	//last measurement interval start time
	time_t mi;			//tps measurement interval
	unsigned int tpi;	//transactions per interval
	struct {
		int transactions_count;			//total succ transactions count
		int check_transactions_count;	//total succ check_transactions count
		int reconnect_attempts;					//reconnect attempts count
		double tt_min,tt_max;			//transactions time (duration)
		double tps_max,tps_avg;			//transactions per second
	} stats;

	void connection_init(PgConnection *c);
	void prepare_queries(PgConnection *c);

  public:
	enum conn_stat {
		CONN_SUCC,		/*! no errors */
		CONN_CHECK_SUCC,		/*! no errors during check */
		CONN_COMM_ERR,		/*! communication error */
		CONN_DB_EXCEPTION		/*! database exception */
	};
	string pool_name;

	PgConnectionPool(bool slave = false);
	~PgConnectionPool();
	void run();
	void on_stop();

	void set_config(PgConnectionPoolCfg& config);
	void dump_config();

	void add_connections(unsigned int count);
	PgConnection* getActiveConnection();
	void returnConnection(PgConnection* c,conn_stat stat = CONN_SUCC);

	void clearStats();
	void getStats(AmArg &arg);
	void getConfig(AmArg &arg);
};

#endif
