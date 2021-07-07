#ifndef _SQLRouter_
#define _SQLRouter_

#include "SBCCallProfile.h"
#include "db/PgConnectionPool.h"
#include "AmUtils.h"
#include "HeaderFilter.h"
#include <algorithm>
#include "cdr/CdrWriter.h"
#include "db/DbTypes.h"
#include "cdr/CdrBase.h"
#include "cdr/AuthCdr.h"
#include "CodesTranslator.h"
#include "UsedHeaderField.h"
#include "Auth.h"
#include "CallCtx.h"

#include "RedisConnection.h"

using std::string;
using std::list;
using std::vector;

struct GetProfileException {
	bool fatal;			//if true we should reload pg connection
	int code;
	GetProfileException(int c, bool h): code(c), fatal(h) {}
};

class UsageCounterHelper {
    AtomicCounter &counter;
  public:
    UsageCounterHelper(AtomicCounter &counter)
      : counter(counter)
    {
        counter.inc();
    }
    ~UsageCounterHelper()
    {
        counter.dec();
    }
};

class SqlRouter
  : public Auth
{
public:
  void getprofiles(const AmSipRequest&,CallCtx &ctx,Auth::auth_id_type auth_id, AmArg *identity_data);
  int configure(cfg_t *confuse_cfg, AmConfigReader &cfg);
  int start();
  void stop();
  void align_cdr(Cdr &cdr);
  void write_cdr(Cdr *cdr, bool last);
  void log_auth(
      const AmSipRequest& req,
      bool success,
      AmArg &ret,
      Auth::auth_id_type auth_id = 0);
  void send_and_log_auth_challenge(const AmSipRequest &req, const string &internal_reason,
                                   const string &hdrs);
  void dump_config();
  void closeCdrFiles();
  void getStats(AmArg &arg);
  void getConfig(AmArg &arg);
  void showOpenedFiles(AmArg &arg);
  void showRetryQueues(AmArg &arg);
  void setCdrWriterPaused(bool paused) { cdr_writer->setPaused(paused); }
  void setRetryInterval(int interval) { cdr_writer->setRetryInterval(interval); }

  const DynFieldsT &getDynFields() const { return dyn_fields; }

  /*! return true if call refused */
  bool check_and_refuse(SqlCallProfile *profile,Cdr *cdr,
                        const AmSipRequest& req,ParamReplacerCtx& ctx,
                        bool send_reply = false);
  void db_reload_credentials(AmArg &ret);

  SqlRouter();
  ~SqlRouter();

private:
  //stats
  AtomicCounter &db_hits, &db_hits_time, &hits, &active_requests;
  double gt_min,gt_max;
  double gps_max,gps_avg;
  time_t mi_start;
  time_t mi;
  unsigned int gpi;

  DbConfig dbc;
  int db_configure(AmConfigReader &cfg);

  void _getprofiles(
    list<SqlCallProfile> &profiles,
    const AmSipRequest&,
    pqxx::connection*,
    Auth::auth_id_type auth_id,
    AmArg *identity_data);
  void dbg_get_profiles(AmArg &fields_values);
  void update_counters(struct timeval &start_time);

  PgConnectionPool *master_pool;
  PgConnectionPool *slave_pool;
  CdrWriter *cdr_writer;

  vector<UsedHeaderField> used_header_fields;
  int failover_to_slave;
  string writecdr_schema;
  string writecdr_function;
  string authlog_function;
  string routing_schema;
  string routing_function;
  PreparedQueriesT prepared_queries;
  PreparedQueriesT cdr_prepared_queries;
  DynFieldsT dyn_fields;
};

#endif
