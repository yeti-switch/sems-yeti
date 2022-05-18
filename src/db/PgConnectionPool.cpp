#include "PgConnectionPool.h"
#include "log.h"
#include <string>
#include "AmUtils.h"
#include "../yeti.h"
#include "../alarms.h"

#include <sstream>

PgConnection::PgConnection(const string &opts):
	pqxx::connection(opts),
	exceptions(0)
{
	timerclear(&access_time);
	//DBG("PgConnection::PgConnection() this = [%p]",this);
}

PgConnection::~PgConnection(){
	//DBG("PgConnection::~PgConnection() this = [%p]",this);
}

PgConnectionPool::PgConnectionPool(bool slave):
	total_connections(0),
	failed_connections(0),
	have_active_connection(false),
	reconnect_failed_alarm(false),
	exceptions_count(0),
	try_connect(true),
	stopped(false),
	gotostop(false),
	mi(5),
	slave(slave)
{
	clearStats();
}

PgConnectionPool::~PgConnectionPool(){
	DBG("PgCP thread stopping");
}

int PgConnectionPoolCfg::cfg2PgCfg(AmConfigReader& cfg){
	dbconfig.cfg2dbcfg(cfg,name);
	size = cfg.getParameterInt(name+"_pool_size",10);
	max_exceptions = cfg.getParameterInt(name+"_max_exceptions",0);
	check_interval=cfg.getParameterInt(name+"_check_interval",25);
	max_wait=cfg.getParameterInt(name+"_max_wait",125);
    statement_timeout=cfg.getParameterInt(name+"_statement_timeout",0);
	routing_init_function = cfg.getParameter("routing_init_function");
	return 0;
}

void PgConnectionPool::dump_config(){
	conn_str =	"host="+cfg.dbconfig.host+
				" port="+int2str(cfg.dbconfig.port)+
				" user="+cfg.dbconfig.user+
				" dbname="+cfg.dbconfig.name+
				" password="+cfg.dbconfig.pass;

	INFO("PgCP: Pool %s CONFIG:",pool_name.c_str());
	INFO("PgCP:		 remote db socket: %s:%d",cfg.dbconfig.host.c_str(),cfg.dbconfig.port);
	INFO("PgCP:		 dbname: %s",cfg.dbconfig.name.c_str());
	INFO("PgCP:		 user/password: %s/%s",cfg.dbconfig.user.c_str(),cfg.dbconfig.pass.c_str());
	INFO("PgCP:		 max_exceptions: %d",cfg.max_exceptions);
	INFO("PgCP:		 check_interval: %d",cfg.check_interval);
    INFO("PgCP:		 statement_timeout: %d",cfg.statement_timeout);
	INFO("PgCP: Pool RUNTIME:");

	connections_mut.lock();
		INFO("PgCP:		 Connections total/failed: %s/%s",int2str(total_connections).c_str(),int2str(failed_connections).c_str());
	connections_mut.unlock();

	INFO("PgCP:		 exceptions_count: %s",int2str(exceptions_count).c_str());
}

void PgConnectionPool::set_config(PgConnectionPoolCfg&config){
	cfg = config;
	DBG("%s: PgConnectionPool configured",pool_name.c_str());
}

void PgConnectionPool::add_connections(unsigned int count){
	connections_mut.lock();
		failed_connections += count;
		total_connections += count;
	connections_mut.unlock();
	try_connect.set(true);
}

void PgConnectionPool::returnConnection(PgConnection* c,conn_stat stat){
	bool return_connection = false,check = false;
	struct timeval now,ttdiff;
	double tt_curr;

	gettimeofday(&now,NULL);
	timerclear(&ttdiff);

	switch(stat){
		case CONN_SUCC: {
			return_connection = true;
		} break;
		case CONN_CHECK_SUCC: {
			return_connection = true;
			check = true;
		} break;
		case CONN_DB_EXCEPTION: {
			c->exceptions++;
			if(c->exceptions > cfg.max_exceptions)
				return_connection = true;
		} break;
		case CONN_COMM_ERR:
		default: {
			return_connection = false;
		};
	}

	if(return_connection){
		connections_mut.lock();
			connections.push_back(c);
			//size_t active_size = connections.size();
			if(timerisset(&c->access_time)){
				//returnConnection() called after getActiveConnection()
				if(check){
					stats.check_transactions_count++;
				} else {
					stats.transactions_count++;
					timersub(&now,&c->access_time,&ttdiff);
					tt_curr = timeval2double(ttdiff);
					if(tt_curr > stats.tt_max)
						stats.tt_max = tt_curr;
					if(stats.tt_min){
						if(tt_curr < stats.tt_min)
							stats.tt_min = tt_curr;
					} else {
						stats.tt_min = tt_curr;
					}
				}
			}
			gettimeofday(&c->access_time,NULL);
		connections_mut.unlock();

		have_active_connection.set(true);
		//DBG("%s: Now %zd active connections",pool_name.c_str(),active_size);
	} else {
		delete c;
		connections_mut.lock();
			RAISE_ALARM(slave ? alarms::MGMT_DB_CONN_SLAVE : alarms::MGMT_DB_CONN);
			failed_connections++;
			unsigned int inactive_size = failed_connections;
		connections_mut.unlock();
		try_connect.set(true);

		DBG("%s: Now %u inactive connections",pool_name.c_str(), inactive_size);
	}
}

PgConnection* PgConnectionPool::getActiveConnection(){
	PgConnection* res = NULL;
	time_t now;
	double diff,tps;
	int intervals;

	while (NULL == res) {
		if(gotostop) {
			DBG("%s: pool is going to shutdown. return NO connection",pool_name.c_str());
			return NULL;
		}

		connections_mut.lock();
			if (connections.size()) {
				res = connections.front();
				connections.pop_front();
				have_active_connection.set(!connections.empty());
			}
		connections_mut.unlock();

		if (NULL == res) {
			// check if all connections broken -> return null
			connections_mut.lock();
				bool all_inactive = total_connections == failed_connections;
			connections_mut.unlock();

			if (all_inactive) {
				DBG("%s: all connections inactive - returning NO connection",pool_name.c_str());
				return NULL;
			}

			// wait until a connection is back
			DBG("%s: waiting for an active connection to return, max_wait = %d",
				pool_name.c_str(), cfg.max_wait);
			if (!have_active_connection.wait_for_to(cfg.max_wait)) {
				WARN("%s: timeout waiting for an active connection (waited %ums)",pool_name.c_str(), cfg.max_wait);
				break;
			}
		} else {
			/*	memorise connection get time	*/
			gettimeofday(&res->access_time,NULL);
			/*	compute tps	*/
			now = res->access_time.tv_sec;
			diff = difftime(now,mi_start);
			intervals = diff/mi;
			if(intervals > 0){
				//now is first point in current measurement interval
				mi_start = now;
				tps = tpi/(double)mi;
				stats.tps_avg = tps;
				if(tps > stats.tps_max)
					stats.tps_max = tps;
				tpi = 1;
			} else {
				//now is another point in current measurement interval
				tpi++;
			}
			DBG("%s: got active connection [%p]",pool_name.c_str(), res);
		}
	}

	return res;
}


void PgConnectionPool::run(){
	bool succ;
	string what;

	DBG("PgCP %s thread starting",pool_name.c_str());
	setThreadName("yeti-pg-cp");

	SET_ALARM(slave ? alarms::MGMT_DB_CONN_SLAVE : alarms::MGMT_DB_CONN,failed_connections,true);

	try_connect.set(true); //for initial connections setup

	bool initial_cycle = true;

	while (!gotostop) {
		try_connect.wait_for_to(PG_CONN_POOL_CHECK_TIMER_RATE);

		if(gotostop)
			break;

		if (try_connect.get()){
			connections_mut.lock();
				unsigned int m_failed_connections = failed_connections;
			connections_mut.unlock();

			if (!m_failed_connections){
				try_connect.set(false);
				continue;
			}

			if(!reconnect_failed_alarm)
				DBG("PgCP: %s: start connection",pool_name.c_str());

			// add connections until error occurs
			while(m_failed_connections){
				succ = false;
				PgConnection* conn = NULL;

				if(!initial_cycle)
					stats.reconnect_attempts++;

				try {
					conn = new PgConnection(conn_str);
					if(conn->is_open()){
						connection_init(conn);
						DBG("PgCP: %s: SQL connected. Backend pid: %d.",pool_name.c_str(),conn->backendpid());
						returnConnection(conn);
						connections_mut.lock();
							failed_connections--;
						connections_mut.unlock();
						reconnect_failed_alarm = false;
						CLEAR_ALARM(slave ? alarms::MGMT_DB_CONN_SLAVE : alarms::MGMT_DB_CONN);
						succ = true;
					} else {
						throw new pqxx::broken_connection("can't open connection");
					}
				} catch(const pqxx::broken_connection &exc){
					what = exc.what();
				} catch(pqxx::pqxx_exception &exc){
					what = exc.base().what();
				}
				if(!succ){
					if(conn){
						if(conn->is_open())
							conn->disconnect();
						delete conn;
					}
					if(!reconnect_failed_alarm)
						ERROR("PgCP: %s: connection exception: %s",
							pool_name.c_str(),what.c_str());
					exceptions_count++;
					reconnect_failed_alarm = true;
					if ((cfg.max_exceptions>0)&&(exceptions_count>cfg.max_exceptions)) {
						ERROR("PgCP: %s: max exception count reached. Pool stopped.",
							pool_name.c_str());
						try_connect.set(false);
						break;
					}
					if(gotostop)
						break;
					usleep(PG_CONN_POOL_RECONNECT_DELAY);
				} else {
					m_failed_connections--;
				}
			}

			connections_mut.lock();
				m_failed_connections = failed_connections;
			connections_mut.unlock();

			if (0==m_failed_connections){
				WARN("PCP: %s: All sql connected.",pool_name.c_str());
				try_connect.set(false);
			}

			if(cfg.size==m_failed_connections){
				usleep(PG_CONN_POOL_RECONNECT_DELAY);
			}

		} else {
			PgConnection* c = NULL;

			connections_mut.lock();
				struct timeval now,diff;
				gettimeofday(&now,NULL);
				//collect connections which haven't been used recently
				list<PgConnection*> cv;
				list<PgConnection*>::iterator i = connections.begin(),ti;
				while(i!=connections.end()){
					ti = i;
					ti++;
					c = (*i);
					timersub(&now,&c->access_time,&diff);
					/*DBG("diff = {%ld , %ld}, check_interval = %d",
						diff.tv_sec,diff.tv_usec,cfg.check_interval);*/
					if(diff.tv_sec>cfg.check_interval){
						//DBG("connecton %p checktime is arrived. schedule to check it",c);
						cv.push_back(c);
						connections.erase(i);
					}
					i = ti;
				}
			connections_mut.unlock();

			while(!cv.empty()){
				//DBG("another connection check");
				c = cv.front();
				cv.pop_front();
				try {
					pqxx::work t(*c);
					t.commit();
					//DBG("check succc. return it to pool");
					returnConnection(c,CONN_CHECK_SUCC);
				} catch (const pqxx::pqxx_exception &e) {
					/*DBG("connection checking failed: '%s'. delete it from pool",
						e.base().what());*/
					returnConnection(c,CONN_COMM_ERR);
				}
			}
			//DBG("while end");
		} // if (try_connect.get()) else

		initial_cycle = false;
	} //while(true)

	connections_mut.lock();
		while(!connections.empty()){
			PgConnection *c = connections.front();
			connections.pop_front();
			DBG("PgCP: %s: Disconnect SQL. Backend pid: %d.",
				pool_name.c_str(),c->backendpid());
			c->disconnect();
			delete c;
		}
	connections_mut.unlock();
	stopped.set(true);
}

void PgConnectionPool::on_stop(){
	DBG("PgCP %s thread stopping",pool_name.c_str());
	gotostop=true;
	try_connect.set(true);

	stopped.wait_for();

	DBG("PgCP %s All disconnected",pool_name.c_str());
}

void PgConnectionPool::clearStats(){
	time(&mi_start);
	tpi = 0;
	stats.transactions_count = 0;
	stats.check_transactions_count = 0;
	stats.reconnect_attempts = 0;
	stats.tt_min = 0;
	stats.tt_max = 0;
	stats.tps_max = 0;
	stats.tps_avg = 0;
	for(list<PgConnection*>::iterator it = connections.begin();it!=connections.end();it++){
		(*it)->exceptions = 0;
	}
}

void PgConnectionPool::getStats(AmArg &arg){
	AmArg conn,conns;

	connections_mut.lock();

	arg["total_connections"] = (int)total_connections;
	arg["failed_connections"] = (int)failed_connections;
	arg["transactions"] = stats.transactions_count;
	arg["exceptions"] = (int)exceptions_count;
	arg["reconnect_attempts"] = stats.reconnect_attempts;
	arg["check_transactions"] = stats.check_transactions_count;
	arg["tt_min"] = stats.tt_min;
	arg["tt_max"] = stats.tt_max;
	arg["tps_max"] = stats.tps_max;
	arg["tps_avg"] = stats.tps_avg;

	for(list<PgConnection*>::iterator it = connections.begin();it!=connections.end();it++){
		conn["exceptions"] = (int)(*it)->exceptions;
		conns.push(conn);
		conn.clear();
	}
	arg.push("connections",conns);

	connections_mut.unlock();
}

void PgConnectionPool::getConfig(AmArg &arg){
	arg["db"] = cfg.dbconfig.conn_str();
	arg["size"] = (int)cfg.size;
	arg["max_exceptions"] = (int)cfg.max_exceptions;
	arg["check_interval"] = (int)cfg.check_interval;
	arg["max_wait"] = (int)cfg.max_wait;
    arg["stmt_timeout"] = (int)cfg.statement_timeout;
}

void PgConnectionPool::connection_init(PgConnection *c){
	const auto &gc = Yeti::instance().config;
	const string &routing_schema = gc.routing_schema;
	if(!routing_schema.empty()){
		c->set_variable("search_path",routing_schema+", public");
	}

	if(cfg.statement_timeout){
		c->set_variable("statement_timeout",int2str(cfg.statement_timeout));
	}

	prepare_queries(c);

	if(!cfg.routing_init_function.empty()){
		std::ostringstream sql;
		sql << "SELECT " << cfg.routing_init_function << "($1,$2)";
#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
		pqxx::prepare::declaration d =
#endif
			c->prepare("routing_init",sql.str());
#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
		d("integer",pqxx::prepare::treat_direct);
		d("integer",pqxx::prepare::treat_direct);
#endif
		c->prepare_now("routing_init");
		pqxx::nontransaction tnx(*c);
		tnx.exec_prepared("routing_init",AmConfig.node_id,gc.pop_id);
		c->unprepare("routing_init");
	}
}

void PgConnectionPool::prepare_queries(PgConnection *c){
	PreparedQueriesT::iterator it = cfg.prepared_queries.begin();
	for(;it!=cfg.prepared_queries.end();++it){
#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
		pqxx::prepare::declaration d =
#endif
			c->prepare(it->first,it->second.first);
#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
		PreparedQueryArgs_iterator ait = it->second.second.begin();
		for(;ait!=it->second.second.end();++ait){
			d(*ait,pqxx::prepare::treat_direct);
		}
#endif
		c->prepare_now(it->first);
	}
}
