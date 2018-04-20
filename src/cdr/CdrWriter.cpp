#include "sems.h"
#include "CdrWriter.h"
#include "log.h"
#include "AmThread.h"
#include <pqxx/pqxx>
#include "../yeti.h"
#include "../alarms.h"
#include "../cdr/TrustedHeaders.h"
#include "../yeti_version.h"

const static_field cdr_static_fields[] = {
	{ "is_master", "boolean" },
	{ "node_id", "integer" },
	{ "pop_id", "integer" },
	{ "attempt_num", "integer" },
	{ "is_last", "boolean" },
	{ "legA_transport_protocol_id", "smallint" },
	{ "legA_local_ip", "inet" },
	{ "legA_local_port", "integer" },
	{ "legA_remote_ip", "inet" },
	{ "legA_remote_port", "integer" },
	{ "legB_transport_protocol_id", "smallint" },
	{ "legB_local_ip", "inet" },
	{ "legB_local_port", "integer" },
	{ "legB_remote_ip", "inet" },
	{ "legB_remote_port", "integer" },
	{ "time_data", "varchar" }, //timers values serialized to json
	{ "early_media_present", "boolean" },
	{ "disconnect_code", "integer" },
	{ "disconnect_reason", "varchar" },
	{ "disconnect_initiator", "integer" },
	{ "disconnect_intermediate_code", "integer" },
	{ "disconnect_intermediate_reason", "varchar" },
	{ "disconnect_rewrited_code", "integer" },
	{ "disconnect_rewrited_reason", "varchar" },
	{ "orig_call_id", "varchar" },
	{ "term_call_id", "varchar" },
	{ "local_tag", "varchar" },
	{ "msg_logger_path", "varchar" },
	{ "dump_level_id", "integer" },
	{ "audio_record_enabled", "boolean"},
	{ "rtp_stats", "json" }, //stats variables serialized to json
	{ "global_tag", "varchar" },
	{ "resources", "varchar" },
	{ "active_resources", "json" },
	{ "failed_resource_type_id", "smallint" },
	{ "failed_resource_id", "bigint" },
	{ "dtmf_events", "json" },
	{ "versions", "json" },
	{ "is_redirected", "boolean" }
};


CdrWriter::CdrWriter()
{

}

CdrWriter::~CdrWriter()
{

}

int CdrWriter::configure(CdrWriterCfg& cfg)
{
	config=cfg;

	//show all query args
	int param_num = 1;
	//static params
	for(;param_num<=WRITECDR_STATIC_FIELDS_COUNT;param_num++){
		const static_field &sf = cdr_static_fields[param_num-1];
		DBG("CdrWriterArg:     %d: %s : %s [static]",param_num,sf.name,sf.type);
	}

	if(config.serialize_dynamic_fields){
		DBG("CdrWriterArg:     %d: dynamic : json [serialized dynamic fields]:",
			param_num);
	}
	//dynamic params
	DynFieldsT_iterator dit = config.dyn_fields.begin();
	for(;dit!=config.dyn_fields.end();++dit){
		if(config.serialize_dynamic_fields){
			DBG("CdrWriterArg:             dynamic: %s : %s",
				dit->name.c_str(),dit->type_name.c_str());
		} else {
			DBG("CdrWriterArg:     %d: %s : %s [dynamic]",param_num++,
				dit->name.c_str(),dit->type_name.c_str());
		}
	}
	return 0;
}


void CdrWriter::start()
{
	cdrthreadpool_mut.lock();
	DBG("CdrWriter::start: Starting %d async DB threads",config.poolsize);
	for(unsigned int i=0;i<config.poolsize;i++){
		CdrThread* th = new CdrThread;
		th->configure(config);
		th->start();
		cdrthreadpool.push_back(th);
	}
	cdrthreadpool_mut.unlock();
}

void CdrWriter::stop()
{
	DBG("CdrWriter::stop: Begin shutdown cycle");
	cdrthreadpool_mut.lock();
	int len=cdrthreadpool.size();
	for(int i=0;i<len;i++){
		DBG("CdrWriter::stop: Try shutdown thread %d",i);
		CdrThread* th= cdrthreadpool.back();
		cdrthreadpool.pop_back();
		th->stop();
		delete th;
	}
	len=cdrthreadpool.size();
	DBG("CdrWriter::stop: LEN:: %d", len);
	cdrthreadpool_mut.unlock();
}

void CdrWriter::postcdr(Cdr* cdr )
{
	if(cdr->suppress){
		delete cdr;
		return;
	}
	cdrthreadpool_mut.lock();
		cdrthreadpool[cdr->cdr_born_time.tv_usec%cdrthreadpool.size()]->postcdr(cdr);
	cdrthreadpool_mut.unlock();
}

void CdrWriter::getConfig(AmArg &arg){
	AmArg params;

	arg["failover_to_slave"] = config.failover_to_slave;

	int param_num = 1;
	//static params
	for(;param_num<=WRITECDR_STATIC_FIELDS_COUNT;param_num++){
		const static_field &sf = cdr_static_fields[param_num-1];
		params.push(int2str(param_num)+": "+string(sf.name)+" : "+string(sf.type));
	}
	//dynamic params
	DynFieldsT_iterator dit = config.dyn_fields.begin();
	for(;dit!=config.dyn_fields.end();++dit){
		params.push(int2str(param_num++)+": "+dit->name+" : "+dit->type_name);
	}
	arg.push("query_args",params);

	arg["failover_to_file"] = config.failover_to_file;
	if(config.failover_to_file){
		arg["failover_file_dir"] = config.failover_file_dir;
		arg["failover_file_completed_dir"] = config.failover_file_completed_dir;
	}

	arg["master_db"] = config.masterdb.conn_str();
	if(config.failover_to_slave){
		arg["slave_db"] = config.slavedb.conn_str();
	}
}

void CdrWriter::showOpenedFiles(AmArg &arg){
	cdrthreadpool_mut.lock();
	for(vector<CdrThread*>::iterator it = cdrthreadpool.begin();it != cdrthreadpool.end();it++){
		AmArg a;
		(*it)->showOpenedFiles(a);
		if(a.getType()!=AmArg::Undef)
			arg.push(a);
	}
	cdrthreadpool_mut.unlock();
}

void CdrWriter::closeFiles(){
	for(vector<CdrThread*>::iterator it = cdrthreadpool.begin();it != cdrthreadpool.end();it++){
		(*it)->closefile();
	}
}

void CdrWriter::getStats(AmArg &arg){
	AmArg underlying_stats,threads;

	arg["name"] = config.name;
	arg["poolsize"]= (int)config.poolsize;
	cdrthreadpool_mut.lock();
	for(vector<CdrThread*>::iterator it = cdrthreadpool.begin();it != cdrthreadpool.end();it++){
		(*it)->getStats(underlying_stats);
		threads.push(underlying_stats);
		underlying_stats.clear();
	}
	cdrthreadpool_mut.unlock();
	arg.push("threads",threads);
}

void CdrWriter::clearStats(){
	cdrthreadpool_mut.lock();
		for(vector<CdrThread*>::iterator it = cdrthreadpool.begin();it != cdrthreadpool.end();it++)
		(*it)->clearStats();
	cdrthreadpool_mut.unlock();
}

void CdrThread::postcdr(Cdr* cdr)
{
	//DBG("%s[%p](%p)",FUNC_NAME,this,cdr);
	queue_mut.lock();
		//queue.push_back(newcdr);
		queue.push_back(cdr);
		queue_run.set(true);
	queue_mut.unlock();
}


CdrThread::CdrThread() :
	queue_run(false),stopped(false),
	masterconn(NULL),slaveconn(NULL),gotostop(false),
	masteralarm(false),slavealarm(false)
{
	clearStats();
}

CdrThread::~CdrThread()
{
	closefile();
}

void CdrThread::getStats(AmArg &arg){
	queue_mut.lock();
		arg["queue_len"] = (int)queue.size();
	queue_mut.unlock();

	arg["stopped"] = stopped.get();
	arg["queue_run"] = queue_run.get();
	arg["db_exceptions"] = stats.db_exceptions;
	arg["writed_cdrs"] = stats.writed_cdrs;
	arg["tried_cdrs"] = stats.tried_cdrs;
}

void CdrThread::showOpenedFiles(AmArg &arg){
	if(wfp.get()&&wfp->is_open()){
		arg = write_path;
	} else {
		arg = AmArg();
	}
}

void CdrThread::clearStats(){
	stats.db_exceptions = 0;
	stats.writed_cdrs = 0;
	stats.tried_cdrs = 0;
}

int CdrThread::configure(CdrThreadCfg& cfg ){
	config=cfg;
	queue_run.set(false);
	return 0;
}

void CdrThread::on_stop(){
	INFO("Stopping CdrWriter thread");
	gotostop=true;
	queue_run.set(true); // we must switch thread to run state for exit.
	stopped.wait_for();
	if(masterconn){
		DBG("CdrWriter: Disconnect master SQL. Backend pid: %d.",masterconn->backendpid());
		masterconn->disconnect();
	}
	if(slaveconn){
		DBG("CdrWriter: Disconnect slave SQL. Backend pid: %d.",slaveconn->backendpid());
		slaveconn->disconnect();
	}
}

void CdrThread::run(){
	INFO("Starting CdrWriter thread");
	setThreadName("yeti-cdr-wr");
	if(!connectdb()){
		ERROR("can't connect to any DB on startup. give up");
		throw std::logic_error("CdrWriter can't connect to any DB on startup");
	}

	bool db_err = false;

while(true){
	Cdr* cdr;

	//DBG("next cycle");

	bool qrun = queue_run.wait_for_to(config.check_interval);

	if (gotostop){
		stopped.set(true);
		return;
	}

	if(db_err || !qrun){
		//DBG("queue condition wait timeout. check connections");
		//check master conn
		if(masterconn!=NULL){
			try {
				pqxx::work t(*masterconn);
				t.commit();
				db_err = false;
			} catch (const pqxx::pqxx_exception &e) {
				delete masterconn;
				if(!_connectdb(&masterconn,config.masterdb.conn_str(),true)){
					if(!masteralarm){
						ERROR("CdrWriter %p master DB connection failed alarm raised",this);
						masteralarm = true;
						RAISE_ALARM(alarms::CDR_DB_CONN);
					}
				} else {
					INFO("CdrWriter %p master DB connection failed alarm cleared",this);
					masteralarm = false;
					db_err = false;
					CLEAR_ALARM(alarms::CDR_DB_CONN);
				}
			}
		} else {
			if(!_connectdb(&masterconn,config.masterdb.conn_str(),true)){
				if(!masteralarm){
					ERROR("CdrWriter %p master DB connection failed alarm raised",this);
					masteralarm = true;
					RAISE_ALARM(alarms::CDR_DB_CONN);
				}
			} else {
				INFO("CdrWriter %p master DB connection failed alarm cleared",this);
				masteralarm = false;
				CLEAR_ALARM(alarms::CDR_DB_CONN);
			}
		}
		//check slave connecion
		if(!config.failover_to_slave)
			continue;

		if(slaveconn!=NULL){
			try {
				pqxx::work t(*slaveconn);
				t.commit();
				db_err = false;
			} catch (const pqxx::pqxx_exception &e) {
				delete slaveconn;
				if(!_connectdb(&slaveconn,config.slavedb.conn_str(),false)){
					if(!slavealarm){
						ERROR("CdrWriter %p slave DB connection failed alarm raised",this);
						slavealarm = true;
						RAISE_ALARM(alarms::CDR_DB_CONN_SLAVE);
					}
				} else {
					INFO("CdrWriter %p slave DB connection failed alarm cleared",this);
					slavealarm = false;
					db_err = false;
					CLEAR_ALARM(alarms::CDR_DB_CONN_SLAVE);
				}
			}
		} else {
			if(!_connectdb(&slaveconn,config.slavedb.conn_str(),false)){
				if(!slavealarm){
					ERROR("CdrWriter %p slave DB connection failed alarm raised",this);
					slavealarm = true;
					RAISE_ALARM(alarms::CDR_DB_CONN_SLAVE);
				}
			} else {
				INFO("CdrWriter %p slave DB connection failed alarm cleared",this);
				slavealarm = false;
				CLEAR_ALARM(alarms::CDR_DB_CONN_SLAVE);
			}
		}
		//continue;
	}

	//DBG("CdrWriter cycle beginstartup");

	queue_mut.lock();
		if(queue.empty()){
			//DBG("no CDR for write");
			queue_run.set(false);
			queue_mut.unlock();
			continue;
		}

		cdr=queue.front();
		queue.pop_front();

		if(queue.empty()){
			//DBG("CdrWriter cycle stop.Empty queue");
			queue_run.set(false);
		}
	queue_mut.unlock();

	bool cdr_writed = false;
#if 0 //used for tests
	if(0!=writecdrtofile(cdr)){
		ERROR("can't write CDR to file");
	} else {
		//succ writed to file
		DBG("CDR was written into file");
		cdr_writed = true;
	}
#endif
//#if 0
	if(0!=writecdr(masterconn,*cdr)){
		ERROR("Cant write CDR to master database");
		db_err = true;
		if (config.failover_to_slave) {
			DBG("failover_to_slave enabled. try");
			if(!slaveconn || 0!=writecdr(slaveconn,*cdr)){
				db_err = true;
				ERROR("Cant write CDR to slave database");
				if(config.failover_to_file){
					DBG("failover_to_file enabled. try");
					if(0!=writecdrtofile(cdr)){
						ERROR("can't write CDR to file");
					} else {
						//succ writed to file
						DBG("CDR was written into file");
						cdr_writed = true;
					}
				} else {
					DBG("failover_to_file disabled");
				}
			} else {
				//succ writed to slave database
				DBG("CDR was written into slave");
				cdr_writed = true;
				closefile();
			}
		} else {
			DBG("failover_to_slave disabled");
			if(config.failover_to_file){
				DBG("failover_to_file enabled. try");
				if(0!=writecdrtofile(cdr)){
					ERROR("can't write CDR to file");
				} else {
					//succ writed to file
					DBG("CDR was written into file");
					cdr_writed = true;
				}
			} else {
				DBG("failover_to_file disabled");
			}
		}
	} else {
		//succ writed to master database
		DBG("CDR was written into master");
		cdr_writed = true;
		closefile();
	}
//#endif
	if(cdr_writed){
		stats.writed_cdrs++;
		DBG("CDR deleted from queue");
		delete cdr;
	} else {
		if(config.failover_requeue){
			DBG("requeuing is enabled. return CDR into queue");
			queue_mut.lock();
				queue.push_back(cdr);
				//queue_run.set(true);
			queue_mut.unlock();
		} else {
			ERROR("CDR write failed. forget about it");
			delete cdr;
		}
	}
} //while
}

void CdrThread::prepare_queries(pqxx::connection *c){
	PreparedQueriesT_iterator it = config.prepared_queries.begin();
	DynFieldsT_iterator dit;

	c->set_variable("search_path",config.db_schema+", public");

	for(;it!=config.prepared_queries.end();++it){
#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
		pqxx::prepare::declaration d =
#endif
			c->prepare(it->first,it->second.first);
#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
		//static fields
		for(int i = 0;i<WRITECDR_STATIC_FIELDS_COUNT;i++){
			//d("varchar",pqxx::prepare::treat_direct);
			d(cdr_static_fields[i].type,pqxx::prepare::treat_direct);
		}
		//dynamic fields
		if(!config.serialize_dynamic_fields){
			dit = config.dyn_fields.begin();
			for(;dit!=config.dyn_fields.end();++dit){
				d(dit->type_name,pqxx::prepare::treat_direct);
			}
		} else {
			d("json",pqxx::prepare::treat_direct);
		}
		//trusted headers
		TrustedHeaders::instance()->invocate(d);
#endif
		c->prepare_now(it->first);
	}
}

int CdrThread::_connectdb(cdr_writer_connection **conn,string conn_str,bool master){
	cdr_writer_connection *c = NULL;
	int ret = 0;
	try{
		c = new cdr_writer_connection(conn_str,master);
		if (c->is_open()){
			prepare_queries(c);
			INFO("CdrWriter: SQL connected. Backend pid: %d.",c->backendpid());
			ret = 1;
		}
	} catch(const pqxx::broken_connection &e){
			ERROR("CdrWriter: SQL connection exception: %s",e.what());
		delete c;
	} catch(const pqxx::undefined_function &e){
		ERROR("CdrWriter: SQL connection: undefined_function query: %s, what: %s",e.query().c_str(),e.what());
		c->disconnect();
		delete c;
		throw std::runtime_error("CdrThread exception");
	} catch(pqxx::failure &e) {
		ERROR("catched pqxx::failure: %s",e.what());
	} catch(std::exception &e) {
		ERROR("catched std::exception: %s",e.what());
	} catch(...) {
		ERROR("catched unknown exception");
	}
	*conn = c;
	return ret;
}

int CdrThread::connectdb(){
	int ret;
	ret = _connectdb(&masterconn,config.masterdb.conn_str(),true);
	if(config.failover_to_slave){
		ret|=_connectdb(&slaveconn,config.slavedb.conn_str(),false);
	}
	return ret;
}

void CdrThread::dbg_writecdr(AmArg &fields_values,Cdr &cdr){
	int k = 0;
	//static fields
	if(fields_values.size() < WRITECDR_STATIC_FIELDS_COUNT) {
		DBG("exception happened before static fields invocation completed. skip values output");
		return;
	}
	for(int j = 0;j<WRITECDR_STATIC_FIELDS_COUNT;j++,k++){
		AmArg &a = fields_values.get(k);
		const static_field &f = cdr_static_fields[j];
		ERROR("%d: %s[%s] -> %s[%s]",
			k,f.name,f.type,
			AmArg::print(a).c_str(),
			a.t2str(a.getType()));
	}
	//dynamic fields
	const size_t n = cdr.dyn_fields.size();
	const size_t m = config.dyn_fields.size();
	if(m!=n){
		ERROR("mismatched count of configured and actually gained dynamic fields."
			  "cfg: %ld, actually: %ld",m,n);
		return;
	}
	DynFieldsT_const_iterator it = config.dyn_fields.begin();
	for(int j = 0;it!=config.dyn_fields.end();++it,++j,++k){
		const DynField &f = *it;
		AmArg &a = cdr.dyn_fields[f.name];
		ERROR("%d: %s[%s] -> %s[%s]",
			k,f.name.c_str(),f.type_name.c_str(),
			AmArg::print(a).c_str(),
			a.t2str(a.getType()));
	}

	//TrustedHeaders::instance()->print_hdrs(cdr.trusted_hdrs);
}

int CdrThread::writecdr(cdr_writer_connection* conn, Cdr& cdr){
#define invoc_field(field_value)\
	fields_values.push(AmArg(field_value));\
	invoc(field_value);

	DBG("%s[%p](conn = %p,cdr = %p)",FUNC_NAME,this,conn,&cdr);
	int ret = 1;

	Yeti::global_config &gc = Yeti::instance().config;
	AmArg fields_values;

	if(conn==NULL){
		ERROR("writecdr() we got NULL connection pointer.");
		return 1;
	}

	fields_values.assertArray();

	//TrustedHeaders::instance()->print_hdrs(cdr->trusted_hdrs);

	stats.tried_cdrs++;
	try{
		pqxx::result r;
		pqxx::nontransaction tnx(*conn);
		if(!tnx.prepared("writecdr").exists()){
			ERROR("have no prepared SQL statement");
			return 1;
		}

		pqxx::prepare::invocation invoc = tnx.prepared("writecdr");

		invoc_field(conn->isMaster());
		invoc_field(gc.node_id);
		invoc_field(gc.pop_id);

		cdr.invoc(invoc,fields_values,config.dyn_fields,
				  config.serialize_dynamic_fields);

		r = invoc.exec();
		if (r.size()!=0&&0==r[0][0].as<int>()){
			ret = 0;
		}

		//dbg_writecdr(fields_values,cdr);
	} catch(const pqxx::pqxx_exception &e){
		DBG("SQL exception on CdrWriter thread: %s",e.base().what());
		dbg_writecdr(fields_values,cdr);
		conn->disconnect();
		stats.db_exceptions++;
	}
	return ret;
#undef invoc_field
}

bool CdrThread::openfile(){
	if(wfp.get()&&wfp->is_open()){
		return true;
	} else {
		wfp.reset(new ofstream());
		ostringstream filename;
		char buf[80];
		time_t nowtime;
		struct tm timeinfo;

		time(&nowtime);
		localtime_r (&nowtime,&timeinfo);
		strftime (buf,80,"%G%m%d_%H%M%S",&timeinfo);
		filename << "/" << std::dec << buf << "_" << std::dec << this << ".csv";
		write_path = config.failover_file_dir+filename.str();
		completed_path = config.failover_file_completed_dir+filename.str();
		wfp->open(write_path.c_str(), std::ofstream::out | std::ofstream::trunc);
		if(!wfp->is_open()){
			ERROR("can't open '%s'. skip writing",write_path.c_str());
			return false;
		}
		DBG("write cdr file header");
		write_header();
		return true;
	}
	return false;
}

void CdrThread::closefile(){
	if(!wfp.get())
		return;
	wfp->flush();
	wfp->close();
	wfp.reset();
	if(0==rename(write_path.c_str(),completed_path.c_str())){
		ERROR("moved from '%s' to '%s'",write_path.c_str(),completed_path.c_str());
	} else {
		ERROR("can't move file from '%s' to '%s'",write_path.c_str(),completed_path.c_str());
	}
}

void CdrThread::write_header(){
	ofstream &wf = *wfp.get();
	TrustedHeaders &th = *TrustedHeaders::instance();
		//write description header
	wf << "#version: " << YETI_VERSION << endl;
	wf << "#static_fields_count: " << WRITECDR_STATIC_FIELDS_COUNT << endl;
	wf << "#dynamic_fields_count: " << config.dyn_fields.size() << endl;
	wf << "#trusted_hdrs_count: " << th.count() << endl;

		//static fields names
	wf << "#fields_descr: ";
	for(int i = 0;i<WRITECDR_STATIC_FIELDS_COUNT;i++){
		if(i) wf << ",";
		wf << "'" << cdr_static_fields[i].name << "'";
	}

		//dynamic fields names
	DynFieldsT_iterator dit = config.dyn_fields.begin();
	for(;dit!=config.dyn_fields.end();++dit){
		wf << ",'"<< dit->name << "'";
	}

		//trusted headers names
	th.print_csv(wf);

	wf << endl;
	wf.flush();
}

int CdrThread::writecdrtofile(Cdr* cdr){
#define quote(v) "'"<<v<< "'" << ','
	if(!openfile()){
		return -1;
	}
	ofstream &s = *wfp.get();
	Yeti::global_config &gc = Yeti::instance().config;

	s << std::dec <<
	quote(gc.node_id) <<
	quote(gc.pop_id);

	cdr->to_csv_stream(s,config.dyn_fields);

	s << endl;
	s.flush();
	stats.writed_cdrs++;
	return 0;
#undef quote
}

int CdrThreadCfg::cfg2CdrThCfg(AmConfigReader& cfg, string& prefix){
	string suffix="master"+prefix;
	string cdr_file_dir = prefix+"_dir";
	string cdr_file_completed_dir = prefix+"_completed_dir";

	serialize_dynamic_fields = cfg.getParameterInt("serialize_dynamic_fields",0);
	failover_requeue = cfg.getParameterInt("failover_requeue",0);

	failover_to_file = cfg.getParameterInt("failover_to_file",1);
	if(failover_to_file){
		if(!cfg.hasParameter(cdr_file_dir)){
			ERROR("missed '%s'' parameter",cdr_file_dir.c_str());
			return -1;
		}
		if(!cfg.hasParameter(cdr_file_completed_dir)){
			ERROR("missed '%s'' parameter",cdr_file_completed_dir.c_str());
			return -1;
		}
		failover_file_dir = cfg.getParameter(cdr_file_dir);
		failover_file_completed_dir = cfg.getParameter(cdr_file_completed_dir);

		//check for permissions
		ofstream t1;
		ostringstream dir_test_file;
		dir_test_file << failover_file_dir << "/test";
		t1.open(dir_test_file.str().c_str(),std::ofstream::out | std::ofstream::trunc);
		if(!t1.is_open()){
			ERROR("can't write test file in '%s' directory",failover_file_dir.c_str());
			return -1;
		}
		remove(dir_test_file.str().c_str());

		ofstream t2;
		ostringstream completed_dir_test_file;
		completed_dir_test_file << failover_file_completed_dir << "/test";
		t2.open(completed_dir_test_file.str().c_str(),std::ofstream::out | std::ofstream::trunc);
		if(!t2.is_open()){
			ERROR("can't write test file in '%s' directory",failover_file_completed_dir.c_str());
			return -1;
		}
		remove(completed_dir_test_file.str().c_str());
	}

	masterdb.cfg2dbcfg(cfg,suffix);
	suffix="slave"+prefix;
	slavedb.cfg2dbcfg(cfg,suffix);

	return 0;
}

int CdrWriterCfg::cfg2CdrWrCfg(AmConfigReader& cfg){
	poolsize=cfg.getParameterInt(name+"_pool_size",10);
	check_interval = cfg.getParameterInt("cdr_check_interval",5000);
	failover_to_slave = cfg.getParameterInt("cdr_failover_to_slave",1);
	serialize_dynamic_fields = cfg.getParameterInt("serialize_dynamic_fields",0);
	return cfg2CdrThCfg(cfg,name);
}
