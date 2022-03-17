#include "AmPlugIn.h"
#include "AmUtils.h"
#include "log.h"
#include "AmArg.h"
#include "AmLcConfig.h"
#include "SBCCallControlAPI.h"
#include <string.h>
#include <syslog.h>
#include <exception>
#include <algorithm>
#include "SBCCallProfile.h"
#include "sip/parse_nameaddr.h"
#include "sip/parse_uri.h"
#include "db/PgConnectionPool.h"
#include "SqlRouter.h"
#include "db/DbTypes.h"
#include "yeti.h"
#include "cdr/AuthCdr.h"
#include "jsonArg.h"

#include "AmSession.h"

#define GET_VARIABLE(var)\
    if(!cfg.hasParameter(#var)){\
        ERROR("missed parameter '"#var"'");\
        return 1;\
    }\
    var = cfg.getParameter(#var);

const static_field profile_static_fields[] = {
    { "node_id", "integer" },
    { "pop_id", "integer" },
    { "protocol_id", "smallint" },
    { "remote_ip", "inet" },
    { "remote_port", "integer" },
    { "local_ip", "inet" },
    { "local_port", "integer" },
    { "from_dsp", "varchar" },
    { "from_name", "varchar" },
    { "from_domain", "varchar" },
    { "from_port", "integer" },
    { "to_name", "varchar" },
    { "to_domain", "varchar" },
    { "to_port", "integer" },
    { "contact_name", "varchar" },
    { "contact_domain", "varchar" },
    { "contact_port", "integer" },
    { "uri_name", "varchar" },
    { "uri_domain", "varchar" },
    { "auth_id", "integer" },
    { "identity", "json" }
};

SqlRouter::SqlRouter()
  : Auth(),
    db_hits(stat_group(Counter, "yeti", "router_db_hits").addAtomicCounter()),
    db_hits_time(stat_group(Counter, "yeti", "router_db_hits_time").addAtomicCounter()),
    hits(stat_group(Counter, "yeti", "router_hits").addAtomicCounter()),
    active_requests(stat_group(Gauge, "yeti", "router_db_active_requests").addAtomicCounter()),
    gt_min(0), gt_max(0),
    gps_max(0), gps_avg(0),
    mi(5),
    gpi(0),
    master_pool(nullptr),
    slave_pool(nullptr),
    cdr_writer(nullptr)
{
    time(&mi_start);

    INFO("SqlRouter instance[%p] created",this);

    stat_group(Counter, "yeti", "router_db_hits_time").setHelp(
        "aggregated get_profiles() requests execution time in msec");
}

SqlRouter::~SqlRouter()
{
  
  if (master_pool)
    delete master_pool;
  
  if (slave_pool)
    delete slave_pool;
  
  if (cdr_writer)
    delete cdr_writer;

  INFO("SqlRouter instance[%p] destroyed",this);
}

void SqlRouter::stop()
{
  DBG("SqlRouter::stop()");
  if(master_pool)
    master_pool->stop();
  if(slave_pool)
    slave_pool->stop();
  if(cdr_writer)
    cdr_writer->stop();
}

int SqlRouter::start()
{
    master_pool->start();
    WARN("Master SQLThread started\n");
    if (1==failover_to_slave) {
        slave_pool->start();
        WARN("Slave SQLThread started\n");
    }
    cdr_writer->start();
    return 0;
};

int SqlRouter::db_configure(AmConfigReader& cfg){
	int ret = 1;
try {
	int n;
	PreparedQueryArgs profile_types,cdr_types,auth_log_types;
		//load config from db
	string sql_query,prefix("master");
	dbc.cfg2dbcfg(cfg,prefix);

	//fill arg types for static fields
	for(int k = 0;k<GETPROFILE_STATIC_FIELDS_COUNT;k++)
		profile_types.push_back(profile_static_fields[k].type);

	for(int k = 0;k<WRITECDR_STATIC_FIELDS_COUNT;k++)
		cdr_types.push_back(cdr_static_fields[k].type);
	/*if(Yeti::instance().config.aleg_cdr_headers.enabled()) {
		//aleg_cdr_headers
		cdr_types.push_back("json");
	}*/

	for(const auto &f : auth_log_static_fields)
		auth_log_types.push_back(f.type);

	/*for(int k = 0;k<TrustedHeaders::instance()->count();k++)
		cdr_types.push_back("varchar");*/

	pqxx::connection c(dbc.conn_str());
	c.set_variable("search_path",routing_schema+", public");
	{
		pqxx::nontransaction t(c);
		pqxx::result r = t.exec("SELECT * from load_interface_out()");
		for(pqxx::row_size_type i = 0; i < r.size();++i){
			const pqxx::row &t = r[i];
			const char *vartype = t["vartype"].c_str();
			const char *varname = t["varname"].c_str();
			DBG("load_interface_out:     %u: %s : %s, %s",i,
				varname,vartype,t["forcdr"].c_str());
			if(true==t["forcdr"].as<bool>()) {
				dyn_fields.push_back(DynField(varname,vartype));
			}
		}
	}

	{
		pqxx::nontransaction t(c);
		pqxx::result r = t.exec("SELECT * from load_interface_in()");
		for(pqxx::row_size_type i = 0; i < r.size();++i){
			const pqxx::row &t = r[i];
			const char *vartype = t["vartype"].c_str();
			DBG("load_interface_in:     %u: %s : %s",i,
				t["varname"].c_str(),vartype);
			used_header_fields.push_back(UsedHeaderField(t));
			profile_types.push_back(vartype);
			auth_log_types.push_back(vartype);
		}
	}

	{
		pqxx::nontransaction t(c);
		if(0!=auth_init(cfg,t)) {
			ERROR("failed to initialize uas auth");
			return 1;
		}
	}

	c.disconnect();

	/*{PreparedQueryArgs_iterator i = profile_types.begin();
	while(i!=profile_types.end()){
		ERROR("profile_types: %s",i->c_str());
		++i;
	}}
	{PreparedQueryArgs_iterator i = cdr_types.begin();
	while(i!=cdr_types.end()){
		ERROR("cdr_types: %s",i->c_str());
		++i;
	}}*/

		//apply them
	sql_query = "SELECT * FROM "+routing_function+"($1";
		//n = GETPROFILE_STATIC_FIELDS_COUNT+used_header_fields.size();
		n = profile_types.size();
		for(int i = 2;i<=n;i++) sql_query.append(",$"+int2str(i));
		sql_query.append(");");
	prepared_queries["getprofile"] = pair<string,PreparedQueryArgs>(sql_query,profile_types);

	sql_query = "SELECT "+writecdr_function+"($1";
		//n = WRITECDR_STATIC_FIELDS_COUNT+dyn_fields.size();
		n =  cdr_types.size();
		for(int i = 2;i<=n;i++) sql_query.append(",$"+int2str(i));
		sql_query.append(");");
	cdr_prepared_queries["writecdr"] = pair<string,PreparedQueryArgs>(sql_query,cdr_types);


	sql_query = "SELECT "+authlog_function+"($1";
		n =  auth_log_types.size();
		for(int i = 2;i<=n;i++) sql_query.append(",$"+int2str(i));
		sql_query.append(");");
	cdr_prepared_queries[auth_sql_statement_name] = pair<string,PreparedQueryArgs>(sql_query,cdr_types);

	ret = 0;

} catch(const pqxx::pqxx_exception &e){
	ERROR("SqlRouter::db_configure: pqxx_exception: %s ",e.base().what());
}
	return ret;
}

int SqlRouter::configure(cfg_t *confuse_cfg, AmConfigReader &cfg){
    PgConnectionPoolCfg masterpoolcfg,slavepoolcfg;

    routing_schema = Yeti::instance().config.routing_schema;
    GET_VARIABLE(routing_function);

    GET_VARIABLE(writecdr_schema);
    GET_VARIABLE(writecdr_function);
    authlog_function = cfg.getParameter("authlog_function","write_auth_log");

    if(0==db_configure(cfg)){
        INFO("SqlRouter::db_configure: config successfuly readed");
    } else {
        INFO("SqlRouter::db_configure: config read error");
        return 1;
    }

    cdr_writer = new CdrWriter();
    auto &cdrconfig = cdr_writer->getConfig();
    cdrconfig.prepared_queries = cdr_prepared_queries;
    cdrconfig.dyn_fields  = dyn_fields;
    cdrconfig.db_schema = writecdr_schema;
    cdrconfig.used_header_fields = used_header_fields;

    if (cdr_writer->configure(confuse_cfg, cfg)) {
        ERROR("Cdr writer pool configuration error.");
        return 1;
    }

    masterpoolcfg.name="master";
    if(0==masterpoolcfg.cfg2PgCfg(cfg)) {
        masterpoolcfg.prepared_queries = prepared_queries;
        INFO("Master pool config loaded");
    } else {
        ERROR("Master pool config loading error");
        return 1;
    }
    failover_to_slave=cfg.hasParameter("failover_to_slave") ? cfg.getParameterInt("failover_to_slave") : 0;

    if (1==failover_to_slave) {
        slavepoolcfg.name="slave";
        if (0==slavepoolcfg.cfg2PgCfg(cfg)) {
            slavepoolcfg.prepared_queries = prepared_queries;
            INFO("Slave pool config loaded");
        } else{
            WARN("Failover to slave enabled but slave config is wrong. Disabling failover");
            failover_to_slave=0;
        }
    }

    master_pool= new PgConnectionPool;
    master_pool->set_config(masterpoolcfg);
    master_pool->add_connections(masterpoolcfg.size);
    master_pool->dump_config();
    WARN("Master SQLThread configured\n");
    if (1==failover_to_slave){
        slave_pool= new PgConnectionPool(true);
        slave_pool->set_config(slavepoolcfg);
        slave_pool->add_connections(slavepoolcfg.size);
        slave_pool->dump_config();
        WARN("Slave SQLThread configured\n");
    } else {
        WARN("Slave SQLThread disabled\n");
    }

    return 0;
}

void SqlRouter::update_counters(struct timeval &start_time){
    struct timeval now_time,diff_time;
    int intervals;
    double diff,gps;

    gettimeofday(&now_time,NULL);

    //per second
    diff = difftime(now_time.tv_sec,mi_start);
    intervals = diff/mi;
    if(intervals > 0){
        mi_start = now_time.tv_sec;
        gps = gpi/(double)mi;
        gps_avg = gps;
        if(gps > gps_max)
            gps_max = gps;
        gpi = 1;
    } else {
       gpi++;
    }

    // took
    timersub(&now_time,&start_time,&diff_time);
    diff = timeval2double(diff_time);
    if(diff > gt_max)
        gt_max = diff;
    if(!gt_min || (diff < gt_min))
        gt_min = diff;

    db_hits_time.inc(diff_time.tv_sec + diff_time.tv_usec/1000);
}

void SqlRouter::getprofiles(
	const AmSipRequest &req,CallCtx &ctx,
	Auth::auth_id_type auth_id, AmArg *identity_data)
{
	PgConnection *conn = NULL;
	PgConnectionPool *pool = master_pool;
	bool getprofile_fail = true;
	int refuse_code = 0xffff;
	struct timeval start_time;

	DBG("Lookup profile for request: \n %s",req.print().c_str());

	UsageCounterHelper u(active_requests);

	hits.inc();
	gettimeofday(&start_time,NULL);

	while (getprofile_fail&&pool) {
	try {
		conn = pool->getActiveConnection();
		if(conn!=NULL){
			_getprofiles(ctx.profiles,req,conn,auth_id,identity_data);
			pool->returnConnection(conn);
			getprofile_fail = false;
		} else {
			DBG("Cant get active connection on %s",pool->pool_name.c_str());
			refuse_code = FC_GET_ACTIVE_CONNECTION;
		}
	} catch(GetProfileException &e){
		DBG("GetProfile exception on %s SQLThread: fatal = %d code  = '%d'",
			pool->pool_name.c_str(),
			e.fatal,e.code);
		refuse_code = e.code;
		if(e.fatal){
			pool->returnConnection(conn,PgConnectionPool::CONN_COMM_ERR);
		} else {
			pool->returnConnection(conn);
		}
	}

	if(getprofile_fail&&pool == master_pool&&1==failover_to_slave) {
		ERROR("SQL failover enabled. Trying slave connection");
		pool = slave_pool;
	} else {
		pool = NULL;
	}

	} //while

	if(getprofile_fail){
		ERROR("SQL cant get profiles. Drop request");
		ctx.profiles.clear();
		ctx.profiles.emplace_back();
		ctx.profiles.back().disconnect_code_id = refuse_code;
		ctx.SQLexception = true;
	} else {
		update_counters(start_time);
		db_hits.inc();
	}
	return;
}

void SqlRouter::_getprofiles(
	list<SqlCallProfile> &profiles,
	const AmSipRequest &req,
	pqxx::connection* conn,
	Auth::auth_id_type auth_id,
	AmArg *identity_data)
{
#define invoc_field(field_value)\
	fields_values.push(AmArg(field_value));\
	invoc(field_value);

	pqxx::result r;
	pqxx::nontransaction tnx(*conn);
	auto &gc = Yeti::instance().config;
	AmArg fields_values;

	const char *sptr;
	sip_nameaddr na;
	sip_uri from_uri,to_uri,contact_uri;

	fields_values.assertArray();

	sptr = req.to.c_str();
	if(	parse_nameaddr(&na,&sptr,req.to.length()) < 0 ||
		parse_uri(&to_uri,na.addr.s,na.addr.len) < 0){
		throw GetProfileException(FC_PARSE_TO_FAILED,false);
	}
	sptr = req.contact.c_str();
	if(	parse_nameaddr(&na,&sptr,req.contact.length()) < 0 ||
		parse_uri(&contact_uri,na.addr.s,na.addr.len) < 0){
		throw GetProfileException(FC_PARSE_CONTACT_FAILED,false);
	}
	sptr = req.from.c_str();
	if(	parse_nameaddr(&na,&sptr,req.from.length()) < 0 ||
		parse_uri(&from_uri,na.addr.s,na.addr.len) < 0){
		throw GetProfileException(FC_PARSE_FROM_FAILED,false);
	}

	string from_name = c2stlstr(na.name);
	from_name.erase(std::remove(from_name.begin(), from_name.end(), '"'),from_name.end());
	if(fixup_utf8_inplace(from_name))
		WARN("From display name contained at least one invalid utf8 sequence. wrong bytes erased");

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	pqxx::prepare::invocation invoc = tnx.prepared("getprofile");
#pragma GCC diagnostic pop

	if(!invoc.exists())
		throw GetProfileException(FC_NOT_PREPARED,true);

	//DBG("trsp: %s",trsp.c_str());
	//req.tt.get_trans()

	invoc_field(AmConfig.node_id);			//"node_id", "integer"
	invoc_field(gc.pop_id);					//"pop_id", "integer"
	invoc_field((int)req.transport_id);		//"proto_id", "smallint"
	invoc_field(req.remote_ip);				//"remote_ip", "inet"
	invoc_field(req.remote_port);			//"remote_port", "integer"
	invoc_field(req.local_ip);				//"local_ip", "inet"
	invoc_field(req.local_port);			//"local_port", "integer"
	invoc_field(from_name);					//"from_dsp", "varchar"
	invoc_field(c2stlstr(from_uri.user));	//"from_name", "varchar"
	invoc_field(c2stlstr(from_uri.host));	//"from_domain", "varchar"
	invoc_field(from_uri.port);				//"from_port", "integer"
	invoc_field(c2stlstr(to_uri.user));		//"to_name", "varchar"
	invoc_field(c2stlstr(to_uri.host));		//"to_domain", "varchar"
	invoc_field(to_uri.port);				//"to_port", "integer"
	invoc_field(c2stlstr(contact_uri.user));//"contact_name", "varchar"
	invoc_field(c2stlstr(contact_uri.host));//"contact_domain", "varchar"
	invoc_field(contact_uri.port);			//"contact_port", "integer"
	invoc_field(req.user);					//"uri_name", "varchar"
	invoc_field(req.domain);				//"uri_domain", "varchar"

	if(auth_id!=0) { invoc_field(auth_id) }
	else { invoc_field(); }

	if(identity_data) {
		string identity_data_str(arg2json(*identity_data));
		invoc_field(identity_data_str);
	} else {
		invoc_field();
	}

	//invoc headers from sip request
	for(vector<UsedHeaderField>::const_iterator it = used_header_fields.begin();
			it != used_header_fields.end(); ++it){
		string value;
		if(it->getValue(req,value)){
			invoc_field(value);
		} else {
			invoc_field();
		}
	}

	try {
		PROF_START(sql_query);
		r = invoc.exec();
		PROF_END(sql_query);
		PROF_PRINT("SQL routing query",sql_query);
	} catch(pqxx::broken_connection &e){
		ERROR("SQL exception for [%p]: pqxx::broken_connection.",conn);
		dbg_get_profiles(fields_values);
		throw GetProfileException(FC_DB_BROKEN_EXCEPTION,true);
	} catch(pqxx::conversion_error &e){
		ERROR("SQL exception for [%p]: conversion error: %s.",conn,e.what());
		dbg_get_profiles(fields_values);
		throw GetProfileException(FC_DB_CONVERSION_EXCEPTION,true);
	} catch(pqxx::pqxx_exception &e){
		ERROR("SQL exception for [%p]: %s.",conn,e.base().what());
		dbg_get_profiles(fields_values);
		throw GetProfileException(FC_DB_BASE_EXCEPTION,true);
	}
	DBG("%s() database returned %ld profiles",FUNC_NAME,r.size());

	if (r.size()==0)
		throw GetProfileException(FC_DB_EMPTY_RESPONSE,false);

	pqxx::result::const_iterator rit = r.begin();
	for(;rit != r.end();++rit){
		const pqxx::row &t = (*rit);
		if(SqlCallProfile::skip(t)){
			continue;
		}

		profiles.emplace_back();
		SqlCallProfile& profile = profiles.back();

		//read profile
		try{
			if(!profile.readFromTuple(t,dyn_fields)){
				throw GetProfileException(FC_READ_FROM_TUPLE_FAILED,false);
			}
		} catch(pqxx::pqxx_exception &e){
			ERROR("SQL exception while reading from profile tuple: %s.",e.base().what());
			throw GetProfileException(FC_READ_FROM_TUPLE_FAILED,false);
		}

		//evaluate it
		if(!profile.eval()){
			throw GetProfileException(FC_EVALUATION_FAILED,false);
		}
		profile.infoPrint(dyn_fields);
	}

	if(profiles.empty()){
		throw GetProfileException(FC_DB_EMPTY_RESPONSE,false);
	}
#undef invoc_field
}

void SqlRouter::dbg_get_profiles(AmArg &fields_values){
	int k = 0;
	//static fields
	for(int j = 0;j<GETPROFILE_STATIC_FIELDS_COUNT;j++){
		AmArg &a = fields_values.get(k);
		const static_field &f = profile_static_fields[j];
		ERROR("%d: %s[%s] -> %s[%s]",
			k,f.name,f.type,
			AmArg::print(a).c_str(),
			a.t2str(a.getType()));
		k++;
	}
	//dyn fields
	for(vector<UsedHeaderField>::const_iterator it = used_header_fields.begin();
			it != used_header_fields.end(); ++it)
	{
		AmArg &a = fields_values.get(k);
		const UsedHeaderField &f = *it;
		ERROR("%d: %s[%s:%s] -> %s[%s]",
			k,
			f.getName().c_str(),f.type2str(),f.part2str(),
			AmArg::print(a).c_str(),
			a.t2str(a.getType()));
		k++;
	}
}

void SqlRouter::align_cdr(Cdr &cdr){
    DynFieldsT_iterator it = dyn_fields.begin();
    for(;it!=dyn_fields.end();++it){
        cdr.dyn_fields[it->name] = AmArg();
    }
}

void SqlRouter::write_cdr(Cdr* cdr, bool last)
{
  DBG("%s(%p) last = %d",FUNC_NAME,cdr,last);
  if(!cdr->writed) {
    cdr->writed = true;
    cdr->is_last = last;
    cdr_writer->postcdr(cdr);
  } else {
    DBG("%s(%p) trying to write already writed cdr",FUNC_NAME,cdr);
  }
}

void SqlRouter::log_auth(
    const AmSipRequest& req,
    bool success,
    AmArg &ret,
    Auth::auth_id_type auth_id)
{
    cdr_writer->post_auth_log(new AuthCdr(
        req,used_header_fields,
        success,
        ret[0].asInt(), ret[1].asCStr(),ret[3].asCStr(),
        auth_id));
}

void SqlRouter::send_and_log_auth_challenge(
    const AmSipRequest &req,
    const string &internal_reason,
    const string &hdrs)
{
    Auth::send_auth_challenge(req, hdrs);
    cdr_writer->post_auth_log(
        new AuthCdr(
            req,used_header_fields, false,
            401, "Unauthorized", internal_reason, 0));
}

void SqlRouter::dump_config()
{
  master_pool->dump_config();
  slave_pool->dump_config();
}

void SqlRouter::closeCdrFiles(){
	if(cdr_writer)
		cdr_writer->closeFiles();
}

void SqlRouter::getConfig(AmArg &arg){
	AmArg u;
	arg["config_db"] = dbc.conn_str();
	arg["failover_to_slave"] = failover_to_slave;

	if(master_pool){
		master_pool->getConfig(u);
		arg.push("master_pool",u);
		u.clear();
	}

	if(failover_to_slave&&slave_pool){
		slave_pool->getConfig(u);
		arg.push("slave_pool",u);
		u.clear();
	}

	arg["routing_schema"] = routing_schema;
	arg["routing_function"] = routing_function;
	arg["writecdr_function"] = writecdr_function;
	arg["writecdr_schema"] = writecdr_schema;

	vector<UsedHeaderField>::const_iterator fit = used_header_fields.begin();
	for(;fit!=used_header_fields.end();++fit){
		AmArg hf;
		fit->getInfo(hf);
		u.push(hf);
	}
	arg.push("sipreq_header_fields",u);
	u.clear();

	DynFieldsT_iterator dit = dyn_fields.begin();
	for(;dit!=dyn_fields.end();++dit){
		u.push(dit->name + " : "+dit->type_name);
	}
	arg.push("dyn_fields",u);
	u.clear();

	if(cdr_writer){
		cdr_writer->getConfig(u);
		arg.push("cdrwriter",u);
		u.clear();
	}
}

void SqlRouter::showOpenedFiles(AmArg &arg){
	if(cdr_writer){
		cdr_writer->showOpenedFiles(arg);
	}
}

void SqlRouter::showRetryQueues(AmArg &arg)
{
    cdr_writer->showRetryQueues(arg);
}

void SqlRouter::getStats(AmArg &arg)
{
    /* SqlRouter stats */
    arg["gt_min"] = gt_min;
    arg["gt_max"] = gt_max;
    arg["gps_max"] = gps_max;
    arg["gps_avg"] = gps_avg;

    arg["hits"] = static_cast<unsigned int>(hits.get());
    arg["db_hits"] = static_cast<unsigned int>(db_hits.get());

    /* pools stats */
    if(master_pool) {
        master_pool->getStats(arg["master_pool"]);
    }
    if(slave_pool) {
        slave_pool->getStats(arg["slave_pool"]);
    }

    /* cdr writer stats */
    if(cdr_writer) {
        cdr_writer->getStats(arg["cdr_writer"]);
    }
}

static void assertEndCRLF(string& s)
{
  if (s[s.size()-2] != '\r' ||
      s[s.size()-1] != '\n') {
    while ((s[s.size()-1] == '\r') ||
       (s[s.size()-1] == '\n'))
      s.erase(s.size()-1);
    s += "\r\n";
  }
}

bool SqlRouter::check_and_refuse(SqlCallProfile *profile,Cdr *cdr,
                            const AmSipRequest& req,ParamReplacerCtx& ctx,
                            bool send_reply)
{
    bool need_reply;
    bool write_cdr;
    unsigned int internal_code,response_code;
    string internal_reason,response_reason;

    if(profile->disconnect_code_id==0)
        return false;

    write_cdr = CodesTranslator::instance()->translate_db_code(profile->disconnect_code_id,
                             internal_code,internal_reason,
                             response_code,response_reason,
                             profile->aleg_override_id);
    need_reply = (response_code!=NO_REPLY_DISCONNECT_CODE);

    if(write_cdr){
        cdr->update_internal_reason(DisconnectByDB,internal_reason,internal_code);
        cdr->update_aleg_reason(response_reason,response_code);
    } else {
        cdr->setSuppress(true);
    }
    if(send_reply && need_reply){
        if(write_cdr){
            cdr->update_with_sip_request(req, Yeti::instance().config.aleg_cdr_headers);
            cdr->update_sbc(*profile);
        }
        //prepare & send sip response
        string hdrs = ctx.replaceParameters(profile->append_headers, "append_headers", req);
        if (hdrs.size()>2)
            assertEndCRLF(hdrs);
        AmSipDialog::reply_error(req, response_code, response_reason, hdrs);
    }
    return true;
}

void SqlRouter::db_reload_credentials(AmArg &ret)
{
    try {
        pqxx::connection c(dbc.conn_str());
        c.set_variable("search_path",routing_schema+", public");
        pqxx::nontransaction t(c);

        size_t credentials_count;
        reload_credentials(t,credentials_count);

        ret["result"] = "reloaded";
        ret["count"] = credentials_count;

        DBG("auth credentials reloaded");
    } catch(...) {
        ERROR("failed to reload credentials");
        AmSession::Exception(500,"exception");
    }
}
