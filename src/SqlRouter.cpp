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
#include "cfg/yeti_opts.h"
#include "cdr/AuthCdr.h"
#include "jsonArg.h"
#include "cdr/CdrWriter.h"
#include <botan/base64.h>
#include "format_helper.h"
#include "AmSession.h"
#include "AmEventDispatcher.h"

#include "ampi/PostgreSqlAPI.h"

#define GET_VARIABLE(var)                                                                                              \
    if (!cfg.hasParameter(#var)) {                                                                                     \
        ERROR("missed parameter '" #var "'");                                                                          \
        return 1;                                                                                                      \
    }                                                                                                                  \
    var = cfg.getParameter(#var);

const static_field profile_static_fields[] = {
    {              "node_id",  "integer" },
    {               "pop_id",  "integer" },
    {          "protocol_id", "smallint" },
    {            "remote_ip",     "inet" },
    {          "remote_port",  "integer" },
    {             "local_ip",     "inet" },
    {           "local_port",  "integer" },
    {             "from_dsp",  "varchar" },
    {            "from_name",  "varchar" },
    {          "from_domain",  "varchar" },
    {            "from_port",  "integer" },
    {              "to_name",  "varchar" },
    {            "to_domain",  "varchar" },
    {              "to_port",  "integer" },
    {         "contact_name",  "varchar" },
    {       "contact_domain",  "varchar" },
    {         "contact_port",  "integer" },
    {             "uri_name",  "varchar" },
    {           "uri_domain",  "varchar" },
    {              "auth_id",  "integer" },
    {             "identity",     "json" },

    // on enabled 'routing.pass_input_interface_name'
    { "input_interface_name",  "varchar" },
    {                nullptr,    nullptr }
};

size_t profile_static_fields_count = 21;

static AmArg cfg_routing_headers;
int          add_routing_header(cfg_t          */*cfg*/, cfg_opt_t          */*opt*/, int argc, const char **argv)
{
    if (argc < 1 || argc > 4) {
        ERROR("expected format: header(header_name[, sql_type = varchar, [format[, format_param]]])");
        return 1;
    }

    cfg_routing_headers.push({
        { "varname", argv[0] }
    });

    auto &a = cfg_routing_headers.back();

    if (argc > 1) {
        a["vartype"] = argv[1];
        if (argc > 2) {
            cfg_routing_headers.back()["varformat"] = argv[2];
            if (argc > 3) {
                cfg_routing_headers.back()["varparam"] = argv[3];
            }
        }
    } else {
        a["vartype"] = "varchar";
    }

    return 0;
}

struct SqlPlaceHolderArgs {
    size_t n;
    SqlPlaceHolderArgs(size_t n)
        : n(n)
    {
    }
};
std::ostream &operator<<(std::ostream &out, const SqlPlaceHolderArgs &args)
{
    out << "($1";
    for (size_t i = 2; i <= args.n; i++)
        out << ",$" << i;
    out << ");";
    return out;
}


SqlRouter::SqlRouter()
    : Auth()
    , db_hits(stat_group(Counter, "yeti", "router_db_hits").addAtomicCounter())
    , db_hits_time(stat_group(Counter, "yeti", "router_db_hits_time").addAtomicCounter())
    , hits(stat_group(Counter, "yeti", "router_hits").addAtomicCounter())
    , active_requests(stat_group(Gauge, "yeti", "router_db_active_requests").addAtomicCounter())
    , gt_min(0)
    , gt_max(0)
    , gps_max(0)
    , gps_avg(0)
    , mi(5)
    , gpi(0)
{
    time(&mi_start);

    DBG("SqlRouter instance[%p] created", this);

    stat_group(Counter, "yeti", "router_db_hits_time")
        .setHelp("aggregated get_profiles() requests execution time in msec");
}

SqlRouter::~SqlRouter()
{
    DBG("SqlRouter instance[%p] destroyed", this);
}

void SqlRouter::sanitize_query_params(QueryInfo &query_info, const std::string &context_id, const char *context_name,
                                      std::function<const char *(unsigned int)> get_param_name)
{
    for (auto i{ 0u }; i < query_info.params.size(); i++) {
        auto &p = query_info.params[i];
        if (!isArgCStr(p))
            continue;

        // TODO: optimize. avoid string copying
        string param_value{ p.asCStr() };

        if (!fixup_utf8_inplace(param_value))
            continue;

        WARN("[%s] fixup %s field %d(%s): %s > %s", context_id.data(), context_name, i + 1, get_param_name(i),
             Botan::base64_encode(reinterpret_cast<const uint8_t *>(p.asCStr()), std::strlen(p.asCStr())).data(),
             Botan::base64_encode(reinterpret_cast<const uint8_t *>(param_value.data()), param_value.size()).data());

        p = param_value;
    }
}

void SqlRouter::apply_routing_headers(const AmArg &data)
{
    if (isArgUndef(data))
        return;

    assertArgArray(data);
    for (size_t i = 0; i < data.size(); i++) {
        AmArg &a = data.get(i);

        const char *vartype = a["vartype"].asCStr();
        DBG("load_interface_in:     %u: %s : %s", i, a["varname"].asCStr(), vartype);

        used_header_fields.emplace_back(a);

        getprofile_types.push_back(vartype);
    }
}

int SqlRouter::load_db_interface_in_out()
{
    // fill arg types for static fields
    for (unsigned int k = 0; k < profile_static_fields_count; k++)
        getprofile_types.push_back(profile_static_fields[k].type);

    for (const auto &f : auth_log_static_fields)
        auth_log_types.push_back(f.type);

    auto &sync_db = Yeti::instance().sync_db;

    if (sync_db.exec_query(format("SELECT * FROM {}.load_interface_out()", routing_schema), "load_interface_out")) {
        return 1;
    }

    if (!isArgUndef(sync_db.db_reply_result)) {
        assertArgArray(sync_db.db_reply_result);
        for (size_t i = 0; i < sync_db.db_reply_result.size(); i++) {
            AmArg &a = sync_db.db_reply_result.get(i);
            // DBG("%zd %s", i, AmArg::print(a).data());
            const char *vartype = a["vartype"].asCStr();
            const char *varname = a["varname"].asCStr();
            bool        forcdr  = a["forcdr"].asBool();

            DBG("load_interface_out:     %zd: %s : %s, %d", i, varname, vartype, forcdr);
            if (forcdr) {
                dyn_fields.emplace_back(varname, vartype);
            }
        }
    }

    apply_routing_headers(cfg_routing_headers);

    return 0;
}

int SqlRouter::configure(cfg_t *confuse_cfg, AmConfigReader &cfg)
{
    std::ostringstream sql;

    cfg_t *routing_sec = cfg_getsec(confuse_cfg, section_name_routing);
    if (!routing_sec) {
        ERROR("missed 'router' section in module config");
        return 1;
    }

    cfg_t *cdr_sec = cfg_getsec(confuse_cfg, section_name_cdr);
    if (!cdr_sec) {
        ERROR("missed 'cdr' section in module config");
        return 1;
    }

    if (0 != auth_init()) {
        ERROR("failed to initialize uas auth");
        return 1;
    }

    auto &ycfg = Yeti::instance().config;

    routing_schema = ycfg.routing_schema;
    GET_VARIABLE(routing_function);

    GET_VARIABLE(writecdr_schema);
    GET_VARIABLE(writecdr_function);
    authlog_function = cfg.getParameter("authlog_function", "write_auth_log");

    failover_to_slave         = cfg.getParameterInt("failover_to_slave", 0);
    connection_lifetime       = cfg_getint(routing_sec, opt_name_connection_lifetime);
    pass_input_interface_name = cfg_getbool(routing_sec, opt_name_pass_input_interface_name);

    if (pass_input_interface_name) {
        // enable 'input_interface_name' field
        profile_static_fields_count++;
    }

    new_codec_groups  = cfg_getbool(routing_sec, opt_name_new_codec_groups);
    lega_gw_cache_key = cfg_getstr(routing_sec, opt_name_lega_gw_cache_key);
    legb_gw_cache_key = cfg_getstr(routing_sec, opt_name_legb_gw_cache_key);

    cfg_t *auth_sec = cfg_getsec(confuse_cfg, section_name_auth);
    if (!auth_sec || 0 == auth_configure(auth_sec)) {
        DBG3("SqlRouter::auth_configure: config successfuly read");
        ycfg.auth_default_realm_header = getDefaultRealmHeader();
    } else {
        ERROR("SqlRouter::auth_configure: config read error");
        return 1;
    }

    PgConnectionPoolCfg masterpoolcfg("master");
    if (0 != masterpoolcfg.cfg2PgCfg(cfg)) {
        ERROR("Master pool config loading error");
        return 1;
    }

    PGPool master_routing_pool(masterpoolcfg.dbconfig.host, masterpoolcfg.dbconfig.port, masterpoolcfg.dbconfig.name,
                               masterpoolcfg.dbconfig.user, masterpoolcfg.dbconfig.pass);
    master_routing_pool.pool_size = masterpoolcfg.size;
    master_routing_pool.keepalives_interval =
        masterpoolcfg.dbconfig.keepalives_interval.value_or(PG_DEFAULT_KEEPALIVES_INTERVAL);

    // add master routing worker pool
    if (!AmEventDispatcher::instance()->post(
            POSTGRESQL_QUEUE,
            new PGWorkerPoolCreate(yeti_routing_pg_worker, PGWorkerPoolCreate::Master, master_routing_pool)))
    {
        ERROR("missed required postgresql module");
        return 1;
    }

    if (1 == failover_to_slave) {
        PgConnectionPoolCfg slavepoolcfg("slave");
        if (0 != slavepoolcfg.cfg2PgCfg(cfg)) {
            WARN("Failover to slave enabled but slave config is wrong. Disabling failover");
            failover_to_slave = 0;
        }

        PGPool slave_routing_pool(slavepoolcfg.dbconfig.host, slavepoolcfg.dbconfig.port, slavepoolcfg.dbconfig.name,
                                  slavepoolcfg.dbconfig.user, slavepoolcfg.dbconfig.pass);
        slave_routing_pool.pool_size = slavepoolcfg.size;
        slave_routing_pool.keepalives_interval =
            slavepoolcfg.dbconfig.keepalives_interval.value_or(PG_DEFAULT_KEEPALIVES_INTERVAL);

        // add slave routing worker pool
        if (!AmEventDispatcher::instance()->post(
                POSTGRESQL_QUEUE,
                new PGWorkerPoolCreate(yeti_routing_pg_worker, PGWorkerPoolCreate::Slave, slave_routing_pool)))
        {
            ERROR("failed to post routing slave pool event");
            return 1;
        }
    }

    // modify/apply prepared queries here
    if (0 == load_db_interface_in_out()) {
        DBG("SqlRouter::load_db_interface_in_out: finished");
    } else {
        ERROR("SqlRouter::load_db_interface_in_out: error");
        return 1;
    }

    PGWorkerConfig *pg_config_routing =
        new PGWorkerConfig(yeti_routing_pg_worker, failover_to_slave, false, /*retransmit_enable*/
                           false,                                            /* use pipeline */
                           masterpoolcfg.statement_timeout ? masterpoolcfg.statement_timeout
                                                           : PG_DEFAULT_WAIT_TIME, /* transaction timeout */
                           0 /* retransmit_interval */, masterpoolcfg.check_interval /* reconnect_interval */);

    pg_config_routing->connection_lifetime = connection_lifetime;
    pg_config_routing->addSearchPath(routing_schema);
    pg_config_routing->addSearchPath("public");

    // prepare routing getprofile
    sql.str("");
    sql << "SELECT * FROM " << routing_function << SqlPlaceHolderArgs(getprofile_types.size());
    auto &getprofile_prepared     = pg_config_routing->addPrepared(getprofile_sql_statement_name, sql.str());
    getprofile_prepared.sql_types = getprofile_types;

    // prepare/execute routing connection init query
    auto routing_init_function = cfg.getParameter("routing_init_function");
    if (!routing_init_function.empty()) {
        sql.str("");
        sql << "SELECT " << routing_init_function << SqlPlaceHolderArgs(2);
        pg_config_routing->addInitialQuery(
            PGParamExecute(PGQueryData(yeti_routing_pg_worker, sql.str(), false /* single */), PGTransactionData(),
                           false /* prepared */));

        std::get<PGParamExecute>(pg_config_routing->initial_queries.back())
            .addParam(AmConfig.node_id)
            .addParam(Yeti::instance().config.pop_id);
    }

    AmEventDispatcher::instance()->post(POSTGRESQL_QUEUE, pg_config_routing);

    // create CDR DB worker
    CdrThreadCfg cdr_cfg;
    if (cdr_cfg.cfg2CdrThCfg(cdr_sec, cfg)) {
        INFO("Cdr writer pool config loading error");
        return 1;
    }

    PGPool cdr_db_master_pool(cdr_cfg.masterdb.host, cdr_cfg.masterdb.port, cdr_cfg.masterdb.name,
                              cdr_cfg.masterdb.user, cdr_cfg.masterdb.pass);
    cdr_db_master_pool.pool_size = cdr_cfg.pool_size;
    cdr_db_master_pool.keepalives_interval =
        cdr_cfg.masterdb.keepalives_interval.value_or(PG_DEFAULT_KEEPALIVES_INTERVAL);

    AmEventDispatcher::instance()->post(
        POSTGRESQL_QUEUE, new PGWorkerPoolCreate(yeti_cdr_pg_worker, PGWorkerPoolCreate::Master, cdr_db_master_pool));

    if (cdr_cfg.failover_to_slave) {
        PGPool cdr_db_slave_pool(cdr_cfg.slavedb.host, cdr_cfg.slavedb.port, cdr_cfg.slavedb.name, cdr_cfg.slavedb.user,
                                 cdr_cfg.slavedb.pass);
        cdr_db_slave_pool.pool_size = cdr_cfg.pool_size;
        cdr_db_slave_pool.keepalives_interval =
            cdr_cfg.slavedb.keepalives_interval.value_or(PG_DEFAULT_KEEPALIVES_INTERVAL);

        AmEventDispatcher::instance()->post(
            POSTGRESQL_QUEUE, new PGWorkerPoolCreate(yeti_cdr_pg_worker, PGWorkerPoolCreate::Slave, cdr_db_slave_pool));
    }

    // configure CDR DB worker
    PGWorkerConfig *pg_config_cdr_writer =
        new PGWorkerConfig(yeti_cdr_pg_worker, cdr_cfg.failover_to_slave, true, /*retransmit_enable*/
                           false,                                               /* use pipeline */
                           0, // PG_DEFAULT_WAIT_TIME, /* transaction timeout */
                           cdr_cfg.retry_interval /* retransmit_interval */,
                           cdr_cfg.check_interval /* reconnect_interval */, cdr_cfg.batch_size, /* batch_size */
                           cdr_cfg.batch_timeout /* batch timeout */, 0 /* max_queue_length */,
                           cdr_cfg.connection_lifetime /* connection_lifetime*/);
    pg_config_cdr_writer->addSearchPath(writecdr_schema);
    pg_config_cdr_writer->addSearchPath("public");

    PreparedQueryArgs cdr_types;
    int               n = WRITECDR_STATIC_FIELDS_COUNT;
    if (ycfg.write_internal_disconnect_code) {
        n++;
        // shift all fields after the disconnect_rewrited_reason
        for (int i = WRITECDR_STATIC_FIELDS_COUNT; i > 25 /* disconnect_rewrited_reason pos */; i--) {
            cdr_static_fields[i].name = cdr_static_fields[i - 1].name;
            cdr_static_fields[i].type = cdr_static_fields[i - 1].type;
        }
        // patch 26 entry
        cdr_static_fields[26].name = "disconnect_code_id";
        cdr_static_fields[26].type = "smallint";
    }
    if (ycfg.bleg_cdr_headers.enabled()) {
        n++;
        std::string i_aleg_cdr_headers("i_aleg_cdr_headers");

        auto idx = std::distance(
            cdr_static_fields,
            std::find_if(cdr_static_fields, cdr_static_fields + WRITECDR_STATIC_FIELDS_COUNT,
                         [&i_aleg_cdr_headers](const static_field &f) { return i_aleg_cdr_headers == f.name; }));
        // shift all fields after the i_aleg_cdr_headers
        for (int i = n - 1; i > idx /* i_aleg_cdr_headers pos */; i--) {
            cdr_static_fields[i].name = cdr_static_fields[i - 1].name;
            cdr_static_fields[i].type = cdr_static_fields[i - 1].type;
        }
        idx++;
        cdr_static_fields[idx].name = "i_bleg_cdr_headers";
        cdr_static_fields[idx].type = "json";
    }
    for (int i = 0; i < n; i++)
        cdr_types.push_back(cdr_static_fields[i].type);

    sql.str("");
    sql << "SELECT " << writecdr_function << SqlPlaceHolderArgs(cdr_types.size());

    auto &cdr_prepared     = pg_config_cdr_writer->addPrepared(cdr_statement_name, sql.str());
    cdr_prepared.sql_types = cdr_types;

    AmEventDispatcher::instance()->post(POSTGRESQL_QUEUE, pg_config_cdr_writer);

    // create AuthLog DB workers
    if (cfg_t *cdr_section = cfg_getsec(confuse_cfg, "cdr")) {
        // reuse cdr_cfg for auth_log workers
        if (cfg_size(cdr_section, "auth_pool_size"))
            cdr_db_master_pool.pool_size = cdr_cfg.pool_size = cfg_getint(cdr_section, "auth_pool_size");
        if (cfg_size(cdr_section, "auth_batch_size"))
            cdr_cfg.batch_size = cfg_getint(cdr_section, "auth_batch_size");
        if (cfg_size(cdr_section, "auth_batch_timeout"))
            cdr_cfg.batch_timeout = cfg_getint(cdr_section, "auth_batch_timeout") / 1000;
    }

    AmEventDispatcher::instance()->post(
        POSTGRESQL_QUEUE,
        new PGWorkerPoolCreate(yeti_auth_log_pg_worker, PGWorkerPoolCreate::Master, cdr_db_master_pool));

    if (cdr_cfg.failover_to_slave) {
        PGPool auth_db_slave_pool(cdr_cfg.slavedb.host, cdr_cfg.slavedb.port, cdr_cfg.slavedb.name,
                                  cdr_cfg.slavedb.user, cdr_cfg.slavedb.pass);
        auth_db_slave_pool.pool_size = cdr_cfg.pool_size;
        auth_db_slave_pool.keepalives_interval =
            cdr_cfg.slavedb.keepalives_interval.value_or(PG_DEFAULT_KEEPALIVES_INTERVAL);

        AmEventDispatcher::instance()->post(
            POSTGRESQL_QUEUE,
            new PGWorkerPoolCreate(yeti_auth_log_pg_worker, PGWorkerPoolCreate::Slave, auth_db_slave_pool));
    }

    // configure AuthLog DB worker
    PGWorkerConfig *pg_config_auth_log =
        new PGWorkerConfig(yeti_auth_log_pg_worker, cdr_cfg.failover_to_slave, true, /*retransmit_enable*/
                           false,                                                    /* use pipeline */
                           0, // PG_DEFAULT_WAIT_TIME, /* transaction timeout */
                           cdr_cfg.retry_interval /* retransmit_interval */,
                           cdr_cfg.check_interval /* reconnect_interval */, cdr_cfg.batch_size, /* batch_size */
                           cdr_cfg.batch_timeout /* batch timeout */, 0 /* max_queue_length */,
                           cdr_cfg.connection_lifetime /* connection lifetime */);
    pg_config_auth_log->addSearchPath(writecdr_schema);
    pg_config_auth_log->addSearchPath("public");

    sql.str("");
    sql << "SELECT " << authlog_function << SqlPlaceHolderArgs(auth_log_types.size());

    auto &auth_log_prepared     = pg_config_auth_log->addPrepared(auth_log_statement_name, sql.str());
    auth_log_prepared.sql_types = auth_log_types;

    AmEventDispatcher::instance()->post(POSTGRESQL_QUEUE, pg_config_auth_log);

    return 0;
}

void SqlRouter::update_counters(struct timeval &start_time)
{
    struct timeval now_time, diff_time;
    int            intervals;
    double         diff, gps;

    gettimeofday(&now_time, NULL);

    db_hits.inc();

    // per second
    diff      = difftime(now_time.tv_sec, mi_start);
    intervals = diff / mi;
    if (intervals > 0) {
        mi_start = now_time.tv_sec;
        gps      = gpi / (double)mi;
        gps_avg  = gps;
        if (gps > gps_max)
            gps_max = gps;
        gpi = 1;
    } else {
        gpi++;
    }

    // took
    timersub(&now_time, &start_time, &diff_time);
    diff = timeval2double(diff_time);
    if (diff > gt_max)
        gt_max = diff;
    if (!gt_min || (diff < gt_min))
        gt_min = diff;

    db_hits_time.inc(diff_time.tv_sec + diff_time.tv_usec / 1000);
}

AmArg SqlRouter::db_async_get_profiles(const std::string &local_tag, const AmSipRequest &req,
                                       Auth::auth_id_type auth_id, const AmArg *identity_data)
{
    AmArg ret;

    hits.inc();

    std::unique_ptr<PGParamExecute> pg_getprofile_event;
    pg_getprofile_event.reset(new PGParamExecute(PGQueryData(yeti_routing_pg_worker,        /* pg worker name */
                                                             getprofile_sql_statement_name, /* prepared stmt name */
                                                             false /*single*/, local_tag /* session_id */),
                                                 PGTransactionData(), true /* prepared */));

    auto &query_info = pg_getprofile_event.get()->qdata.info[0];

#define invoc_field(field_value) query_info.addParam(field_value);

#define invoc_typed_field(type, field_value) query_info.addTypedParam(type, field_value);

#define invoc_null() query_info.addParam(AmArg());

    auto &gc = Yeti::instance().config;

    const char  *sptr;
    sip_nameaddr na;
    sip_uri      from_uri, to_uri, contact_uri;

    sptr = req.to.c_str();
    if (parse_nameaddr(&na, &sptr, req.to.length()) < 0 || parse_uri(&to_uri, na.addr.s, na.addr.len) < 0) {
        throw GetProfileException(FC_PARSE_TO_FAILED, false);
    }

    sptr = req.contact.c_str();
    if (parse_nameaddr(&na, &sptr, req.contact.length()) < 0 || parse_uri(&contact_uri, na.addr.s, na.addr.len) < 0) {
        throw GetProfileException(FC_PARSE_CONTACT_FAILED, false);
    }

    sptr = req.from.c_str();
    na.name.clear();
    if (parse_nameaddr(&na, &sptr, req.from.length()) < 0 || parse_uri(&from_uri, na.addr.s, na.addr.len) < 0) {
        throw GetProfileException(FC_PARSE_FROM_FAILED, false);
    }

    string from_name = c2stlstr(na.name);
    from_name.erase(std::remove(from_name.begin(), from_name.end(), '"'), from_name.end());

    invoc_field(AmConfig.node_id);                        //"node_id", "integer"
    invoc_field(gc.pop_id);                               //"pop_id", "integer"
    invoc_typed_field("smallint", (int)req.transport_id); //"transport_id", "smallint"
    invoc_field(req.remote_ip);                           //"remote_ip", "inet"
    invoc_field(req.remote_port);                         //"remote_port", "integer"
    invoc_field(req.local_ip);                            //"local_ip", "inet"
    invoc_field(req.local_port);                          //"local_port", "integer"
    invoc_field(from_name);                               //"from_dsp", "varchar"
    invoc_field(c2stlstr(from_uri.user));                 //"from_name", "varchar"
    invoc_field(c2stlstr(from_uri.host));                 //"from_domain", "varchar"
    invoc_field(from_uri.port);                           //"from_port", "integer"
    invoc_field(c2stlstr(to_uri.user));                   //"to_name", "varchar"
    invoc_field(c2stlstr(to_uri.host));                   //"to_domain", "varchar"
    invoc_field(to_uri.port);                             //"to_port", "integer"
    invoc_field(c2stlstr(contact_uri.user));              //"contact_name", "varchar"
    invoc_field(c2stlstr(contact_uri.host));              //"contact_domain", "varchar"
    invoc_field(contact_uri.port);                        //"contact_port", "integer"
    invoc_field(req.user);                                //"uri_name", "varchar"
    invoc_field(req.domain);                              //"uri_domain", "varchar"

    if (auth_id != 0) {
        invoc_field(auth_id)
    } else {
        invoc_null();
    }

    if (identity_data) {
        string identity_data_str(arg2json(*identity_data));
        invoc_field(identity_data_str);
    } else {
        invoc_null();
    }

    if (pass_input_interface_name) {
        invoc_field(AmConfig.sip_ifs[req.local_if].name);
    }

    // invoc headers from sip request
    for (const auto &h : used_header_fields) {
        auto value = h.getValue(req).value_or(AmArg());
        invoc_field(value);
    }

#undef invoc_field

    sanitize_query_params(query_info, local_tag, "Routing", [this](auto i) {
        return i < profile_static_fields_count ? profile_static_fields[i].name
                                               : used_header_fields[i - profile_static_fields_count].getName().data();
    });

    if (gc.postgresql_debug) {
        for (unsigned int i = 0; i < query_info.params.size(); i++) {
            DBG("%s/getprofile %d(%s/%s): %s %s", local_tag.data(), i + 1,
                i < profile_static_fields_count ? profile_static_fields[i].name
                                                : used_header_fields[i - profile_static_fields_count].getName().data(),
                getprofile_types[i].data(), AmArg::t2str(query_info.params[i].getType()),
                AmArg::print(query_info.params[i]).data());
        }
    }

    if (!AmEventDispatcher::instance()->post(POSTGRESQL_QUEUE, pg_getprofile_event.release())) {
        ERROR("failed to post getprofile query event");
        return 1;
    }

    return ret;
}

void SqlRouter::align_cdr(Cdr &cdr)
{
    DynFieldsT_iterator it = dyn_fields.begin();
    for (; it != dyn_fields.end(); ++it) {
        cdr.dyn_fields[it->name] = AmArg();
    }
}

void SqlRouter::write_cdr(std::unique_ptr<Cdr> &cdr, bool last)
{
    DBG3("%s(%p) last = %d", FUNC_NAME, cdr.get(), last);
    if (!cdr)
        return;
    if (!cdr->writed) {
        cdr->writed  = true;
        cdr->is_last = last;

        std::unique_ptr<PGParamExecute> pg_param_execute_event;
        pg_param_execute_event.reset(
            new PGParamExecute(PGQueryData(yeti_cdr_pg_worker, /* pg worker name */
                                           cdr_statement_name, /* prepared stmt name */
                                           false /*single*/),
                               PGTransactionData(PGTransactionData::isolation_level::read_committed,
                                                 PGTransactionData::write_policy::read_write),
                               true /* prepared */));
        cdr->apply_params(pg_param_execute_event.get()->qdata.info.front(), dyn_fields);

        auto &query_info = pg_param_execute_event->qdata.info.front();

        sanitize_query_params(query_info, cdr->local_tag, "CDR", [](auto i) { return cdr_static_fields[i].name; });

        if (Yeti::instance().config.postgresql_debug) {
            for (unsigned int i = 0; i < query_info.params.size(); i++) {
                DBG("%s/cdr %d(%s/%s): %s %s", cdr->local_tag.data(), i + 1, cdr_static_fields[i].name,
                    cdr_static_fields[i].type, AmArg::t2str(query_info.params[i].getType()),
                    AmArg::print(query_info.params[i]).data());
            }
        }

        cdr.reset();

        AmEventDispatcher::instance()->post(POSTGRESQL_QUEUE, pg_param_execute_event.release());
        // cdr_writer->postcdr(cdr);
    } else {
        DBG("%s(%p) trying to write already written cdr", FUNC_NAME, cdr.get());
    }
}

void SqlRouter::write_auth_log(const AuthCdr &auth_log)
{
    std::unique_ptr<PGParamExecute> pg_param_execute_event;
    pg_param_execute_event.reset(
        new PGParamExecute(PGQueryData(yeti_auth_log_pg_worker, /* pg worker name */
                                       auth_log_statement_name, /* prepared stmt name */
                                       false /*single*/),
                           PGTransactionData(PGTransactionData::isolation_level::read_committed,
                                             PGTransactionData::write_policy::read_write),
                           true /* prepared */));

    auth_log.apply_params(pg_param_execute_event.get()->qdata.info.front());

    auto &query_info = pg_param_execute_event->qdata.info.front();

    sanitize_query_params(query_info, auth_log.getOrigCallId(), "AUTH_LOG",
                          [](auto i) { return auth_log_static_fields[i].name; });

    if (Yeti::instance().config.postgresql_debug) {
        for (unsigned int i = 0; i < query_info.params.size(); i++) {
            DBG("%p/auth_log %d(%s/%s): %s %s", &auth_log, i + 1, auth_log_static_fields[i].name,
                auth_log_types[i].data(), AmArg::t2str(query_info.params[i].getType()),
                AmArg::print(query_info.params[i]).data());
        }
    }

    AmEventDispatcher::instance()->post(POSTGRESQL_QUEUE, pg_param_execute_event.release());
}

void SqlRouter::log_auth(const AmSipRequest &req, bool success, AmArg &ret, int auth_feedback_code,
                         Auth::auth_id_type auth_id)
{
    write_auth_log(
        AuthCdr(req, success, ret[0].asInt(), ret[1].asCStr(), ret[3].asCStr(), auth_feedback_code, auth_id));
}

void SqlRouter::send_and_log_auth_challenge(const AmSipRequest &req, const OriginationPreAuth::Reply &ip_auth_data,
                                            const string &internal_reason, int auth_feedback_code, const string &hdrs,
                                            bool post_auth_log)
{
    Auth::send_auth_challenge(req, hdrs, ip_auth_data);
    if (post_auth_log) {
        write_auth_log(AuthCdr(req, false, 401, "Unauthorized", internal_reason, auth_feedback_code, 0));
    }
}

void SqlRouter::dump_config() {}

void SqlRouter::getConfig(AmArg &arg)
{
    AmArg u;
    // arg["config_db"] = dbc.conn_str();
    arg["failover_to_slave"]   = failover_to_slave;
    arg["connection_lifetime"] = connection_lifetime;

    arg["routing_schema"]    = routing_schema;
    arg["routing_function"]  = routing_function;
    arg["writecdr_function"] = writecdr_function;
    arg["writecdr_schema"]   = writecdr_schema;

    vector<UsedHeaderField>::const_iterator fit = used_header_fields.begin();
    for (; fit != used_header_fields.end(); ++fit) {
        AmArg hf;
        fit->getInfo(hf);
        u.push(hf);
    }
    arg.push("sipreq_header_fields", u);
    u.clear();

    DynFieldsT_iterator dit = dyn_fields.begin();
    for (; dit != dyn_fields.end(); ++dit) {
        u.push(dit->name + " : " + dit->type_name);
    }
    arg.push("dyn_fields", u);
    u.clear();
}

void SqlRouter::getStats(AmArg &arg)
{
    /* SqlRouter stats */
    arg["gt_min"]  = gt_min;
    arg["gt_max"]  = gt_max;
    arg["gps_max"] = gps_max;
    arg["gps_avg"] = gps_avg;

    arg["hits"]    = static_cast<unsigned int>(hits.get());
    arg["db_hits"] = static_cast<unsigned int>(db_hits.get());
}

static void assertEndCRLF(string &s)
{
    if (s[s.size() - 2] != '\r' || s[s.size() - 1] != '\n') {
        while ((s[s.size() - 1] == '\r') || (s[s.size() - 1] == '\n'))
            s.erase(s.size() - 1);
        s += "\r\n";
    }
}

bool SqlRouter::check_and_refuse(SqlCallProfile *profile, Cdr *cdr, const AmSipRequest &req, ParamReplacerCtx &ctx,
                                 bool send_reply)
{
    bool         need_reply;
    bool         write_cdr;
    unsigned int internal_code, response_code;
    string       internal_reason, response_reason;

    if (profile->disconnect_code_id == 0)
        return false;

    write_cdr =
        CodesTranslator::instance()->translate_db_code(profile->disconnect_code_id, internal_code, internal_reason,
                                                       response_code, response_reason, profile->aleg_override_id);
    need_reply = (response_code != NO_REPLY_DISCONNECT_CODE);

    if (write_cdr) {
        cdr->update_internal_reason(DisconnectByDB, internal_reason, internal_code, profile->disconnect_code_id);
        cdr->update_aleg_reason(response_reason, response_code);
    } else {
        cdr->setSuppress(true);
    }
    if (send_reply && need_reply) {
        if (write_cdr) {
            cdr->update_with_aleg_sip_request(req);
            cdr->update_sbc(*profile);
        }
        // prepare & send sip response
        string hdrs = ctx.replaceParameters(profile->append_headers, "append_headers", req);
        if (hdrs.size() > 2)
            assertEndCRLF(hdrs);
        AmSipDialog::reply_error(req, response_code, response_reason, hdrs);
    }
    return true;
}
