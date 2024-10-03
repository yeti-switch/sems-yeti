#include "YetiTest.h"
#include "../src/yeti.h"
#include "../src/cfg/yeti_opts.h"

#include "AmLcConfig.h"
#include "format_helper.h"

#define redis_conn Yeti::instance().rctl.getRedisConn()

class PolicyFactory;
extern PolicyFactory* makePolicyFactory(bool test, TestServer* server = 0);
extern void freePolicyFactory();

class YetiTestInitialiser
{
protected:
    RedisSettings settings;
    RedisTestServer* test_server;

    void initTestServer()
    {
        test_server->response_enabled.set(false);
        test_server->addLoadScriptCommandResponse(invalidate_resources_default_path, invalidate_resources_hash);
        test_server->addLoadScriptCommandResponse(get_all_resources_default_path, get_all_resources_hash);
        test_server->addLoadScriptCommandResponse(check_resources_default_path, check_resources_hash);
        test_server->response_enabled.set(true);
    }
public:
    YetiTestInitialiser()
    {
        DBG("YetiTestInitialiser");
        test_server = &redis_test::instance()->test_server;
        settings = redis_test::instance()->settings;
        initTestServer();
    }
};

typedef singleton<YetiTestInitialiser> yeti_init;
static yeti_init* yeti_init_global = yeti_init::instance();
static yeti_test* yeti_test_global = yeti_test::instance();

YetiTest::YetiTest()
{
    test_server = &redis_test::instance()->test_server;
    settings = redis_test::instance()->settings;
}

void YetiTest::SetUp()
{
    test_server->response_enabled.set(false);
    test_server->clear();
    test_server->addLoadScriptCommandResponse(redis_conn.get_script_path(INVALIDATE_RESOURCES_SCRIPT), invalidate_resources_hash);
    test_server->addLoadScriptCommandResponse(redis_conn.get_script_path(GET_ALL_RESOURCES_SCRIPT), get_all_resources_hash);
    test_server->addLoadScriptCommandResponse(redis_conn.get_script_path(CHECK_RESOURCES_SCRIPT), check_resources_hash);
    test_server->response_enabled.set(true);
}

void YetiTest::initResources(ResourceRedisConnection &conn)
{
    vector<vector<AmArg>> args_vec = {
        {"HSET", "r:0:472", AmConfig.node_id, 0},
        {"HSET", "r:1:472", AmConfig.node_id, 0},
        {"HSET", "r:2:472", AmConfig.node_id, 0},
        {"HSET", "r:3:472", AmConfig.node_id, 0}
    };

    for (auto args : args_vec) {
        auto req = new CustomTestResourcesRequest(args);
        conn.post_request(req, conn.get_write_conn());
        ASSERT_TRUE(req->wait_finish(3000));
    }
}

void YetiTest::cleanResources(ResourceRedisConnection &conn)
{
    vector<vector<AmArg>> args_vec = {
        {"HDEL", "r:0:472", AmConfig.node_id},
        {"HDEL", "r:1:472", AmConfig.node_id},
        {"HDEL", "r:2:472", AmConfig.node_id},
        {"HDEL", "r:3:472", AmConfig.node_id}
    };

    for (auto args : args_vec) {
        auto req = new CustomTestResourcesRequest(args);
        conn.post_request(req, conn.get_write_conn());
        ASSERT_TRUE(req->wait_finish(3000));
    }
}

int YetiTest::configure_run_redis_connection(
    ResourceRedisConnection &conn,
    ResourceRedisConnection::Request::cb_func result_cb,
    ResourceRedisConnection::Request::cb_func init_cb,
    int timeout)
{
    auto cfg = Yeti::instance().confuse_cfg;
    auto cfg_resources = cfg_getsec(cfg, section_name_resources);
    auto redis_write = cfg_getsec(cfg_resources, "write");
    auto redis_read = cfg_getsec(cfg_resources, "read");

    cfg_setstr(redis_write, opt_redis_hosts, format("{}:{}", settings.host, settings.port).data());
    cfg_setstr(redis_read, opt_redis_hosts, format("{}:{}", settings.host, settings.port).data());
    if(timeout) {
        cfg_setint(redis_write, opt_redis_timeout, timeout);
        cfg_setint(redis_read, opt_redis_timeout, timeout);
    }

    auto resources_sec = cfg_getsec(Yeti::instance().confuse_cfg, section_name_resources);
    conn.configure(resources_sec);

    if(result_cb)
        conn.registerOperationResultCallback(result_cb);

    if(init_cb)
        conn.registerResourcesInitializedCallback(init_cb);

    conn.init();
    conn.start();

    return 0;
}

class YetiTestListener : public testing::EmptyTestEventListener
{
public:
    void OnTestProgramStart(const testing::UnitTest&) override
    {
        while(!Yeti::instance().isAllComponentsInited()) { sleep(1); }
    }

    void OnTestProgramEnd(const testing::UnitTest&) override
    {
        yeti_test::dispose();
    }
};

YetiTestFactory::YetiTestFactory()
{
    AmArg routes;
    routes["vartype"] = "int2";
    routes["varname"] = "two";
    routes["forcdr"] = false;
    pqtest_server.addResponse(string("SELECT * FROM load_interface_out()"), routes);
    pqtest_server.addResponse(string("SELECT * FROM load_interface_in()"), routes);

    AmArg restype;
    restype["id"] = 279;
    restype["name"] = "alexey";
    restype["internal_code_id"] = 500;
    restype["action_id"] = 5;
    pqtest_server.addResponse(string("SELECT * FROM load_resource_types()"), restype);
    freePolicyFactory();
    makePolicyFactory(true, &pqtest_server);

    testing::UnitTest::GetInstance()->listeners().Append(new YetiTestListener);
}

