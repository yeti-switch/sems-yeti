#include "YetiTest.h"
#include "../src/RedisInstance.h"
#include "../src/yeti.h"
#include <hiredis/read.h>

class PolicyFactory;
class TestServer;
extern PolicyFactory* makePolicyFactory(bool test, TestServer* server = 0);
extern void freePolicyFactory();

#define PARAM_EXT_REDIS_NAME     "external"
#define PARAM_REDIS_HOST_NAME    "host"
#define PARAM_REDIS_PORT_NAME    "port"
#define SECTION_REDIS_NAME       "redis"

#define STR_HELPER(x) #x
#define STR_(x) STR_HELPER(x)

#define HOST           "127.0.0.1"
#define PORT           6379

static yeti_test* yeti_global = yeti_test::instance();

YetiTest::YetiTest() {
    server = &yeti_global->server;
}

void YetiTest::SetUp() {
    server->clear();
}

class YetiTestListener : public testing::EmptyTestEventListener
{
public:
    void OnTestProgramStart(const testing::UnitTest&) override
    {
        //while(!Yeti::instance().isAllComponentsInited()) { sleep(1); }

        cfg_opt_t redis[] = {
            CFG_BOOL(PARAM_EXT_REDIS_NAME, cfg_false, CFGF_NONE),
            CFG_STR(PARAM_REDIS_HOST_NAME, HOST, CFGF_NONE),
            CFG_INT(PARAM_REDIS_PORT_NAME, PORT, CFGF_NONE),
            CFG_END()
        };
        cfg_opt_t yeti[] = {
            CFG_SEC(SECTION_REDIS_NAME, redis, CFGF_NONE),
            CFG_END()
        };
        AmArg data = test_config::instance()->configureModule("yeti", yeti);
        YetiTestFactory::RedisSettings& redis_setting = yeti_global->redis;
        redis_setting.external = data[SECTION_REDIS_NAME][PARAM_EXT_REDIS_NAME].asBool();
        redis_setting.host = data[SECTION_REDIS_NAME][PARAM_REDIS_HOST_NAME].asCStr();
        redis_setting.port = data[SECTION_REDIS_NAME][PARAM_REDIS_PORT_NAME].asLong();
        TesterConfig::ConfigParameters config_parameters;
        config_parameters.emplace<string, TesterConfig::parameter_var>(PARAM_EXT_REDIS_NAME "-" SECTION_REDIS_NAME, {.type = TesterConfig::parameter_var::Bool, .u = {&redis_setting.external}});
        config_parameters.emplace<string, TesterConfig::parameter_var>(SECTION_REDIS_NAME "-" PARAM_REDIS_HOST_NAME, {.type = TesterConfig::parameter_var::String, .u = {&redis_setting.host}});
        config_parameters.emplace<string, TesterConfig::parameter_var>(SECTION_REDIS_NAME "-" PARAM_REDIS_PORT_NAME, {.type = TesterConfig::parameter_var::Integer, .u = {&redis_setting.port}});
        test_config::instance()->useCmdModule(config_parameters);

        // redis instance factory
        freeRedisInstance();
        makeRedisInstance(!redis_setting.external, &yeti_global->server);
    }

    void OnTestProgramEnd(const testing::UnitTest&) override
    {
        freeRedisInstance();
        yeti_test::dispose();
    }
};

YetiTestFactory::YetiTestFactory()
{
    AmArg routes;
    routes["vartype"] = "int2";
	routes["varname"] = "two";
	routes["forcdr"] = false;
    pqtest_server.addResponse(string("SELECT * from load_interface_out()"), routes);
    pqtest_server.addResponse(string("SELECT * from load_interface_in()"), routes);

    AmArg restype;
    restype["id"] = 279;
    restype["name"] = "alexey";
    restype["internal_code_id"] = 500;
    restype["action_id"] = 5;
    pqtest_server.addResponse(string("SELECT * from load_resource_types()"), restype);
    freePolicyFactory();
    makePolicyFactory(true, &pqtest_server);

    makeRedisInstance(true);
    testing::UnitTest::GetInstance()->listeners().Append(new YetiTestListener);
}

