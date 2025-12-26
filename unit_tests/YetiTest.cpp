#include "YetiTest.h"
#include "../src/yeti.h"
#include "../src/cfg/yeti_opts.h"

#include "AmLcConfig.h"
#include "format_helper.h"

#define redis_conn Yeti::instance().rctl.getRedisConn()

class YetiTestInitialiser {
  protected:
    RedisSettings settings;

  public:
    YetiTestInitialiser()
    {
        DBG("YetiTestInitialiser");
        settings = redis_test::instance()->settings;
    }
};

typedef singleton<YetiTestInitialiser> yeti_init;
static yeti_init                      *yeti_init_global = yeti_init::instance();

YetiTest::YetiTest()
{
    settings = redis_test::instance()->settings;
}

void YetiTest::initResources(ResourceRedisConnection &conn)
{
    vector<vector<AmArg>> args_vec = {
        { "HSET", "r:0:472", AmConfig.node_id, 0 },
        { "HSET", "r:1:472", AmConfig.node_id, 0 },
        { "HSET", "r:2:472", AmConfig.node_id, 0 },
        { "HSET", "r:3:472", AmConfig.node_id, 0 }
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
        { "HDEL", "r:0:472", AmConfig.node_id },
        { "HDEL", "r:1:472", AmConfig.node_id },
        { "HDEL", "r:2:472", AmConfig.node_id },
        { "HDEL", "r:3:472", AmConfig.node_id }
    };

    for (auto args : args_vec) {
        auto req = new CustomTestResourcesRequest(args);
        conn.post_request(req, conn.get_write_conn());
        ASSERT_TRUE(req->wait_finish(3000));
    }
}

int YetiTest::configure_run_redis_connection(ResourceRedisConnection                  &conn,
                                             ResourceRedisConnection::Request::cb_func result_cb,
                                             ResourceRedisConnection::Request::cb_func init_cb, int timeout)
{
    auto cfg           = Yeti::instance().confuse_cfg;
    auto cfg_resources = cfg_getsec(cfg, section_name_resources);
    auto redis_write   = cfg_getsec(cfg_resources, "write");
    auto redis_read    = cfg_getsec(cfg_resources, "read");

    cfg_setstr(redis_write, opt_redis_hosts, format("{}:{}", settings.host, settings.port).data());
    cfg_setstr(redis_read, opt_redis_hosts, format("{}:{}", settings.host, settings.port).data());
    if (timeout) {
        cfg_setint(redis_write, opt_redis_timeout, timeout);
        cfg_setint(redis_read, opt_redis_timeout, timeout);
    }

    conn.configure(cfg_resources);

    if (result_cb)
        conn.registerOperationResultCallback(result_cb);

    if (init_cb)
        conn.registerResourcesInitializedCallback(init_cb);

    conn.init();
    conn.start();

    return 0;
}

class YetiTestListener : public testing::EmptyTestEventListener {
  public:
    void OnTestProgramStart(const testing::UnitTest &) override
    {
        while (!Yeti::instance().isAllComponentsInited()) {
            sleep(1);
        }
    }
};
