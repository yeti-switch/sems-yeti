#include "YetiTest.h"
#include "../src/RedisConnection.h"
#include "../src/resources/ResourceControl.h"
#include "../src/resources/ResourceRedisConnection.h"
#include "../src/cfg/yeti_opts.h"

static AmCondition<bool> inited(false);
static void InitCallback() {
    inited.set(true);
}

static cfg_t *init_confuse_cfg()
{
    cfg_t *cfg = cfg_init(yeti_opts, CFGF_NONE);
    return cfg;
}

static cfg_t *confuse_cfg = init_confuse_cfg();

static int configure_run_redis_connection(
    ResourceRedisConnection &conn,
    ResourceRedisConnection::cb_op_func* result_cb = nullptr,
    ResourceRedisConnection::cb_func* init_cb = nullptr,
    int timeout = DEFAULT_REDIS_TIMEOUT_MSEC)
{
    AmConfigReader cfg;
    cfg.setParameter("write_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("write_redis_port", int2str(yeti_test::instance()->redis.port));
    cfg.setParameter("read_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("read_redis_port", int2str(yeti_test::instance()->redis.port));
    if(timeout) {
        cfg.setParameter("read_redis_timeout", int2str(timeout));
        cfg.setParameter("write_redis_timeout", int2str(timeout));
    }

    conn.configure(confuse_cfg, cfg);

    if(result_cb)
        conn.registerResourcesInitializedCallback(init_cb);

    if(result_cb)
        conn.registerOperationResultCallback(result_cb);

    conn.init();
    conn.start();

    return 0;

}

TEST_F(YetiTest, ResourceInit)
{
    ResourceRedisConnection conn("resourceTest");
    configure_run_redis_connection(conn, nullptr, InitCallback);

    time_t time_ = time(0);
    while(!conn.get_write_conn()->wait_connected() &&
          !conn.get_read_conn()->wait_connected() &&
          !inited.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    conn.stop(true);
}

static AmCondition<bool> getPutSuccess(false);
static void GetPutCallback(bool success) {
    getPutSuccess.set(success);
}

TEST_F(YetiTest, ResourceGetPut)
{
    ResourceRedisConnection conn("resourceTest");
    configure_run_redis_connection(conn, GetPutCallback);

    time_t time_ = time(0);
    while(!conn.get_write_conn()->wait_connected() &&
          !conn.get_read_conn()->wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    server->addCommandResponse("MULTI", REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponse("HINCRBY r:0:472 1 2", REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponse("HINCRBY r:1:472 1 2", REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponse("EXEC", REDIS_REPLY_ARRAY, AmArg());

    ResourcesOperationList operations;
    auto &res_op = operations.emplace_back(ResourcesOperation::RES_GET);
    res_op.resources.parse("0:472:100:2;1:472:100:2");
    for(auto& res: res_op.resources) {
        res.active = true;
    }

    OperationResources *op = new OperationResources(&conn, std::move(operations), false);
    op->perform();

    time_ = time(0);
    while(!getPutSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }
    conn.stop(true);
}

TEST_F(YetiTest, ResourceCheck)
{
    ResourceRedisConnection conn("resourceTest");
    configure_run_redis_connection(conn);

    time_t time_ = time(0);
    while(!conn.get_write_conn()->wait_connected() &&
          !conn.get_read_conn()->wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    ResourceList rl;
    rl.parse("0:472:100:2;1:472:100:2");
    CheckResources *cr = new CheckResources(&conn, rl);
    cr->perform();

    time_ = time(0);
    while(!cr->wait_finish(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }
    AmArg result = cr->get_result();
    ASSERT_TRUE(isArgArray(result));
    ASSERT_EQ(result.size(), size_t{2});
    delete cr;

    conn.stop(true);
}

static AmCondition<bool> getAllSuccess(false);
static AmArg getAllResult;
static void GetAllCallback(bool is_error, const AmArg& result) {
    getAllSuccess.set(!is_error);
    getAllResult = result;
}

static bool isArgNumber(const AmArg& arg)
{
    return isArgInt(arg) || isArgLongLong(arg) || isArgDouble(arg);
}

TEST_F(YetiTest, ResourceGetAll)
{
    ResourceRedisConnection conn("resourceTest");
    configure_run_redis_connection(conn);

    time_t time_ = time(0);
    while(!conn.get_write_conn()->wait_connected() &&
          !conn.get_read_conn()->wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    server->addCommandResponse("HGETALL r:0:472", REDIS_REPLY_ARRAY, "1");
    server->addCommandResponse("HGETALL r:0:472", REDIS_REPLY_ARRAY, "0");

    GetAllResources *res = new GetAllResources(&conn, GetAllCallback, 0, 472);
    res->perform();

    time_ = time(0);
    while(!getAllSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }
    ASSERT_TRUE(isArgStruct(getAllResult));
    ASSERT_TRUE(isArgNumber(getAllResult["1"]));
    ASSERT_EQ(getAllResult["1"].asInt(), 0);

    server->addCommandResponse("HGETALL r:0:472", REDIS_REPLY_ARRAY, "1");
    server->addCommandResponse("HGETALL r:0:472", REDIS_REPLY_ARRAY, "0");
    server->addCommandResponse("HGETALL r:1:472", REDIS_REPLY_ARRAY, "1");
    server->addCommandResponse("HGETALL r:1:472", REDIS_REPLY_ARRAY, "0");
    server->addCommandResponse("KEYS r:*:472", REDIS_REPLY_ARRAY, "r:1:472");
    server->addCommandResponse("KEYS r:*:472", REDIS_REPLY_ARRAY, "r:0:472");

    res = new GetAllResources(&conn, GetAllCallback, ANY_VALUE, 472);
    res->perform();

    getAllSuccess.set(false);
    time_ = time(0);
    while(!getAllSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }
    ASSERT_TRUE(isArgStruct(getAllResult));
    ASSERT_TRUE(isArgStruct(getAllResult["r:0:472"]));
    ASSERT_TRUE(isArgNumber(getAllResult["r:0:472"]["1"]));
    ASSERT_TRUE(isArgStruct(getAllResult["r:1:472"]));
    ASSERT_TRUE(isArgNumber(getAllResult["r:1:472"]["1"]));
    ASSERT_EQ(getAllResult["r:0:472"]["1"].asInt(), 0);
    ASSERT_EQ(getAllResult["r:1:472"]["1"].asInt(), 0);

    server->addCommandResponse("HGETALL r:0:472", REDIS_REPLY_ARRAY, "1");
    server->addCommandResponse("HGETALL r:0:472", REDIS_REPLY_ARRAY, "0");
    server->addCommandResponse("KEYS r:0:*", REDIS_REPLY_ARRAY, "r:0:472");

    res = new GetAllResources(&conn, GetAllCallback, 0, ANY_VALUE);
    res->perform();

    getAllSuccess.set(false);
    time_ = time(0);
    while(!getAllSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }
    ASSERT_TRUE(isArgStruct(getAllResult));
    ASSERT_TRUE(isArgStruct(getAllResult["r:0:472"]));
    ASSERT_TRUE(isArgNumber(getAllResult["r:0:472"]["1"]));
    ASSERT_EQ(getAllResult["r:0:472"]["1"].asInt(), 0);

    server->addCommandResponse("HGETALL r:0:472", REDIS_REPLY_ARRAY, "1");
    server->addCommandResponse("HGETALL r:0:472", REDIS_REPLY_ARRAY, "0");
    server->addCommandResponse("HGETALL r:1:472", REDIS_REPLY_ARRAY, "1");
    server->addCommandResponse("HGETALL r:1:472", REDIS_REPLY_ARRAY, "0");
    server->addCommandResponse("KEYS r:*:*", REDIS_REPLY_ARRAY, "r:1:472");
    server->addCommandResponse("KEYS r:*:*", REDIS_REPLY_ARRAY, "r:0:472");
    res = new GetAllResources(&conn, GetAllCallback, ANY_VALUE, ANY_VALUE);
    res->perform();

    getAllSuccess.set(false);
    time_ = time(0);
    while(!getAllSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }
    ASSERT_TRUE(isArgStruct(getAllResult));
    ASSERT_TRUE(isArgStruct(getAllResult["r:0:472"]));
    ASSERT_TRUE(isArgNumber(getAllResult["r:0:472"]["1"]));
    ASSERT_TRUE(isArgStruct(getAllResult["r:1:472"]));
    ASSERT_TRUE(isArgNumber(getAllResult["r:1:472"]["1"]));
    ASSERT_EQ(getAllResult["r:0:472"]["1"].asInt(), 0);
    ASSERT_EQ(getAllResult["r:1:472"]["1"].asInt(), 0);

    conn.stop(true);
}

TEST_F(YetiTest, ResourceOverload)
{
    ResourceRedisConnection conn("resourceTest");
    configure_run_redis_connection(conn, GetPutCallback);

    time_t time_ = time(0);
    while(!conn.get_write_conn()->wait_connected() &&
          !conn.get_read_conn()->wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    server->addCommandResponse("HVALS r:1:472", REDIS_REPLY_ARRAY, "0");
    server->addCommandResponse("MULTI", REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponse("HINCRBY r:1:472 1 3", REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponse("EXEC", REDIS_REPLY_ARRAY, AmArg());
    getPutSuccess.set(false);
    ResourceList rl;
    ResourceList::iterator rit;
    rl.parse("1:472:2:3");
    ASSERT_EQ(conn.get(rl, rit), RES_SUCC);

    time_ = time(0);
    while(!getPutSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    server->addCommandResponse("HVALS r:1:472", REDIS_REPLY_ARRAY, "3");
    ASSERT_EQ(conn.get(rl, rit), RES_BUSY);

    server->addCommandResponse("HVALS r:1:472", REDIS_REPLY_ARRAY, "3");
    server->addCommandResponse("HVALS r:0:472", REDIS_REPLY_ARRAY, "0");
    server->addCommandResponse("HVALS r:2:472", REDIS_REPLY_ARRAY, "0");
    server->addCommandResponse("HVALS r:3:472", REDIS_REPLY_ARRAY, "0");
    server->addCommandResponse("MULTI", REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponse("HINCRBY r:0:472 1 3", REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponse("HINCRBY r:2:472 1 3", REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponse("HINCRBY r:3:472 1 3", REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponse("EXEC", REDIS_REPLY_ARRAY, AmArg());
    getPutSuccess.set(false);
    rl.parse("1:472:2:3|0:472:2:3|2:472:2:3;3:472:2:3");
    ASSERT_EQ(conn.get(rl, rit), RES_SUCC);
    time_ = time(0);
    while(!getPutSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    server->addCommandResponse("HVALS r:1:472", REDIS_REPLY_ARRAY, "3");
    server->addCommandResponse("HVALS r:0:472", REDIS_REPLY_ARRAY, "0");
    server->addCommandResponse("HVALS r:2:472", REDIS_REPLY_ARRAY, "0");
    server->addCommandResponse("HVALS r:3:472", REDIS_REPLY_ARRAY, "3");
    ASSERT_EQ(conn.get(rl, rit), RES_BUSY);

    server->addCommandResponse("HVALS r:3:472", REDIS_REPLY_ARRAY, "3");
    rl.parse("3:472:2:3");
    ASSERT_EQ(conn.get(rl, rit), RES_BUSY);

    conn.stop(true);
}

TEST_F(YetiTest, ResourceTimeout)
{
    ResourceRedisConnection conn("resourceTest");
    configure_run_redis_connection(conn, nullptr, nullptr, 0);

    time_t time_ = time(0);
    while(!conn.get_write_conn()->wait_connected() &&
          !conn.get_read_conn()->wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    getPutSuccess.set(false);
    ResourceList rl;
    ResourceList::iterator rit;
    rl.parse("1:472:2:3");
    server->addTail("HVALS r:1:472", 1);
    ASSERT_EQ(conn.get(rl, rit), RES_ERR);

    conn.stop(true);
}
