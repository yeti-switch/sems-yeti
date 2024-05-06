#include "YetiTest.h"
#include "../src/RedisConnection.h"
#include "../src/resources/ResourceControl.h"
#include "../src/resources/ResourceRedisConnection.h"

static AmCondition<bool> inited(false);
static void InitCallback() {
    inited.set(true);
}

TEST_F(YetiTest, ResourceInit)
{
    ResourceRedisConnection conn("resourceTest");
    AmConfigReader cfg;
    cfg.setParameter("write_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("write_redis_port", int2str(yeti_test::instance()->redis.port));
    cfg.setParameter("read_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("read_redis_port", int2str(yeti_test::instance()->redis.port));
    cfg.setParameter("read_redis_timeout", int2str(DEFAULT_REDIS_TIMEOUT_MSEC));
    cfg.setParameter("write_redis_timeout", int2str(DEFAULT_REDIS_TIMEOUT_MSEC));
    conn.configure(cfg);
    conn.registerResourcesInitializedCallback(InitCallback);
    conn.init();
    conn.start();

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
    AmConfigReader cfg;
    cfg.setParameter("write_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("write_redis_port", int2str(yeti_test::instance()->redis.port));
    cfg.setParameter("read_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("read_redis_port", int2str(yeti_test::instance()->redis.port));
    cfg.setParameter("read_redis_timeout", int2str(DEFAULT_REDIS_TIMEOUT_MSEC));
    cfg.setParameter("write_redis_timeout", int2str(DEFAULT_REDIS_TIMEOUT_MSEC));
    conn.configure(cfg);
    conn.registerOperationResultCallback(GetPutCallback);
    conn.init();
    conn.start();

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

    OperationResources *op = new OperationResources(&conn, std::move(operations));
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
    AmConfigReader cfg;
    cfg.setParameter("write_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("write_redis_port", int2str(yeti_test::instance()->redis.port));
    cfg.setParameter("read_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("read_redis_port", int2str(yeti_test::instance()->redis.port));
    cfg.setParameter("read_redis_timeout", int2str(DEFAULT_REDIS_TIMEOUT_MSEC));
    cfg.setParameter("write_redis_timeout", int2str(DEFAULT_REDIS_TIMEOUT_MSEC));
    conn.configure(cfg);
    conn.init();
    conn.start();

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
    AmConfigReader cfg;
    cfg.setParameter("write_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("write_redis_port", int2str(yeti_test::instance()->redis.port));
    cfg.setParameter("read_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("read_redis_port", int2str(yeti_test::instance()->redis.port));
    cfg.setParameter("read_redis_timeout", int2str(DEFAULT_REDIS_TIMEOUT_MSEC));
    cfg.setParameter("write_redis_timeout", int2str(DEFAULT_REDIS_TIMEOUT_MSEC));
    conn.configure(cfg);
    conn.init();
    conn.start();

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
    AmConfigReader cfg;
    cfg.setParameter("write_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("write_redis_port", int2str(yeti_test::instance()->redis.port));
    cfg.setParameter("read_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("read_redis_port", int2str(yeti_test::instance()->redis.port));
    cfg.setParameter("read_redis_timeout", int2str(DEFAULT_REDIS_TIMEOUT_MSEC));
    cfg.setParameter("write_redis_timeout", int2str(DEFAULT_REDIS_TIMEOUT_MSEC));
    conn.configure(cfg);
    conn.registerOperationResultCallback(GetPutCallback);
    conn.init();
    conn.start();

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
    AmConfigReader cfg;
    cfg.setParameter("write_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("write_redis_port", int2str(yeti_test::instance()->redis.port));
    cfg.setParameter("read_redis_host", yeti_test::instance()->redis.host.c_str());
    cfg.setParameter("read_redis_port", int2str(yeti_test::instance()->redis.port));
    conn.configure(cfg);
    conn.init();
    conn.start();

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
