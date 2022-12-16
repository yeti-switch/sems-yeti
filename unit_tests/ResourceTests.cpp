#include "YetiTest.h"
#include "../src/RedisConnection.h"
#include "../src/resources/ResourceRedisConnection.h"

static AmCondition<bool> inited(false);
static void InitCallback() {
    inited.set(true);
}

TEST_F(YetiTest, ResourceInitTest)
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

TEST_F(YetiTest, ResourceGetPutTest)
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
    ResourceOperationList rol;
    rol.parse("0:472:100:2;1:472:100:2");
    for(auto& res: rol) {
        res.op = ResourceOperation::RES_GET;
        res.active = true;
    }
    OperationResources *op = new OperationResources(&conn, rol);
    op->perform();

    time_ = time(0);
    while(!getPutSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }
    conn.stop(true);
}

