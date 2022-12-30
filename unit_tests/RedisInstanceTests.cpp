#include "YetiTest.h"
#include "../src/RedisInstance.h"
#include <hiredis/hiredis.h>
#include "../src/RedisConnection.h"
#include "../src/resources/ResourceRedisConnection.h"

TEST_F(YetiTest, RedisFormatTest)
{
    char *cmd, *cmd1;
    redis::redisFormatCommand(&cmd,"HSET %s %d %d","r:471",8,0);
    ::redisFormatCommand(&cmd1,"HSET %s %d %d","r:471",8,0);
    ASSERT_FALSE(strcmp(cmd, cmd1));
    redis::redisFreeCommand(cmd);
    ::redisFreeCommand(cmd1);
}

TEST_F(YetiTest, RedisSimpleTest)
{
    timeval timeout = { DEFAULT_REDIS_TIMEOUT_MSEC, 0 };
    redisContext* ctx = redis::redisConnectWithTimeout(yeti_test::instance()->redis.host.c_str(), yeti_test::instance()->redis.port, timeout);
    ASSERT_TRUE(ctx);
    ASSERT_FALSE(redis::redisGetErrorNumber(ctx));
    ASSERT_FALSE(redis::redisAppendCommand(ctx, "HSET %s %d %d","r:471",8,0));
    redisReply* r;
    ASSERT_FALSE(redis::redisGetReply(ctx, (void**)&r));
    redis::freeReplyObject(ctx, r);
    redis::redisFree(ctx);
}

class TestRedisConnection
  : public RedisConnectionPool
{
    AmCondition<bool> gotreply;
    AmArg result;
    RedisConnection* conn;
    RedisReplyEvent::result_type rstatus;

  public:
    TestRedisConnection()
      : RedisConnectionPool("test", "regTest"),
        gotreply(false),
        rstatus(RedisReplyEvent::SuccessReply)
    {}
    ~TestRedisConnection() {}

    void process_reply_event(RedisReplyEvent & event) override {
        gotreply.set(true);
        result = event.data;
        rstatus = event.result;
    }

    int init(const string& host, int port) {
        int ret = RedisConnectionPool::init();
        conn = addConnection(host, port);
        if(ret || !conn) return -1;
        return 0;
    }

    bool is_connected() {return conn->is_connected(); }
    bool wait_connected() { return conn->wait_connected(); }
    bool is_gotreply() {return gotreply.get(); }
    bool wait_reply() { return gotreply.wait_for_to(500); }

    RedisReplyEvent::result_type get_result_type() { return rstatus; }
    AmArg& get_result() { return result; }
    RedisConnection* get_connection() { return conn; }

    void post(AmEvent* ev) {
        gotreply = false;
        rstatus = RedisReplyEvent::SuccessReply;
        result.clear();
        postEvent(ev);
    }
};

TEST_F(YetiTest, RedisConnectionTest)
{
    TestRedisConnection conn;
    conn.init(yeti_test::instance()->redis.host.c_str(), yeti_test::instance()->redis.port);
    conn.start();

    time_t time_ = time(0);
    while(!conn.wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    char *cmd;
    redis::redisFormatCommand(&cmd,"HSET %s %d %d","r:471",8,0);
    server->addFormattedCommandResponse(cmd, REDIS_REPLY_NIL, AmArg());
    conn.post(new RedisRequestEvent(conn.get_connection(), "regTest", cmd, strlen(cmd), true));

    time_ = time(0);
    while(!conn.wait_reply()){
        ASSERT_FALSE(time(0) - time_ > 30);
    }

    redis::redisFormatCommand(&cmd,"HGET %s %d", "r:471", 8);
    AmArg res("0");
    server->addFormattedCommandResponse(cmd, REDIS_REPLY_ARRAY, res);
    conn.post(new RedisRequestEvent(conn.get_connection(), "regTest", cmd, strlen(cmd), true));

    time_ = time(0);
    while(!conn.wait_reply()){
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    INFO("%s", AmArg::print(conn.get_result()).c_str());
    ASSERT_EQ(conn.get_result_type(), RedisReplyEvent::SuccessReply);

    conn.stop(true);
}

TEST_F(YetiTest, RedisMultiTest)
{
    timeval timeout = { DEFAULT_REDIS_TIMEOUT_MSEC, 0 };
    redisContext* ctx = redis::redisConnectWithTimeout(yeti_test::instance()->redis.host.c_str(), yeti_test::instance()->redis.port, timeout);
    ASSERT_TRUE(ctx);
    ASSERT_FALSE(redis::redisGetErrorNumber(ctx));
    vector<string> commands;
    commands.push_back("HSET r:471 8 0");
    commands.push_back("HGET r:471 8");
    server->addCommandResponse("MULTI", REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponse(commands[0], REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponse(commands[1], REDIS_REPLY_STATUS, AmArg());
    AmArg res;
    res.assertArray();
    res[0] = 0;
    res[1] = "0";
    server->addCommandResponse("EXEC", REDIS_REPLY_ARRAY, res);
    AmArg ret = runMultiCommand(ctx, commands, "HSET-HGET");
    redis::redisFree(ctx);
}
