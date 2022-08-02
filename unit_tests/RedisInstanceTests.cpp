#include "YetiTest.h"
#include "../src/RedisInstance.h"
#include <hiredis/hiredis.h>
#include "../src/RedisConnection.h"

TEST_F(YetiTest, FormatRedisTest)
{
    char *cmd, *cmd1;
    redis::redisFormatCommand(&cmd,"HSET %s %d %d","r:471",8,0);
    ::redisFormatCommand(&cmd1,"HSET %s %d %d","r:471",8,0);
    ASSERT_FALSE(strcmp(cmd, cmd1));
    redis::redisFreeCommand(cmd);
    ::redisFreeCommand(cmd1);
}

#define REDIS_CONN_TIMEOUT 5

TEST_F(YetiTest, SimpleRedisTest)
{
    timeval timeout = { REDIS_CONN_TIMEOUT, 0 };
    redisContext* ctx = redis::redisConnectWithTimeout(yeti_test::instance()->redis.host.c_str(), yeti_test::instance()->redis.port, timeout);
    ASSERT_TRUE(ctx);
    ASSERT_FALSE(redis::redisGetErrorNumber(ctx));
    ASSERT_FALSE(redis::redisAppendCommand(ctx, "HSET %s %d %d","r:471",8,0));
    redisReply* r;
    ASSERT_FALSE(redis::redisGetReply(ctx, (void**)&r));
    redis::freeReplyObject(ctx, r);
    redis::redisFree(ctx);
}

class TestRedisConnection : public RedisConnection
{
    bool connected;
    bool gotreply;
    AmArg result;
    RedisReplyEvent::result_type rstatus;
public:
    TestRedisConnection()
    : RedisConnection("test", "regTest")
    , connected(false), gotreply(false), rstatus(RedisReplyEvent::SuccessReply){}
    ~TestRedisConnection(){}

    void process_reply_event(RedisReplyEvent & event) override {
        gotreply = true;
        result = event.data;
        rstatus = event.result;
    }
    void on_connect() override {
        connected = true;
    }

    bool is_connected() {return connected; }
    bool is_gotreply() {return gotreply; }
    RedisReplyEvent::result_type get_result_type() {return rstatus;}
    AmArg& get_result() {return result;}

    void post(AmEvent* ev) {
        gotreply = false;
        rstatus = RedisReplyEvent::SuccessReply;
        result.clear();
        postEvent(ev);
    }
};

TEST_F(YetiTest, AsyncRedisTest)
{
    TestRedisConnection conn;
    conn.init(yeti_test::instance()->redis.host.c_str(), yeti_test::instance()->redis.port);
    conn.start();

    time_t time_ = time(0);
    while(!conn.is_connected()) {
        usleep(500);
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    char *cmd;
    redis::redisFormatCommand(&cmd,"HSET %s %d %d","r:471",8,0);
    server->addFormattedCommandResponce(cmd, REDIS_REPLY_NIL, AmArg());
    conn.post(new RedisRequestEvent("regTest", cmd, strlen(cmd), true));

    time_ = time(0);
    while(!conn.is_gotreply()){
        usleep(500);
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    redis::redisFormatCommand(&cmd,"HGET %s %d", "r:471", 8);
    AmArg res("0");
    server->addFormattedCommandResponce(cmd, REDIS_REPLY_STRING, res);
    conn.post(new RedisRequestEvent("regTest", cmd, strlen(cmd), true));

    time_ = time(0);
    while(!conn.is_gotreply()){
        usleep(500);
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    ASSERT_TRUE(conn.get_result() == res);
    ASSERT_EQ(conn.get_result_type(), RedisReplyEvent::SuccessReply);

    conn.stop(true);
}

TEST_F(YetiTest, MultiRedisTest)
{
    timeval timeout = { REDIS_CONN_TIMEOUT, 0 };
    redisContext* ctx = redis::redisConnectWithTimeout(yeti_test::instance()->redis.host.c_str(), yeti_test::instance()->redis.port, timeout);
    ASSERT_TRUE(ctx);
    ASSERT_FALSE(redis::redisGetErrorNumber(ctx));
    vector<string> commands;
    commands.push_back("HSET r:471 8 0");
    commands.push_back("HGET r:471 8");
    server->addCommandResponce("MULTI", REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponce(commands[0], REDIS_REPLY_STATUS, AmArg());
    server->addCommandResponce(commands[1], REDIS_REPLY_STATUS, AmArg());
    AmArg res;
    res.assertArray();
    res[0] = 0;
    res[1] = "0";
    server->addCommandResponce("EXEC", REDIS_REPLY_ARRAY, res);
    AmArg ret = runMultiCommand(ctx, commands, "HSET-HGET");
    redis::redisFree(ctx);
}
