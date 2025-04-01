#include "YetiTest.h"
#include "../src/resources/ResourceControl.h"
#include "../src/resources/ResourceRedisConnection.h"

#include <jsonArg.h>

#include <functional>

class TestResourceRedisConnection: public ResourceRedisConnection {
public:
    using ResourceRedisConnection::ResourceRedisConnection;
    std::function<void(const vector<AmArg> &args)> on_prepare_request;

protected:
    bool prepare_request(Request* req, Connection* conn, const char* script_name, vector<AmArg> &args) override {
        const bool res = ResourceRedisConnection::prepare_request(req, conn, script_name, args);

        if(on_prepare_request)
            on_prepare_request(args);

        return res;
    }
};

static AmCondition<bool> inited(false);
static void InitCallback(bool is_error, const AmArg&) {
    inited.set(!is_error);
}

TEST_F(YetiTest, ResourceInit)
{
    TestResourceRedisConnection conn("resourceTest1");
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
static void GetPutCallback(bool is_error, const AmArg&) {
    getPutSuccess.set(!is_error);
}

TEST_F(YetiTest, ResourceGetPut)
{
    TestResourceRedisConnection conn("resourceTest2");
    configure_run_redis_connection(conn, GetPutCallback);

    time_t time_ = time(0);
    while(!conn.get_write_conn()->wait_connected() &&
          !conn.get_read_conn()->wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    initResources(conn);

    ResourceList rl;
    rl.parse("0:472:100:2;1:472:100:2");
    for(auto& res: rl) {
        res.active = true;
    }

    conn.get(string(),rl);

    ASSERT_TRUE(getPutSuccess.wait_for_to(3000));

    cleanResources(conn);
    conn.stop(true);
}

TEST_F(YetiTest, ResourceCheck)
{
    TestResourceRedisConnection conn("resourceTest3");
    configure_run_redis_connection(conn);

    time_t time_ = time(0);
    while(!conn.get_write_conn()->wait_connected() &&
          !conn.get_read_conn()->wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    initResources(conn);

    AmArg ret;
    json2arg(R"raw([0, 0])raw", ret);
    test_server->addCommandResponse("EVALSHA %s 0 %s %s", REDIS_TEST_REPLY_ARRAY, ret,
        check_resources_hash, "r:0:472", "r:1:472");

    ResourceList rl;
    rl.parse("0:472:100:2;1:472:100:2");
    auto *cr = new ResourceRedisConnection::CheckRequest(rl);
    conn.check(cr);

    time_ = time(0);
    while(!cr->wait_finish(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }
    AmArg result = cr->get_result();
    ASSERT_TRUE(isArgArray(result));
    ASSERT_EQ(result.size(), size_t{2});
    ASSERT_EQ(result[0].asLongLong(), 0);
    ASSERT_EQ(result[1].asLongLong(), 0);
    delete cr;

    cleanResources(conn);
    conn.stop(true);
}

TEST_F(YetiTest, ResourceGetCheck)
{
    TestResourceRedisConnection conn("resourceTest4");
    configure_run_redis_connection(conn, GetPutCallback);

    time_t time_ = time(0);
    while(!conn.get_write_conn()->wait_connected() &&
          !conn.get_read_conn()->wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    initResources(conn);

    // get
    ResourceList rl;
    rl.parse("0:472:100:2;1:472:100:2");
    for(auto& res: rl) {
        res.active = true;
    }

    getPutSuccess.set(false);
    conn.get(string(),rl);

    time_ = time(0);
    while(!getPutSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    // check
    AmArg ret;
    json2arg(R"raw([2, 2])raw", ret);
    test_server->addCommandResponse("EVALSHA %s 0 %s %s", REDIS_TEST_REPLY_ARRAY, ret,
        check_resources_hash, "r:0:472", "r:1:472");

    auto *cr = new ResourceRedisConnection::CheckRequest(rl);
    conn.check(cr);

    time_ = time(0);
    while(!cr->wait_finish(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }
    AmArg result = cr->get_result();
    ASSERT_TRUE(isArgArray(result));
    ASSERT_EQ(result.size(), size_t{2});
    ASSERT_EQ(result[0].asLongLong(), 2);
    ASSERT_EQ(result[1].asLongLong(), 2);
    delete cr;

    cleanResources(conn);
    conn.stop(true);
}

static AmCondition<bool> getAllSuccess(false);
static AmArg getAllResult;
static void GetAllCallback(bool is_error, const AmArg& result) {
    getAllResult = result;
    getAllSuccess.set(!is_error);
}

static bool isArgNumber(const AmArg& arg)
{
    return isArgInt(arg) || isArgLongLong(arg) || isArgDouble(arg);
}

TEST_F(YetiTest, ResourceGetAll)
{
    TestResourceRedisConnection conn("resourceTest5");
    configure_run_redis_connection(conn);

    time_t time_ = time(0);
        while(!conn.get_write_conn()->wait_connected() &&
          !conn.get_read_conn()->wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    initResources(conn);

    AmArg ret;
    json2arg(R"raw([["r:0:472", [1, 0]]])raw", ret);
    test_server->addCommandResponse("EVALSHA %s 2 %d %d", REDIS_TEST_REPLY_ARRAY, ret,
        get_all_resources_hash, 0, 472);

    getAllSuccess.set(false);
    getAllResult.clear();
    conn.get_all(new ResourceRedisConnection::GetAllRequest(0, 472, GetAllCallback));

    time_ = time(0);
    while(!getAllSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    ASSERT_TRUE(isArgStruct(getAllResult));
    ASSERT_TRUE(isArgNumber(getAllResult["1"]));
    ASSERT_EQ(getAllResult["1"].asInt(), 0);

    json2arg(R"raw([["r:0:472", [1, 0]], ["r:1:472", [1, 0]]])raw", ret);
    test_server->addCommandResponse("EVALSHA %s 2 %d %d", REDIS_TEST_REPLY_ARRAY, ret,
        get_all_resources_hash, ANY_VALUE, 472);

    getAllSuccess.set(false);
    getAllResult.clear();
    conn.get_all(new ResourceRedisConnection::GetAllRequest(ANY_VALUE, 472, GetAllCallback));

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

    json2arg(R"raw([["r:0:472", [1, 0]]])raw", ret);
    test_server->addCommandResponse("EVALSHA %s 2 %d %d", REDIS_TEST_REPLY_ARRAY, ret,
        get_all_resources_hash, 0, ANY_VALUE);

    getAllSuccess.set(false);
    getAllResult.clear();
    conn.get_all(new ResourceRedisConnection::GetAllRequest(0, ANY_VALUE, GetAllCallback));

    time_ = time(0);
    while(!getAllSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    ASSERT_TRUE(isArgStruct(getAllResult));
    ASSERT_TRUE(isArgStruct(getAllResult["r:0:472"]));
    ASSERT_TRUE(isArgNumber(getAllResult["r:0:472"]["1"]));
    ASSERT_EQ(getAllResult["r:0:472"]["1"].asInt(), 0);

    json2arg(R"raw([["r:0:472", [1, 0]], ["r:1:472", [1, 0]]])raw", ret);
    test_server->addCommandResponse("EVALSHA %s 2 %d %d", REDIS_TEST_REPLY_ARRAY, ret,
        get_all_resources_hash, ANY_VALUE, ANY_VALUE);

    getAllSuccess.set(false);
    getAllResult.clear();
    conn.get_all(new ResourceRedisConnection::GetAllRequest(ANY_VALUE, ANY_VALUE, GetAllCallback));

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

    cleanResources(conn);
    conn.stop(true);
}

TEST_F(YetiTest, ResourceOverload)
{
    TestResourceRedisConnection conn("resourceTest6");
    configure_run_redis_connection(conn, GetPutCallback);

    time_t time_ = time(0);
    while(!conn.get_write_conn()->wait_connected() &&
          !conn.get_read_conn()->wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    initResources(conn);

    AmArg ret;
    json2arg(R"raw([0])raw", ret);
    test_server->addCommandResponse("EVALSHA %s 0 %s", REDIS_TEST_REPLY_ARRAY, ret,
        check_resources_hash, "r:1:472");

    getPutSuccess.set(false);
    ResourceList rl;
    ResourceList::iterator rit;
    rl.parse("1:472:2:3");
    ASSERT_EQ(conn.get(string(), rl, rit), RES_SUCC);

    time_ = time(0);
    while(!getPutSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    json2arg(R"raw([3])raw", ret);
    test_server->addCommandResponse("EVALSHA %s 0 %s", REDIS_TEST_REPLY_ARRAY, ret,
        check_resources_hash, "r:1:472");

    ASSERT_EQ(conn.get(string(), rl, rit), RES_BUSY);

    json2arg(R"raw([3, 0, 0, 0])raw", ret);
    test_server->addCommandResponse("EVALSHA %s 0 %s %s %s %s", REDIS_TEST_REPLY_ARRAY, ret,
        check_resources_hash, "r:1:472", "r:0:472", "r:2:472", "r:3:472");

    getPutSuccess.set(false);
    rl.parse("1:472:2:3|0:472:2:3|2:472:2:3;3:472:2:3");
    ASSERT_EQ(conn.get(string(), rl, rit), RES_SUCC);
    time_ = time(0);
    while(!getPutSuccess.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    json2arg(R"raw([3, 0, 0, 3])raw", ret);
    test_server->addCommandResponse("EVALSHA %s 0 %s %s %s %s", REDIS_TEST_REPLY_ARRAY, ret,
        check_resources_hash, "r:1:472", "r:0:472", "r:2:472", "r:3:472");

    ASSERT_EQ(conn.get(string(), rl, rit), RES_BUSY);

    json2arg(R"raw([3])raw", ret);
    test_server->addCommandResponse("EVALSHA %s 0 %s", REDIS_TEST_REPLY_ARRAY, ret,
        check_resources_hash, "r:3:472");

    rl.parse("3:472:2:3");
    ASSERT_EQ(conn.get(string(), rl, rit), RES_BUSY);

    cleanResources(conn);
    conn.stop(true);
}

TEST_F(YetiTest, ResourceTimeout)
{
    // this test works only with test_server
    if(redis_test::instance()->settings.external)
        return;

    TestResourceRedisConnection conn("resourceTest7");
    configure_run_redis_connection(conn, nullptr, InitCallback, 0);

    time_t time_ = time(0);
    while(!conn.get_write_conn()->wait_connected() &&
          !conn.get_read_conn()->wait_connected() &&
          !inited.wait_for_to(500)) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    cleanResources(conn);
    ResourceList rl;
    ResourceList::iterator rit;
    rl.parse("1:472:2:3");
    test_server->addTail("HVALS r:1:472", 1);
    ASSERT_EQ(conn.get(string(), rl, rit), RES_ERR);

    conn.stop(true);
}
