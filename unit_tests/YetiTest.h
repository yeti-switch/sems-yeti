#ifndef YETI_TEST_H
#define YETI_TEST_H

#include <singleton.h>
#include <unit_tests/Config.h>
#include <unit_tests/TestServer.h>
#include <gtest/gtest.h>
#include <apps/redis/unit_tests/RedisTestServer.h>
#include <apps/redis/unit_tests/RedisTest.h>

#include "../src/resources/ResourceRedisClient.h"
#include "../src/resources/ResourceRedisConnection.h"

const char invalidate_resources_hash[] = "5b46be51ed0aaeb4345131f47ca36d977be8d39a";
const char get_all_resources_hash[] = "d90c1b9f557f590b13c4d918045fae98cd131821";
const char check_resources_hash[] = "e5d1e31bbedc44dfdfe1465a6960aa21c47ceb86";

const char invalidate_resources_default_path[] = "./etc/invalidate_resources.lua";
const char get_all_resources_default_path[] = "./etc/get_all_resources.lua";
const char check_resources_default_path[] = "./etc/check_resources.lua";

class YetiTest : public testing::Test
{
protected:
    RedisSettings settings;
    RedisTestServer* test_server;
public:
    YetiTest();

    void SetUp() override;

    void initResources(ResourceRedisConnection &conn);
    void cleanResources(ResourceRedisConnection &conn);

protected:

    /* CustomTestResourcesRequest */
    class CustomTestResourcesRequest:
        public ResourceRedisClient::Request
    {
      private:
        vector<AmArg> &args;

      public:
        CustomTestResourcesRequest(vector<AmArg> &args)
          : args(args)
        {}

      protected:
        bool make_args(const string&, vector<AmArg> &args) override
        {
            args = this->args;
            return true;
        }
    };

    int configure_run_redis_connection(
        ResourceRedisConnection &conn,
        ResourceRedisConnection::Request::cb_func result_cb = nullptr,
        ResourceRedisConnection::Request::cb_func init_cb = nullptr,
        int timeout = DEFAULT_REDIS_TIMEOUT_MSEC);
};

struct YetiTestFactory
{
    TestServer pqtest_server;

    YetiTestFactory();
    ~YetiTestFactory(){}

    void dispose(){}
};

typedef singleton<YetiTestFactory> yeti_test;

#endif/*YETI_TEST_H*/
