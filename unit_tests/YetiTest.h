#ifndef YETI_TEST_H
#define YETI_TEST_H

#include <singleton.h>
#include <unit_tests/Config.h>
#include <unit_tests/TestServer.h>
#include <gtest/gtest.h>
#include "RedisTestServer.h"

#define DEFAULT_REDIS_TIMEOUT_MSEC 1000

class YetiTest : public testing::Test
{
protected:
    RedisTestServer* server;
public:
    YetiTest();

    void SetUp() override;
};

struct YetiTestFactory
{
    RedisTestServer server;
    TestServer pqtest_server;
    struct RedisSettings{
        bool external;
        string host;
        int port;
        int timeout;
        RedisSettings()
          : timeout(DEFAULT_REDIS_TIMEOUT_MSEC)
        {}
    } redis;

    YetiTestFactory();
    ~YetiTestFactory(){}

    void dispose(){}
};

typedef singleton<YetiTestFactory> yeti_test;

#endif/*YETI_TEST_H*/
