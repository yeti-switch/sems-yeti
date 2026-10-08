#ifndef YETI_TEST_H
#define YETI_TEST_H

#include <singleton.h>
#include <unit_tests/Config.h>
#include <gtest/gtest.h>
#include <apps/redis/unit_tests/RedisTest.h>

#include "../src/resources/ResourceRedisClient.h"
#include "../src/resources/ResourceRedisConnection.h"

#include <AmSipMsg.h>
#include <sip/parse_header.h>

/** test input "Name: value CRLF ..." -> AmSipHeaderMap via sip parser */
inline AmSipHeaderMap hdrs_from_string(const string &hdrs_str)
{
    AmSipHeaderMap     hdrs;
    string             s = hdrs_str;
    list<sip_header *> parsed;
    char              *c = s.data();
    if (!parse_headers(parsed, &c, c + s.size()))
        for (const auto *h : parsed)
            addHeader(hdrs, *h);
    free_headers(parsed);
    return hdrs;
}

const char invalidate_resources_default_path[] = "./etc/invalidate_resources.lua";
const char get_all_resources_default_path[]    = "./etc/get_all_resources.lua";
const char check_resources_default_path[]      = "./etc/check_resources.lua";

class YetiTest : public testing::Test {
  protected:
    RedisSettings settings;

  public:
    YetiTest();

    void initResources(ResourceRedisConnection &conn);
    void cleanResources(ResourceRedisConnection &conn);

  protected:
    /* CustomTestResourcesRequest */
    class CustomTestResourcesRequest : public ResourceRedisClient::Request {
      private:
        vector<AmArg> &args;

      public:
        CustomTestResourcesRequest(vector<AmArg> &args)
            : args(args)
        {
        }

      protected:
        bool make_args(const string &, vector<AmArg> &args) override
        {
            args = this->args;
            return true;
        }
    };

    int configure_run_redis_connection(ResourceRedisConnection                  &conn,
                                       ResourceRedisConnection::Request::cb_func result_cb = nullptr,
                                       ResourceRedisConnection::Request::cb_func init_cb   = nullptr,
                                       int                                       timeout = DEFAULT_REDIS_TIMEOUT_MSEC);
};

#endif /*YETI_TEST_H*/
