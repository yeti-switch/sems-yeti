#include "YetiTest.h"
#include "../src/GatewaysCache.h"

#include <ranges>

TEST_F(YetiTest, GatewaysCacheThrottling)
{
    GatewaysCache cache;
    cache.update({{AmArg{
        { "id", 1LL },
        { "throttling_codes", AmArg{"local408","408"} },
        { "throttling_minimum_calls", 2 },
        { "throttling_window", 5 },
        { "throttling_threshold_start", 30.0 },
        { "throttling_threshold_end", 70.0 },
    }}});

    AmArg ret;
    AmArg arg;
    arg.assertArray();
    cache.info(arg, ret);
    //DBG("ret: %s", ret.print().data());
    ASSERT_EQ(ret["gateways"]["1"]["throttling_enabled"].asBool(), true);

    AmSipReply reply;
    reply.code = 408;
    int now = 5;
    reply.recv_timestamp = { now, 0 };

    cache.update_reply_stats(1, reply);
    cache.info(arg, ret);
    //we have not reached throttling_minimum_calls yet
    ASSERT_EQ(ret["gateways"]["1"]["stats"]["failure_rate"].asDouble(), 0.0);
    ASSERT_EQ(ret["gateways"]["1"]["stats"]["skip_rate"].asDouble(), 0.0);
    ASSERT_FALSE(cache.should_skip(1, now));

    cache.update_reply_stats(1, reply);
    cache.info(arg, ret);
    //throttling_minimum_calls reached. expect 100 failure rate
    ASSERT_EQ(ret["gateways"]["1"]["stats"]["failure_rate"].asDouble(), 100.0);
    ASSERT_EQ(ret["gateways"]["1"]["stats"]["skip_rate"].asDouble(), 100.0);
    ASSERT_TRUE(cache.should_skip(1, now));

    reply.code = 200;
    cache.update_reply_stats(1, reply);
    cache.update_reply_stats(1, reply);
    cache.info(arg, ret);
    //have 2 more successful calls. failure rate is 50
    ASSERT_EQ(ret["gateways"]["1"]["stats"]["failure_rate"].asDouble(), 50.0);
    ASSERT_EQ(ret["gateways"]["1"]["stats"]["skip_rate"].asDouble(), 60.0);

    //check skip probability
    int skipped = 0, allowed = 0;
    for(int _ : std::ranges::iota_view{0, 10000}) {
        if(cache.should_skip(1, now)) skipped +=1;
        else allowed+=1;
    }
    auto skip_rate = skipped*100/(allowed + skipped);
    DBG("failure/skip 50%/60%. skipped:%d, allowed:%d, rate:%d", skipped, allowed, skip_rate);
    ASSERT_LE(skip_rate, 65);
    ASSERT_GE(skip_rate, 55);

    cache.update_reply_stats(1, reply);
    cache.update_reply_stats(1, reply);
    //skip probability should be decreased 60% -> 26.6(6)
    skipped = allowed = 0;
    for(int _ : std::ranges::iota_view{0, 10000}) {
        if(cache.should_skip(1, now)) skipped +=1;
        else allowed+=1;
    }
    skip_rate = skipped*100/(allowed + skipped);
    DBG("failure/skip 33.3(3)%/26.6(6)%. skipped:%d, allowed:%d, rate:%d", skipped, allowed, skip_rate);
    ASSERT_LE(skip_rate, 31);
    ASSERT_GE(skip_rate, 21);

    //move time forward to obsolete old counters
    reply.recv_timestamp = { now + 20, 0 };
    cache.update_reply_stats(1, reply);
    ASSERT_FALSE(cache.should_skip(1, now));
}
