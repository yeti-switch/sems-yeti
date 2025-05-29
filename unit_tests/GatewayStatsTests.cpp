#include "YetiTest.h"
#include "../src/GatewayStats.h"

TEST_F(YetiTest, GatewayStatsBasicOperations)
{
    GatewayStats s;
    s.set_window_size(5);

    ASSERT_EQ(s.global.success_replies, 0);
    ASSERT_EQ(s.global.failed_replies, 0);

    s.add_failed_reply(10);
    s.add_success_reply(10);

    s.add_failed_reply(11);
    s.add_success_reply(11);

    ASSERT_EQ(s.global.success_replies, 2);
    ASSERT_EQ(s.global.failed_replies, 2);

    ASSERT_EQ(s.getTimeSlots().at(10).success_replies, 1);
    ASSERT_EQ(s.getTimeSlots().at(10).failed_replies, 1);
    ASSERT_EQ(s.getTimeSlots().at(11).success_replies, 1);
    ASSERT_EQ(s.getTimeSlots().at(11).failed_replies, 1);

    //check obsolete slots cleanup

    s.add_failed_reply(20);
    s.add_success_reply(20);

    ASSERT_EQ(s.global.success_replies, 1);
    ASSERT_EQ(s.global.failed_replies, 1);
}
