#include "YetiTest.h"

#include "../src/sdp_filter.h"

TEST_F(YetiTest, fixDynamicPayloads_NoReference_Static)
{
    AmSdp sdp;
    sdp.media.emplace_back();
    auto &m     = sdp.media.back();
    m.type      = MT_AUDIO;
    m.transport = TP_RTPAVP;

    m.payloads = {
        { 0, "PCMU", 8000, -1 },
        { 8, "PCMA", 8000, -1 }
    };

    fixDynamicPayloads(sdp);

    ASSERT_EQ(m.payloads[0].payload_type, 0);
    ASSERT_EQ(m.payloads[1].payload_type, 8);
}

TEST_F(YetiTest, fixDynamicPayloads_NoReference_Dynamic)
{
    AmSdp sdp;
    sdp.media.emplace_back();
    auto &m     = sdp.media.back();
    m.type      = MT_AUDIO;
    m.transport = TP_RTPAVP;

    m.payloads = {
        {  0,            "PCMU",  8000, -1 },
        {  8,            "PCMA",  8000, -1 },
        { -1, "telephone-event",  8000, -1 },
        { -1, "telephone-event", 16000, -1 }
    };

    fixDynamicPayloads(sdp);

    ASSERT_EQ(m.payloads[2].payload_type, 96);
    ASSERT_EQ(m.payloads[3].payload_type, 97);
}

TEST_F(YetiTest, fixDynamicPayloads_Reference_Dynamic)
{
    AmSdp sdp;
    sdp.media.emplace_back();
    auto &m     = sdp.media.back();
    m.type      = MT_AUDIO;
    m.transport = TP_RTPAVP;

    vector<SdpMedia> ref_media = { SdpMedia() };
    auto            &ref_m     = ref_media.back();
    ref_m.type                 = MT_AUDIO;
    ref_m.transport            = TP_RTPAVP;

    m.payloads = {
        {  0,            "PCMU",  8000, -1 },
        {  8,            "PCMA",  8000, -1 },
        { 96, "telephone-event",  8000, -1 },
        { 97, "telephone-event", 16000, -1 }
    };

    ref_m.payloads = {
        {   0,            "PCMU",  8000, -1 },
        {   8,            "PCMA",  8000, -1 },
        { 101, "telephone-event",  8000, -1 },
        { 102, "telephone-event", 16000, -1 }
    };

    fixDynamicPayloads(sdp, &ref_media);

    ASSERT_EQ(m.payloads[2].payload_type, 101);
    ASSERT_EQ(m.payloads[3].payload_type, 102);
}

TEST_F(YetiTest, fixDynamicPayloads_Reference_Dynamic_Conflicts)
{
    AmSdp sdp;
    sdp.media.emplace_back();
    auto &m     = sdp.media.back();
    m.type      = MT_AUDIO;
    m.transport = TP_RTPAVP;

    vector<SdpMedia> ref_media = { SdpMedia() };
    auto            &ref_m     = ref_media.back();
    ref_m.type                 = MT_AUDIO;
    ref_m.transport            = TP_RTPAVP;

    m.payloads = {
        {   0,            "PCMU",  8000, -1 },
        {   8,            "PCMA",  8000, -1 },
        { 101,            "OPUS", 16000, -1 },
        { 102,            "OPUS", 32000, -1 },
        {  96, "telephone-event",  8000, -1 },
        {  97, "telephone-event", 16000, -1 }
    };

    ref_m.payloads = {
        {   0,            "PCMU",  8000, -1 },
        {   8,            "PCMA",  8000, -1 },
        { 101, "telephone-event",  8000, -1 },
        { 102, "telephone-event", 16000, -1 }
    };

    fixDynamicPayloads(sdp, &ref_media);

    ASSERT_EQ(m.payloads[2].payload_type, 96);
    ASSERT_EQ(m.payloads[3].payload_type, 97);
    ASSERT_EQ(m.payloads[4].payload_type, 101);
    ASSERT_EQ(m.payloads[5].payload_type, 102);
}

TEST_F(YetiTest, fixDynamicPayloads_Reference_Dynamic_Conflicts_NotAssigned)
{
    AmSdp sdp;
    sdp.media.emplace_back();
    auto &m     = sdp.media.back();
    m.type      = MT_AUDIO;
    m.transport = TP_RTPAVP;

    vector<SdpMedia> ref_media = { SdpMedia() };
    auto            &ref_m     = ref_media.back();
    ref_m.type                 = MT_AUDIO;
    ref_m.transport            = TP_RTPAVP;

    m.payloads = {
        {   0,            "PCMU",  8000, -1 },
        {   8,            "PCMA",  8000, -1 },
        { 101,            "OPUS", 16000, -1 },
        {  -1,            "OPUS", 32000, -1 },
        {  -1, "telephone-event",  8000, -1 },
        {  97, "telephone-event", 16000, -1 }
    };

    ref_m.payloads = {
        {   0,            "PCMU",  8000, -1 },
        {   8,            "PCMA",  8000, -1 },
        { 101, "telephone-event",  8000, -1 },
        { 102, "telephone-event", 16000, -1 }
    };

    fixDynamicPayloads(sdp, &ref_media);

    ASSERT_EQ(m.payloads[2].payload_type, 98);
    ASSERT_EQ(m.payloads[3].payload_type, 96);
    ASSERT_EQ(m.payloads[4].payload_type, 101);
    ASSERT_EQ(m.payloads[5].payload_type, 102);
}
