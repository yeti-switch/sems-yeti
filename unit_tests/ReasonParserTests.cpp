#include "YetiTest.h"
#include "../src/ReasonParser.h"

string Reason_hdr_comma_separated(
    "Reason: SIP; cause=200; text=\"Call completed elsewhere\" , "
    "Q.850 ;cause=16 ;text=\"Terminated\"");

string Reason_hdr_new_header(
    "Reason: SIP; cause=200; text=\"Call completed elsewhere\"\r\n"
    "Reason: Q.850 ;cause=16 ;text=\"Terminated\"");

AmArg sip_reason_expected{
    { "cause", 200 },
    { "text", "Call completed elsewhere" }
};

AmArg q850_reason_expected{
    { "cause", 16 },
    { "text", "Terminated" }
};

AmArg reasons_expected{
    { "sip", sip_reason_expected },
    { "q850", q850_reason_expected }
};

TEST_F(YetiTest, ReasonParserCommaSeparated)
{
    YetiCfg::headers_processing_config::leg_reasons cfg;
    cfg.add_q850_reason = true;
    cfg.add_sip_reason = true;

    ReasonParser p;
    p.parse_headers(Reason_hdr_comma_separated);

    AmArg serialized_reasons;
    p.serialize(serialized_reasons, cfg);
    ASSERT_EQ(serialized_reasons, reasons_expected);
}

TEST_F(YetiTest, ReasonParserCommaSeparatedFlat)
{
    YetiCfg::headers_processing_config::leg_reasons cfg;
    cfg.add_q850_reason = true;
    cfg.add_sip_reason = true;

    ReasonParser p;
    p.parse_headers(Reason_hdr_comma_separated);

    AmArg serialized_reasons;
    p.serialize_flat(serialized_reasons, cfg);
    ASSERT_EQ(serialized_reasons, (AmArg{
        { "sip_cause", 200 },
        { "sip_text", "Call completed elsewhere" },
        { "q850_cause", 16 },
        { "q850_text", "Terminated" },
     }));
}

TEST_F(YetiTest, ReasonParserCommaSeparatedFlatParams)
{
    YetiCfg::headers_processing_config::leg_reasons cfg;
    cfg.add_q850_reason = true;
    cfg.add_sip_reason = true;

    ReasonParser p;
    p.parse_headers(
        "Reason: SIP; cause=200; sparam1; sparam2=test; sparam3=\"test\"; "
            "text=\"Call completed elsewhere\" , "
        "Q.850 ;cause=16; qparam1; qparam2=test; qparam3=\"test\"; "
            "text=\"Terminated\"");

    AmArg serialized_reasons;
    p.serialize_flat(serialized_reasons, cfg);
    ASSERT_EQ(serialized_reasons, (AmArg{
        { "sip_cause", 200 },
        { "sip_text", "Call completed elsewhere" },
        { "sip_params", "sparam1; sparam2=test; sparam3=test" },
        { "q850_cause", 16 },
        { "q850_text", "Terminated" },
        { "q850_params", "qparam1; qparam2=test; qparam3=test" },
     }));
}

TEST_F(YetiTest, ReasonParserNewHeader)
{
    YetiCfg::headers_processing_config::leg_reasons cfg;
    cfg.add_q850_reason = true;
    cfg.add_sip_reason = true;

    ReasonParser p;
    p.parse_headers(Reason_hdr_new_header);

    AmArg serialized_reasons;
    p.serialize(serialized_reasons, cfg);
    ASSERT_EQ(serialized_reasons, reasons_expected);
}

TEST_F(YetiTest, ReasonParserCfgEmpty)
{
    YetiCfg::headers_processing_config::leg_reasons cfg;
    cfg.add_q850_reason = false;
    cfg.add_sip_reason = false;

    ReasonParser p;
    p.parse_headers(Reason_hdr_comma_separated);

    AmArg serialized_reasons;
    p.serialize(serialized_reasons, cfg);
    ASSERT_EQ(serialized_reasons, AmArg());
}

TEST_F(YetiTest, ReasonParserCfgSIPOnly)
{
    YetiCfg::headers_processing_config::leg_reasons cfg;
    cfg.add_q850_reason = false;
    cfg.add_sip_reason = true;

    ReasonParser p;
    p.parse_headers(Reason_hdr_comma_separated);

    AmArg serialized_reasons;
    p.serialize(serialized_reasons, cfg);
    ASSERT_EQ(serialized_reasons, (AmArg{
        { "sip", sip_reason_expected }
    }));
}

TEST_F(YetiTest, ReasonParserCfgQ850Only)
{
    YetiCfg::headers_processing_config::leg_reasons cfg;
    cfg.add_q850_reason = true;
    cfg.add_sip_reason = false;

    ReasonParser p;
    p.parse_headers(Reason_hdr_comma_separated);

    AmArg serialized_reasons;
    p.serialize(serialized_reasons, cfg);
    ASSERT_EQ(serialized_reasons, (AmArg{
        { "q850", q850_reason_expected }
    }));
}

TEST_F(YetiTest, ReasonParserAddUnknown)
{
    YetiCfg::headers_processing_config::leg_reasons cfg;
    cfg.add_q850_reason = true;
    cfg.add_sip_reason = true;

    ReasonParser p;
    p.parse_headers(
        "Reason: SIP; cause=200; test; test2=test3;test4=\"test5\";text=\"Call completed elsewhere\" , "
        "QWE; cause=111; text=\"some reason\" , "
        "Q.850 ;cause=16 ;text=\"Terminated\"");

    AmArg serialized_reasons;
    p.serialize(serialized_reasons, cfg);
    ASSERT_EQ(serialized_reasons, (AmArg{
        { "sip", AmArg {
            { "cause", 200 },
            { "text", "Call completed elsewhere" },
            { "params", "test; test2=test3; test4=test5" }
        }},
        { "q850", q850_reason_expected }
    }));
}

TEST_F(YetiTest, ReasonParserNoCause)
{
    YetiCfg::headers_processing_config::leg_reasons cfg;
    cfg.add_q850_reason = true;
    cfg.add_sip_reason = true;

    ReasonParser p;
    p.parse_headers(
        "Reason: Q.850 ;text=\"Terminated\"");

    AmArg serialized_reasons;
    p.serialize(serialized_reasons, cfg);
    ASSERT_EQ(serialized_reasons, AmArg());
}

TEST_F(YetiTest, ReasonParserNoText)
{
    YetiCfg::headers_processing_config::leg_reasons cfg;
    cfg.add_q850_reason = true;
    cfg.add_sip_reason = true;

    ReasonParser p;
    p.parse_headers(
        "Reason: Q.850 ;cause=16");

    AmArg serialized_reasons;
    p.serialize(serialized_reasons, cfg);
    ASSERT_EQ(serialized_reasons, (AmArg{
        { "q850", AmArg{
            { "cause", 16 }
        }}
    }));
}
