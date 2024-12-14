#include "YetiTest.h"
#include "../src/UsedHeaderField.h"
#include "sip/defs.h"

string good_na_1("<sip:user1@domain1;uparam1=uval11;uparam2=uval12;uparam3?uhdr1=uhval1>;hparam1=hval1;hparam2");
string good_na_2("test2 <sip:user2@domain2:5061;uparam1=uval21;uparam2=uval22>");
string good_na_3("test3 <sips:user3@domain3:5062;uparam1=uval31;uparam2=uval32>");
string good_na_4("tel:1234567890");

static string good_diversion_hdrs =
    "Diversion: " + good_na_1 + CRLF +
    "Diversion: " + good_na_2 + ", " + good_na_3 + CRLF +
    "Diversion: " + good_na_4;

struct tparam {
    string varformat;
    string varparam;
    AmArg expected_result;

    tparam(const string &varformat, const string &varparam, const AmArg &expected_result)
      : varformat(varformat),
        varparam(varparam),
        expected_result(expected_result)
    {}
};

void PrintTo(const tparam& arg, std::ostream* os)
{
    *os << "[" <<
        arg.varformat << "," <<
        arg.varparam << "," <<
        arg.expected_result.print();
}

class UsedHeaderFieldTest
  : public testing::TestWithParam<tparam>
{};

TEST_P(UsedHeaderFieldTest, getValue) {
    AmSipRequest req;
    req.hdrs += good_diversion_hdrs;

    DBG("hdrs: %s", good_diversion_hdrs.data());
    auto &param = GetParam();

    AmArg hf_params = {
        { "varname", "Diversion" },
        { "varformat", param.varformat },
        { "varparam", param.varparam }
    };
    UsedHeaderField hf(hf_params);

    auto ret = hf.getValue(req);
    ASSERT_TRUE(ret.has_value());
    ASSERT_EQ(ret.value(), param.expected_result);
}

static AmArg uri_json_expected({
    AmArg{
        { "n", AmArg() },
        { "s", "sip" },
        { "u", "user1" },
        { "h", "domain1" },
        { "p", 5060 },
        { "up", {
            { "uparam1", "uval11" },
            { "uparam2", "uval12"},
            { "uparam3", ""},
        }},
        { "uh", {
            { "uhdr1", "uhval1" },
        }},
        { "np", {
            { "hparam1", "hval1" },
            { "hparam2", ""}
        }}
    }
});

static AmArg uri_json_array_expected{
    uri_json_expected[0],
    AmArg{
        { "n", "test2" },
        { "s", "sip" },
        { "u", "user2" },
        { "h", "domain2" },
        { "p", 5061 },
        { "up", {
            { "uparam1", "uval21" },
            { "uparam2", "uval22"}
        }},
    },
    AmArg{
        { "n", "test3" },
        { "s", "sips" },
        { "u", "user3" },
        { "h", "domain3" },
        { "p", 5062 },
        { "up", {
            { "uparam1", "uval31" },
            { "uparam2", "uval32"}
        }},
    },
    AmArg{
        { "s", "tel" },
        { "u", "1234567890" }
    }
};

INSTANTIATE_TEST_SUITE_P(YetiTest, UsedHeaderFieldTest, testing::Values(
    tparam("", "", good_na_1 + ", " + good_na_2 + ", " + good_na_3 + ", " + good_na_4),
    tparam("uri_user", "", "user1"),
    tparam("uri_user_array", "", "user1,user2,user3,1234567890"),
    tparam("uri_domain", "", "domain1"),
    tparam("uri_domain_array", "", "domain1,domain2,domain3,"),
    tparam("uri_port", "", "5060"),
    tparam("uri_port_array", "", "5060,5061,5062,0"),
    tparam("uri_param", "uparam1", "uval11"),
    tparam("uri_param_array", "uparam1", "uval11,uval21,uval31,"),
    tparam("uri_json", "", uri_json_expected),
    tparam("uri_json_array", "", uri_json_array_expected)),

    [](const testing::TestParamInfo<UsedHeaderFieldTest::ParamType>& info) {
        string ret;

        if(info.param.varformat.empty()) ret = "raw";
        else ret = info.param.varformat;

        if(!info.param.varparam.empty())
            ret += "_" + info.param.varparam;

        return ret;
    });
