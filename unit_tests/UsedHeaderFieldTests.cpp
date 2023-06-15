#include "YetiTest.h"
#include "../src/UsedHeaderField.h"
#include "sip/defs.h"

string good_na_1("test1 <sip:user1@domain1;uparam1=uval11;uparam2=uval12>");
string good_na_2("test2 <sip:user2@domain2:5061;uparam1=uval21;uparam2=uval22>");
string good_na_3("test3 <sip:user3@domain3:5062;uparam1=uval31;uparam2=uval32>");

static string good_diversion_hdrs =
    "Diversion: " + good_na_1 + CRLF +
    "Diversion: " + good_na_2 + ", " + good_na_3;

struct tparam {
    string varformat;
    string varparam;
    string expected_result;

    tparam(const string &varformat, const string &varparam, const string &expected_result)
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
        arg.expected_result;
}

class UsedHeaderFieldTest
  : public testing::TestWithParam<tparam>
{};

TEST_P(UsedHeaderFieldTest, getValue) {
    AmSipRequest req;
    req.hdrs += good_diversion_hdrs;

    auto &param = GetParam();

    AmArg hf_params = {
        { "varname", "Diversion" },
        { "varformat", param.varformat },
        { "varparam", param.varparam }
    };
    UsedHeaderField hf(hf_params);

    string value;
    ASSERT_TRUE(hf.getValue(req, value));
    ASSERT_EQ(value, param.expected_result);
}

INSTANTIATE_TEST_SUITE_P(YetiTest, UsedHeaderFieldTest, testing::Values(
    tparam("", "", good_na_1 + ", " + good_na_2 + ", " + good_na_3),
    tparam("uri_user", "", "user1"),
    tparam("uri_user_array", "", "user1,user2,user3"),
    tparam("uri_domain", "", "domain1"),
    tparam("uri_domain_array", "", "domain1,domain2,domain3"),
    tparam("uri_port", "", "5060"),
    tparam("uri_port_array", "", "5060,5061,5062"),
    tparam("uri_param", "uparam1", "uval11"),
    tparam("uri_param_array", "uparam1", "uval11,uval21,uval31")),

    [](const testing::TestParamInfo<UsedHeaderFieldTest::ParamType>& info) {
        string ret;

        if(info.param.varformat.empty()) ret = "raw";
        else ret = info.param.varformat;

        if(!info.param.varparam.empty())
            ret += "_" + info.param.varparam;

        return ret;
    });
