#include "YetiTest.h"
#include "../src/cdr/CdrHeaders.h"
#include "jsonArg.h"

TEST_F(YetiTest, cdr_headers_parsing)
{
    cdr_headers_t hdrs;
    hdrs.add_header("X-StringTest", "string");
    hdrs.add_header("X-ArrayTest", "array");
    hdrs.add_header("X-SmallintTest", "smallint");
    hdrs.add_header("X-SmallintOverflowDigitsTest", "smallint");
    hdrs.add_header("X-SmallintOverflowMaxTest", "smallint");
    hdrs.add_header("X-SmallintOverflowMinTest", "smallint");
    hdrs.add_header("X-IntegerTest", "integer");
    hdrs.add_header("X-IntegerOverflowMaxTest", "integer");
    hdrs.add_header("X-IntegerOverflowMinTest", "integer");
    hdrs.add_header("X-IntegerConversionOverflowTest", "integer");

    auto ret = hdrs.serialize_headers(
        "X-StringTest: qwe\r\n"
        "X-ArrayTest: rty\r\n"
        "X-ArrayTest: asd\r\n"
        "X-SmallintTest: 42\r\n"
        "X-SmallintOverflowDigitsTest: 12345678901\r\n"
        "X-SmallintOverflowMaxTest: 65535\r\n"
        "X-SmallintOverflowMinTest: -65535\r\n"
        "X-IntegerTest: 42\r\n"
        "X-IntegerOverflowMaxTest: 3147483648\r\n"
        "X-IntegerOverflowMinTest: -3147483649\r\n"
        "X-IntegerConversionOverflowTest: -3147483648\r\n"
    );

    DBG("%s", arg2json(ret).data());

    ASSERT_EQ(ret["x_stringtest"], AmArg("qwe"));

    ASSERT_EQ(ret["x_arraytest"], (AmArg{"rty","asd"}));

    ASSERT_EQ(ret["x_smallinttest"], AmArg(42));
    ASSERT_EQ(ret["x_smallintoverflowdigitstest"], AmArg());
    ASSERT_EQ(ret["x_smallintoverflowmaxtest"], AmArg());
    ASSERT_EQ(ret["x_smallintoverflowmintest"], AmArg());

    ASSERT_EQ(ret["x_integertest"], AmArg(42));
    ASSERT_EQ(ret["x_integeroverflowmintest"], AmArg());
    ASSERT_EQ(ret["x_integeroverflowmaxtest"], AmArg());
    ASSERT_EQ(ret["x_integerconversionoverflowtest"], AmArg());
}
