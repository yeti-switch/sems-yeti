#include "YetiTest.h"
#include "../src/HeaderFilter.h"

TEST_F(YetiTest, inplaceHeaderFilter)
{
    {
        vector<FilterEntry> filters;
        FilterEntry         entry;
        entry.filter_type = FilterType::Whitelist;
        entry.filter_list.emplace("x-origin");
        filters.push_back(entry);
        string headers("Host: domain.invalid\r\nX-Origin: test\r\nContent-Type: application/json\r\n");
        ASSERT_FALSE(inplaceHeaderFilter(headers, filters));
        ASSERT_EQ(headers, string("X-Origin: test\r\n"));
    }
    {
        vector<FilterEntry> filters;
        FilterEntry         entry;
        entry.filter_type = FilterType::Blacklist;
        entry.filter_list.emplace("x-origin");
        filters.push_back(entry);
        string headers("Host: domain.invalid\r\nX-Origin: test\r\nContent-Type: application/json\r\n");
        ASSERT_FALSE(inplaceHeaderFilter(headers, filters));
        ASSERT_EQ(headers, string("Host: domain.invalid\r\nContent-Type: application/json\r\n"));
    }
    {
        vector<FilterEntry> filters;
        FilterEntry         entry;
        entry.filter_type = FilterType::Blacklist;
        entry.filter_list.emplace("x-origin");
        filters.push_back(entry);
        entry.filter_type = FilterType::Whitelist;
        filters.push_back(entry);
        string headers("Host: domain.invalid\r\nX-Origin: test\r\nContent-Type: application/json\r\n");
        ASSERT_FALSE(inplaceHeaderFilter(headers, filters));
        ASSERT_TRUE(headers.empty());
    }
}

TEST_F(YetiTest, inplaceHeaderFilterPattern)
{
    {
        vector<FilterEntry> filters;
        FilterEntry         entry;
        entry.filter_type = FilterType::Whitelist;
        entry.filter_list.emplace("x-*");
        filters.push_back(entry);
        string headers("Host: domain.invalid\r\nX-Origin: test\r\nContent-Type: application/json\r\n");
        ASSERT_FALSE(inplaceHeaderPatternFilter(headers, filters));
        ASSERT_EQ(headers, string("X-Origin: test\r\n"));
    }
    {
        vector<FilterEntry> filters;
        FilterEntry         entry;
        entry.filter_type = FilterType::Blacklist;
        entry.filter_list.emplace("x-*");
        filters.push_back(entry);
        string headers("Host: domain.invalid\r\nX-Origin: test\r\nContent-Type: application/json\r\n");
        ASSERT_FALSE(inplaceHeaderPatternFilter(headers, filters));
        ASSERT_EQ(headers, string("Host: domain.invalid\r\nContent-Type: application/json\r\n"));
    }
    {
        vector<FilterEntry> filters;
        FilterEntry         entry;
        entry.filter_type = FilterType::Blacklist;
        entry.filter_list.emplace("x-*");
        filters.push_back(entry);
        entry.filter_type = FilterType::Whitelist;
        filters.push_back(entry);
        string headers("Host: domain.invalid\r\nX-Origin: test\r\nContent-Type: application/json\r\n");
        ASSERT_FALSE(inplaceHeaderFilter(headers, filters));
        ASSERT_TRUE(headers.empty());
    }
}
