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
        AmSipHeaderMap headers{
            {         "Host",   "domain.invalid" },
            {     "X-Origin",             "test" },
            { "Content-Type", "application/json" }
        };
        ASSERT_FALSE(inplaceHeaderFilter(headers, filters));
        ASSERT_EQ(headers, (AmSipHeaderMap{
                               { "X-Origin", "test" }
        }));
    }
    {
        vector<FilterEntry> filters;
        FilterEntry         entry;
        entry.filter_type = FilterType::Blacklist;
        entry.filter_list.emplace("x-origin");
        filters.push_back(entry);
        AmSipHeaderMap headers{
            {         "Host",   "domain.invalid" },
            {     "X-Origin",             "test" },
            { "Content-Type", "application/json" }
        };
        ASSERT_FALSE(inplaceHeaderFilter(headers, filters));
        ASSERT_EQ(headers, (AmSipHeaderMap{
                               {         "Host",   "domain.invalid" },
                               { "Content-Type", "application/json" }
        }));
    }
    {
        vector<FilterEntry> filters;
        FilterEntry         entry;
        entry.filter_type = FilterType::Blacklist;
        entry.filter_list.emplace("x-origin");
        filters.push_back(entry);
        entry.filter_type = FilterType::Whitelist;
        filters.push_back(entry);
        AmSipHeaderMap headers{
            {         "Host",   "domain.invalid" },
            {     "X-Origin",             "test" },
            { "Content-Type", "application/json" }
        };
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
        AmSipHeaderMap headers{
            {         "Host",   "domain.invalid" },
            {     "X-Origin",             "test" },
            { "Content-Type", "application/json" }
        };
        ASSERT_FALSE(inplaceHeaderPatternFilter(headers, filters));
        ASSERT_EQ(headers, (AmSipHeaderMap{
                               { "X-Origin", "test" }
        }));
    }
    {
        vector<FilterEntry> filters;
        FilterEntry         entry;
        entry.filter_type = FilterType::Blacklist;
        entry.filter_list.emplace("x-*");
        filters.push_back(entry);
        AmSipHeaderMap headers{
            {         "Host",   "domain.invalid" },
            {     "X-Origin",             "test" },
            { "Content-Type", "application/json" }
        };
        ASSERT_FALSE(inplaceHeaderPatternFilter(headers, filters));
        ASSERT_EQ(headers, (AmSipHeaderMap{
                               {         "Host",   "domain.invalid" },
                               { "Content-Type", "application/json" }
        }));
    }
    {
        vector<FilterEntry> filters;
        FilterEntry         entry;
        entry.filter_type = FilterType::Blacklist;
        entry.filter_list.emplace("x-*");
        filters.push_back(entry);
        entry.filter_type = FilterType::Whitelist;
        filters.push_back(entry);
        AmSipHeaderMap headers{
            {         "Host",   "domain.invalid" },
            {     "X-Origin",             "test" },
            { "Content-Type", "application/json" }
        };
        ASSERT_FALSE(inplaceHeaderFilter(headers, filters));
        ASSERT_TRUE(headers.empty());
    }
}
