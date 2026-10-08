/*
 * Copyright (C) 2010 Stefan Sayer
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * For a license to use the SEMS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * SEMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "HeaderFilter.h"
#include "log.h"
#include "AmUtils.h"
#include <algorithm>

const char *FilterType2String(FilterType ft)
{
    switch (ft) {
    case Transparent: return "transparent";
    case Whitelist:   return "whitelist";
    case Blacklist:   return "blacklist";
    default:          return "unknown";
    };
}

FilterType String2FilterType(const char *ft)
{
    if (!ft)
        return Undefined;

    if (!strcasecmp(ft, "transparent"))
        return Transparent;

    if (!strcasecmp(ft, "whitelist"))
        return Whitelist;

    if (!strcasecmp(ft, "blacklist"))
        return Blacklist;

    return Undefined;
}

bool isActiveFilter(FilterType ft)
{
    return (ft != Undefined) && (ft != Transparent);
}

/** @return whether successful */
bool readFilter(AmConfigReader &cfg, const char *cfg_key_filter, const char *cfg_key_list,
                vector<FilterEntry> &filter_list, bool keep_transparent_entry)
{
    string filter = cfg.getParameter(cfg_key_filter);
    if (filter.empty())
        return true;

    FilterEntry hf;
    hf.filter_type = String2FilterType(filter.c_str());
    if (Undefined == hf.filter_type) {
        ERROR("invalid %s mode '%s'", cfg_key_filter, filter.c_str());
        return false;
    }

    // no transparent filter
    if (!keep_transparent_entry && hf.filter_type == Transparent)
        return true;

    vector<string> elems = explode(cfg.getParameter(cfg_key_list), ",");
    for (vector<string>::iterator it = elems.begin(); it != elems.end(); it++) {
        string c = *it;
        std::transform(c.begin(), c.end(), c.begin(), ::tolower);
        hf.filter_list.insert(c);
    }

    filter_list.push_back(hf);
    return true;
}

/** erase headers whose lowercased name is (black list) or is not (white list) matched */
template <typename Match> static void eraseHeaders(AmSipHeaderMap &hdrs, FilterType f_type, Match match)
{
    for (auto it = hdrs.begin(); it != hdrs.end();) {
        string hdr_name = it->first;
        std::transform(hdr_name.begin(), hdr_name.end(), hdr_name.begin(), ::tolower);

        bool erase = false;
        if (f_type == Whitelist) {
            erase = !match(hdr_name);
        } else if (f_type == Blacklist) {
            erase = match(hdr_name);
        }

        if (erase) {
            DBG("erasing header '%s' by %s", hdr_name.c_str(), FilterType2String(f_type));
            it = hdrs.erase(it);
        } else {
            ++it;
        }
    }
}

int inplaceHeaderFilter(AmSipHeaderMap &hdrs, const vector<FilterEntry> &filter_list)
{
    if (hdrs.empty() || filter_list.empty())
        return 0;

    DBG("applying %zd header filters", filter_list.size());

    for (const auto &fe : filter_list) {
        if (!isActiveFilter(fe.filter_type))
            continue;
        const set<string> &headerfilter_list = fe.filter_list;
        eraseHeaders(hdrs, fe.filter_type,
                     [&](const string &name) { return headerfilter_list.find(name) != headerfilter_list.end(); });
    }

    return 0;
}


class PatternMatchFunctor {
    const string &v;

  public:
    PatternMatchFunctor(const string &v)
        : v(v)
    {
    }
    bool match(const string &p) const
    {
        if (*p.begin() == '*') {
            // endwith
            size_t plen = p.size() - 1;
            if (plen == 0)
                return true; // any
            size_t vlen = v.size();
            if (plen > vlen)
                return false;
            return 0 == memcmp(p.data() + 1, v.data() + vlen - plen, plen);
        } else if (*p.rbegin() == '*') {
            // startwith
            size_t plen = p.size() - 1;
            size_t vlen = v.size();
            if (plen > vlen)
                return false;
            return 0 == memcmp(p.data(), v.data(), plen);
        } else {
            // full
            return p == v;
        }
    }
    bool operator()(const string &p) const
    {
        if (match(p)) {
            DBG("'%s' matched with '%s'", v.c_str(), p.c_str());
            return true;
        }
        return false;
    }
};

inline bool matchListPattern(const string &s, const set<string> &l)
{
    if (s.empty())
        return false;
    PatternMatchFunctor f(s);
    return std::find_if(l.begin(), l.end(), f) != l.end();
}

int inplaceHeaderPatternFilter(AmSipHeaderMap &hdrs, const vector<FilterEntry> &filter_list)
{
    if (hdrs.empty() || filter_list.empty())
        return 0;

    DBG("applying %zd header pattern filters", filter_list.size());

    for (const auto &fe : filter_list) {
        if (!isActiveFilter(fe.filter_type))
            continue;
        const set<string> &headerfilter_list = fe.filter_list;
        eraseHeaders(hdrs, fe.filter_type,
                     [&](const string &name) { return matchListPattern(name, headerfilter_list); });
    }
    return 0;
}
