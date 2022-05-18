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
#include "sip/parse_common.h"
#include "log.h"
#include "AmUtils.h"
#include <algorithm>

const char* FilterType2String(FilterType ft) {
    switch(ft) {
    case Transparent: return "transparent";
    case Whitelist: return "whitelist";
    case Blacklist: return "blacklist";
    default: return "unknown";
    };
}

FilterType String2FilterType(const char* ft) {
    if (!ft)
	return Undefined;

    if (!strcasecmp(ft,"transparent"))
	return Transparent;

    if (!strcasecmp(ft,"whitelist"))
	return Whitelist;

    if (!strcasecmp(ft,"blacklist"))
	return Blacklist;

    return Undefined;
}

bool isActiveFilter(FilterType ft) {
    return (ft != Undefined) && (ft != Transparent);
}

/** @return whether successful */
bool readFilter(AmConfigReader& cfg, const char* cfg_key_filter, const char* cfg_key_list,
		vector<FilterEntry>& filter_list, bool keep_transparent_entry) {
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
    if (!keep_transparent_entry && hf.filter_type==Transparent)
	return true;

    vector<string> elems = explode(cfg.getParameter(cfg_key_list), ",");
    for (vector<string>::iterator it=elems.begin(); it != elems.end(); it++) {
	string c = *it;
	std::transform(c.begin(), c.end(), c.begin(), ::tolower);
	hf.filter_list.insert(c);
    }

    filter_list.push_back(hf);
    return true;
}

int skip_header(const std::string& hdr, size_t start_pos, 
		size_t& name_end, size_t& val_begin,
		size_t& val_end, size_t& hdr_end) {
    // adapted from sip/parse_header.cpp

    name_end = val_begin = val_end = start_pos;
    hdr_end = hdr.length();

    //
    // Header states
    //
    enum {
	H_NAME=0,
	H_HCOLON,
	H_VALUE_SWS,
	H_VALUE,
    };

    int st = H_NAME;
    int saved_st = 0;

    
    size_t p = start_pos;
    for(;p<hdr.length() && st != ST_LF && st != ST_CRLF;p++){

	switch(st){

	case H_NAME:
	    switch(hdr[p]){

		case_CR_LF;

	    case HCOLON:
		st = H_VALUE_SWS;
		name_end = p;
		break;

	    case SP:
	    case HTAB:
		st = H_HCOLON;
		name_end = p;
		break;
	    }
	    break;

	case H_VALUE_SWS:
	    switch(hdr[p]){

		case_CR_LF;

	    case SP:
	    case HTAB:
		break;

	    default:
		st = H_VALUE;
		val_begin = p;
		break;
		
	    };
	    break;

	case H_VALUE:
	    switch(hdr[p]){
		case_CR_LF;
	    };
	    if (st==ST_CR || st==ST_LF)
		val_end = p;
	    break;

	case H_HCOLON:
	    switch(hdr[p]){
	    case HCOLON:
		st = H_VALUE_SWS;
		val_begin = p;
		break;

	    case SP:
	    case HTAB:
		break;

	    default:
		DBG("Missing ':' after header name");
		return MALFORMED_SIP_MSG;
	    }
	    break;

	    case_ST_CR(hdr[p]);

	    st = saved_st;
	    hdr_end = p;
	    break;
	}
    }
    
    hdr_end = p;
    if (p==hdr.length() && st==H_VALUE) {
	val_end = p;	
    }
    
    return 0;
}

int inplaceHeaderFilter(string& hdrs, const vector<FilterEntry>& filter_list) {
    if (!hdrs.length() || ! filter_list.size())
	return 0;

    DBG("applying %zd header filters", filter_list.size());

    for (vector<FilterEntry>::const_iterator fe =
	     filter_list.begin(); fe != filter_list.end(); fe++) {
	const set<string>& headerfilter_list = fe->filter_list;
	const FilterType& f_type = fe->filter_type; 

	if (!isActiveFilter(f_type))
	  continue;

	// todo: multi-line header support

	size_t start_pos = 0;
	while (start_pos<hdrs.length()) {
	    size_t name_end, val_begin, val_end, hdr_end;
	    int res;
	    if ((res = skip_header(hdrs, start_pos, name_end, val_begin,
				   val_end, hdr_end)) != 0) {
		return res;
	    }
	    string hdr_name = hdrs.substr(start_pos, name_end-start_pos);
	    std::transform(hdr_name.begin(), hdr_name.end(), hdr_name.begin(), ::tolower);
	    bool erase = false;
	    if (f_type == Whitelist) {
		erase = headerfilter_list.find(hdr_name)==headerfilter_list.end();
	    } else if (f_type == Blacklist) {
		erase = headerfilter_list.find(hdr_name)!=headerfilter_list.end();
	    }
	    if (erase) {
		DBG("erasing header '%s' by %s", hdr_name.c_str(), FilterType2String(f_type));
		hdrs.erase(start_pos, hdr_end-start_pos);
	    } else {
		start_pos = hdr_end;
	    }
	}

    }

    return 0;
}


class PatternMatchFunctor
{
	const string &v;
  public:
	PatternMatchFunctor(const string &v): v(v) {}
	bool match(const string &p) const
	{
		if(*p.begin()=='*') {
			//endwith
			size_t plen =  p.size()-1;
			if(plen==0) return true; //any
			size_t vlen = v.size();
			if(plen > vlen) return false;
			return 0==memcmp(p.data()+1,v.data()+vlen-plen,plen);
		} else if(*p.rbegin()=='*') {
			//startwith
			size_t plen =  p.size()-1;
			size_t vlen = v.size();
			if(plen > vlen) return false;
			return 0==memcmp(p.data(),v.data(),plen);
		} else {
			//full
			return p==v;
		}
	}
	bool operator() (const string &p) const
	{
		if(match(p)){
			DBG("'%s' matched with '%s'",v.c_str(),p.c_str());
			return true;
		}
		return false;
	}
};

inline bool matchListPattern(const string& s, const set<string> &l)
{
	if(s.empty()) return false;
	PatternMatchFunctor f(s);
	return std::find_if(l.begin(), l.end(), f)!=l.end();
}

int inplaceHeaderPatternFilter(string& hdrs, const vector<FilterEntry>& filter_list)
{
	if (!hdrs.length() || !filter_list.size())
		return 0;

	DBG("applying %zd header pattern filters", filter_list.size());

	for (vector<FilterEntry>::const_iterator fe =
		 filter_list.begin(); fe != filter_list.end(); fe++)
	{
		const set<string>& headerfilter_list = fe->filter_list;
		const FilterType& f_type = fe->filter_type;

		if (!isActiveFilter(f_type))
			continue;

		size_t start_pos = 0;
		while (start_pos<hdrs.length()) {
			int res;
			size_t name_end, val_begin, val_end, hdr_end;

			if ((res = skip_header(hdrs, start_pos, name_end, val_begin,
				val_end, hdr_end)) != 0)
			{
				return res;
			}

			string hdr_name = hdrs.substr(start_pos, name_end-start_pos);
			std::transform(hdr_name.begin(), hdr_name.end(), hdr_name.begin(), ::tolower);

			bool erase = false;
			if (f_type == Whitelist) {
				erase = !matchListPattern(hdr_name,headerfilter_list);
			} else if (f_type == Blacklist) {
				erase = matchListPattern(hdr_name,headerfilter_list);
			}
			if (erase) {
				DBG("erasing header '%s' by %s", hdr_name.c_str(), FilterType2String(f_type));
				hdrs.erase(start_pos, hdr_end-start_pos);
			} else {
				start_pos = hdr_end;
			}
		}
	}
	return 0;
}
