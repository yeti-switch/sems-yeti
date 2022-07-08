#include "CodecsGroup.h"
#include "AmUtils.h"
#include "AmPlugIn.h"
#include "AmThread.h"
#include "log.h"
#include "amci/amci.h"
#include "RTPParameters.h"
#include "yeti.h"
#include "db/DbHelpers.h"

#include <algorithm>

//#define ERROR_ON_UNKNOWN_CODECS

CodecsGroups* CodecsGroups::_instance=0;

static void replace(string& s, const string& from, const string& to){
	size_t pos = 0;
	while ((pos = s.find(from, pos)) != string::npos) {
		s.replace(pos, from.length(), to);
		pos += s.length();
	}
}

CodecsGroupException::CodecsGroupException(
	unsigned int code,
	unsigned int codecs_group)
	: InternalException(code,0)
{
	string s = int2str(codecs_group);
	replace(internal_reason,"$cg",s);
	replace(response_reason,"$cg",s);
}

//copied from SBCCallProfile.cpp
static bool readPayload(SdpPayload &p, const string &src)
{
	vector<string> elems = explode(src, "/");

	if (elems.size() < 1) return false;

	if (elems.size() > 2) str2int(elems[2], p.encoding_param);
	if (elems.size() > 1) str2int(elems[1], p.clock_rate);
	else p.clock_rate = 8000; // default value
	p.encoding_name = elems[0];

	string pname = p.encoding_name;
	std::transform(pname.begin(), pname.end(), pname.begin(), ::toupper);

	// fix static payload type numbers
	// (http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xml)
	for (int i = 0; i < IANA_RTP_PAYLOADS_SIZE; i++) {
		string s = IANA_RTP_PAYLOADS[i].payload_name;
		std::transform(s.begin(), s.end(), s.begin(), ::toupper);
		if (p.encoding_name == s &&
			(unsigned)p.clock_rate == IANA_RTP_PAYLOADS[i].clock_rate &&
			(p.encoding_param == -1 || ((unsigned)p.encoding_param == IANA_RTP_PAYLOADS[i].channels)))
		p.payload_type = i;
	}
	return true;
}

CodecsGroupEntry::CodecsGroupEntry(){
	//codecs_filter.filter_type = Whitelist;
}

bool CodecsGroupEntry::add_codec(string c, string sdp_params, int dyn_payload_id){
	SdpPayload p;
	AmPlugIn* plugin = AmPlugIn::instance();

	//std::transform(c.begin(), c.end(), c.begin(), ::toupper);
	//codecs_filter.filter_list.insert(c);
	if (!readPayload(p, c)){
		ERROR("CodecsGroupEntry() can't read payload '%s'",c.c_str());
		return false;
	}
	int payload_id = plugin->getDynPayload(p.encoding_name, p.clock_rate, 0);
	amci_payload_t* payload = plugin->payload(payload_id);
	if(!payload) {
		ERROR("Ignoring unknown payload: %s/%i",
			p.encoding_name.c_str(), p.clock_rate);
#ifdef ERROR_ON_UNKNOWN_CODECS
		return false;
#else
		return true;
#endif
	}

	p.sdp_format_parameters = sdp_params;

	if(payload_id < DYNAMIC_PAYLOAD_TYPE_START) {
		p.payload_type = payload->payload_id;
	} else {
		if(dyn_payload_id != -1){
			DBG("found dyn_payload_id %d for codec %s/%i",
				dyn_payload_id, p.encoding_name.c_str(), p.clock_rate);
			if (dyn_payload_id < DYNAMIC_PAYLOAD_TYPE_START) {
				ERROR("Ignoring dyn_payload_id %d for %s/%i. it mustn't be less than %d",
					  dyn_payload_id, p.encoding_name.c_str(), p.clock_rate,
					  DYNAMIC_PAYLOAD_TYPE_START);
				p.payload_type = -1;
			} else {
				p.payload_type = dyn_payload_id;
			}
		} else {
			p.payload_type = -1;
		}
	}

	codecs_payloads.push_back(p);
	return true;
}

void CodecsGroupEntry::getConfig(AmArg &ret) const {
	vector<SdpPayload>::const_iterator it = codecs_payloads.begin();
	for(;it!=codecs_payloads.end();++it){
		AmArg c;
		const SdpPayload &p = *it;
		/*c["payload_type"] = p.payload_type;
		c["encoding_name"] = p.encoding_name;
		c["clock_rate"] = p.clock_rate;*/
		c = p.encoding_name+"/"+int2str(p.clock_rate);
		ret.push(c);
	}
}

int CodecsGroups::configure(AmConfigReader & )
{
	return 0;
}

void CodecsGroups::load_codecs(const AmArg &data)
{
	map<unsigned int,CodecsGroupEntry> _m;

	if(isArgArray(data)) {
		for(size_t i = 0; i < data.size(); i++) {
			auto &row = data[i];
			//DbAmArg_hash_get_str
			unsigned int group_id = DbAmArg_hash_get_int(row, "o_codec_group_id", 0);
			int dyn_payload_id = DbAmArg_hash_get_int(row, "o_dynamic_payload_id", -1);
			string sdp_format_params = DbAmArg_hash_get_str(row, "o_format_params");
			string codec = DbAmArg_hash_get_str(row, "o_codec_name");
			if(!insert(_m,group_id,codec,sdp_format_params, dyn_payload_id)){
				ERROR("can't insert codec '%s'",codec.data());
				return;
			} else {
				DBG("codec '%s' added to group %d",codec.c_str(),group_id);
			}
		}
	}

	INFO("codecs groups are loaded successfully. apply changes");

	AmLock l(codec_groups_mutex);
	codec_groups.swap(_m);
}

void CodecsGroups::GetConfig(AmArg& ret) {
	AmArg &groups = ret["groups"];
	AmLock l(codec_groups_mutex);
	for(const auto &g : codec_groups) {
		g.second.getConfig(groups[int2str(g.first)]);
	}
}
