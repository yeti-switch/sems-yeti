#include "dtmf_sip_info.h"
#include "sip/defs.h"

#include "sstream"

#include "AmUtils.h"
#include "AmMimeBody.h"

//invert AmSipDtmfEvent::str2id
static inline void add_dtmf_symbol(std::stringstream &stream,int symbol_code){
	static const char symbols[6] = {'*', '#', 'A', 'B', 'C', 'D'};
	//0..9
	if(symbol_code<10){
		stream << symbol_code;
		return;
	}
	//10..15
	if(symbol_code < 16){
		stream << symbols[symbol_code-10];
		return;
	}
	//>15
	stream << symbol_code;
}

namespace yeti_dtmf {

template <>
void send_dtmf<DTMF>(AmSipDialog *dlg, AmDtmfEvent* dtmf){
	AmMimeBody body;
	AmContentType type;

	std::stringstream s;
	s << dtmf->event() << CRLF;

	string payload(s.str());

	type.setType("application");
	type.setSubType("dtmf");

	body.setContentType(type);
	body.setPayload((const unsigned char *)payload.c_str(),payload.length());

	dlg->sendRequest(SIP_METH_INFO,&body);
}

template <>
void send_dtmf<DTMF_RELAY>(AmSipDialog *dlg, AmDtmfEvent* dtmf){
	AmMimeBody body;
	AmContentType type;

	std::stringstream s;
	s << "Signal="; add_dtmf_symbol(s,dtmf->event()); s << CRLF;
	s << "Duration=" << dtmf->duration() << CRLF;

	string payload(s.str());

	type.setType("application");
	type.setSubType("dtmf-relay");

	body.setContentType(type);
	body.setPayload((const unsigned char *)payload.c_str(),payload.length());

	dlg->sendRequest(SIP_METH_INFO,&body);
}

void DtmfInfoSendEvent::send(AmSipDialog *dlg){
	switch(m_type){
	case DTMF:
		send_dtmf<DTMF>(dlg,this);
		break;
	case DTMF_RELAY:
		send_dtmf<DTMF_RELAY>(dlg,this);
		break;
	default:
		ERROR("unknown dtmf sip info event type");
	}
}

} //namespace yeti_dtmf

