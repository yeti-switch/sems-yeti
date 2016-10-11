#ifndef DTMF_SIP_INFO_H
#define DTMF_SIP_INFO_H

#include "AmEvent.h"
#include "AmSipDialog.h"
#include "AmDtmfDetector.h"
#include "AmB2BSession.h"

namespace yeti_dtmf {

enum dtmf_info_mode { DTMF, DTMF_RELAY };

template<enum dtmf_info_mode method>
void send_dtmf(AmSipDialog *dlg, AmDtmfEvent* dtmf);

class DtmfInfoSendEvent: public AmDtmfEvent {
	dtmf_info_mode m_type;
  public:
	DtmfInfoSendEvent(int event, int duration, dtmf_info_mode type):
		AmDtmfEvent(event,duration), m_type(type)
			{ event_id = B2BDtmfEvent; }
	DtmfInfoSendEvent(AmDtmfEvent *e, dtmf_info_mode type):
		AmDtmfEvent(e->event(),e->duration()), m_type(type)
			{ event_id = B2BDtmfEvent;}
	const dtmf_info_mode type() { return m_type; }
	void send(AmSipDialog *dlg);
};

class DtmfInfoSendEventDtmf: public DtmfInfoSendEvent {
  public:
	DtmfInfoSendEventDtmf(AmDtmfEvent *e):
		DtmfInfoSendEvent(e,DTMF) {}
};

class DtmfInfoSendEventDtmfRelay: public DtmfInfoSendEvent {
  public:
	DtmfInfoSendEventDtmfRelay(AmDtmfEvent *e):
		DtmfInfoSendEvent(e,DTMF_RELAY) {}
};

}

#endif // DTMF_SIP_INFO_H
