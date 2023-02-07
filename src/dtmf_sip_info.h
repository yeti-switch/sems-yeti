#pragma once

#include "AmEvent.h"
#include "AmSipDialog.h"
#include "AmDtmfDetector.h"
#include "AmB2BSession.h"

namespace yeti_dtmf {

enum dtmf_info_mode { DTMF, DTMF_RELAY };

template<enum dtmf_info_mode method>
void send_dtmf(AmSipDialog *dlg, AmDtmfEvent* dtmf);

class DtmfInfoSendEvent
  : public AmDtmfEvent
{
    dtmf_info_mode m_type;

  public:
    DtmfInfoSendEvent(int event, int duration, dtmf_info_mode type)
      : AmDtmfEvent(event, duration, -1,
                    Dtmf::SOURCE_DETECTOR),
        m_type(type)
    {
        event_id = B2BDtmfEvent;
    }

    DtmfInfoSendEvent(AmDtmfEvent *e, dtmf_info_mode type)
      : AmDtmfEvent(e->event(), e->duration(), e->volume(),
                    Dtmf::SOURCE_DETECTOR),
        m_type(type)
    {
        event_id = B2BDtmfEvent;
    }

    dtmf_info_mode type() {
        return m_type;
    }

    void send(AmSipDialog *dlg);
};

struct DtmfInfoSendEventDtmf: public DtmfInfoSendEvent {
    DtmfInfoSendEventDtmf(AmDtmfEvent *e)
      : DtmfInfoSendEvent(e, DTMF)
    {}
};

struct DtmfInfoSendEventDtmfRelay: public DtmfInfoSendEvent {
    DtmfInfoSendEventDtmfRelay(AmDtmfEvent *e)
      : DtmfInfoSendEvent(e, DTMF_RELAY)
    {}
};

}
