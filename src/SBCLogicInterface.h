#ifndef _SBC_LOGIC_INTERFACE_H
#define _SBC_LOGIC_INTERFACE_H

#include "AmSipMsg.h"
#include "ParamReplacer.h"

#include "SBC.h"
struct CallLegCreator;

#include "SBCCallLeg.h"
class SBCCallLeg;

enum getProfileRequestType {
    InDialogRequest,
    OutOfDialogRequest
};

class SBCLogicInterface
{
  public:
    virtual SBCCallLeg *getCallLeg( const AmSipRequest& req,
                                    ParamReplacerCtx& ctx,
                                    CallLegCreator *leg_creator ) = 0;

    };

#endif //_SBC_LOGIC_INTERFACE_H
