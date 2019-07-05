/*
 * Copyright (C) 2010-2011 Stefan Sayer
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

#ifndef _SBC_H
#define _SBC_H

#include "AmB2BSession.h"

#include "AmConfigReader.h"
#include "AmUriParser.h"
#include "HeaderFilter.h"
#include "SBCCallProfile.h"
#include "RegexMapper.h"
#include "AmEventQueueProcessor.h"

#include "yeti.h"
class Yeti;

#include "SqlRouter.h"
#include "hash/CdrList.h"
#include "resources/ResourceControl.h"

#include "CallLeg.h"
class SBCCallLeg;

#include <map>

using std::string;

#define SBC_TIMER_ID_CALL_TIMERS_START   10
#define SBC_TIMER_ID_CALL_TIMERS_END     99

struct CallLegCreator {
  virtual SBCCallLeg* create(CallCtx *call_ctx);
  virtual SBCCallLeg* create(SBCCallLeg* caller);
};

class SimpleRelayDialog;

struct SimpleRelayCreator {
  typedef pair<SimpleRelayDialog*,SimpleRelayDialog*> Relay;
  virtual Relay createRegisterRelay(SBCCallProfile& call_profile,
				    vector<AmDynInvoke*> &cc_modules);
  virtual Relay createSubscriptionRelay(SBCCallProfile& call_profile,
					vector<AmDynInvoke*> &cc_modules);
  virtual Relay createGenericRelay(SBCCallProfile& call_profile,
				   vector<AmDynInvoke*> &cc_modules);
};

class SBCFactory: public AmSessionFactory,
    public AmConfigFactory,
    public AmDynInvoke,
    public AmDynInvokeFactory
{
  auto_ptr<Yeti> yeti;

  SqlRouter router;
  CdrList cdr_list;
  ResourceControl rctl;

  AmDynInvoke *yeti_invoke;
  bool registrations_enabled;
  bool registrar_enabled;

  bool core_options_handling;

  auto_ptr<CallLegCreator> callLegCreator;
  auto_ptr<SimpleRelayCreator> simpleRelayCreator;

  void postControlCmd(const AmArg& args, AmArg& ret);

  void processAuthorizedRegister(const AmSipRequest& req, Auth::auth_id_type auth_id);

 public:
  static SBCFactory* instance();

  SBCFactory(const string& _app_name);
  ~SBCFactory();

  int onLoad();
  int configure(const std::string& config) override;

  void setCallLegCreator(CallLegCreator* clc) { callLegCreator.reset(clc); }
  CallLegCreator* getCallLegCreator() { return callLegCreator.get(); }

  void setSimpleRelayCreator(SimpleRelayCreator* src) { 
    simpleRelayCreator.reset(src); 
  }
  SimpleRelayCreator* getSimpleRelayCreator() { return simpleRelayCreator.get(); }

  AmSession* onInvite(const AmSipRequest& req, const string& app_name,
		      const map<string,string>& app_params);

  void onOoDRequest(const AmSipRequest& req);

  AmSessionEventHandlerFactory* session_timer_fact;

  // hack for routing of OoD (e.g. REGISTER) messages
  AmDynInvokeFactory* gui_fact;

  AmEventQueueProcessor subnot_processor;

  // DI
  // DI factory
  AmDynInvoke* getInstance() { return yeti_invoke; }
  // DI API
  void invoke(const string& method, 
	      const AmArg& args, AmArg& ret);

};

extern void assertEndCRLF(string& s);

#endif
