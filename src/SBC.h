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
  virtual SBCCallLeg* create(fake_logger *logger,
                             OriginationPreAuth::Reply &ip_auth_data,
                             Auth::auth_id_type auth_result_id);
  virtual SBCCallLeg* create(SBCCallLeg* caller, AmSipDialog* dlg);
  virtual ~CallLegCreator() {}
};

class SBCFactory: public AmSessionFactory,
    public AmConfigFactory,
    public AmDynInvoke,
    public AmDynInvokeFactory
{
  unique_ptr<Yeti> yeti;

  /*SqlRouter router;
  CdrList cdr_list;
  ResourceControl rctl;*/

  AmArg pre_auth_ret;
  AmDynInvoke *yeti_invoke;
  bool auth_feedback;

  bool core_options_handling;

  unique_ptr<CallLegCreator> callLegCreator;

  void postControlCmd(const AmArg& args, AmArg& ret);

  void send_auth_error_reply(const AmSipRequest& req, AmArg &ret, int auth_feedback_code);
  void send_and_log_auth_challenge(const AmSipRequest& req,
                                   const string &internal_reason,
                                   bool post_auth_log,
                                   int auth_feedback_code = 0);

 public:
  static SBCFactory* instance();

  SBCFactory(const string& _app_name);
  ~SBCFactory();

  int onLoad() override;
  int configure(const std::string& config) override;
  int reconfigure(const std::string& config) override;

  void setCallLegCreator(CallLegCreator* clc) { callLegCreator.reset(clc); }
  CallLegCreator* getCallLegCreator() { return callLegCreator.get(); }

  AmSession* onInvite(const AmSipRequest& req, const string& app_name,
                      const map<string,string>& app_params) override;

  void onOoDRequest(const AmSipRequest& req) override;

  AmSessionEventHandlerFactory* session_timer_fact;

  // hack for routing of OoD (e.g. REGISTER) messages
  AmDynInvokeFactory* gui_fact;

  AmEventQueueProcessor subnot_processor;

  // DI
  // DI factory
  AmDynInvoke* getInstance() override { return yeti_invoke; }
  // DI API
  void invoke(const string& method,
              const AmArg& args, AmArg& ret) override;

};

extern void assertEndCRLF(string& s);

#endif
