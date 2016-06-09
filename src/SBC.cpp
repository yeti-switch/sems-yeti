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

/* 
SBC - feature-wishlist
- accounting (MySQL DB, cassandra DB)
- RTP transcoding mode (bridging)
- overload handling (parallel call to target thresholds)
- call distribution
- select profile on monitoring in-mem DB record
 */
#include "SBC.h"

#include "SBCCallControlAPI.h"

#include "log.h"
#include "AmUtils.h"
#include "AmAudio.h"
#include "AmPlugIn.h"
#include "AmMediaProcessor.h"
#include "AmConfigReader.h"
#include "AmSessionContainer.h"
#include "AmSipHeaders.h"
#include "SBCSimpleRelay.h"
#include "RegisterDialog.h"
#include "SubscriptionDialog.h"
#include "sip/pcap_logger.h"
#include "sip/sip_parser.h"
#include "sip/sip_trans.h"

#include "HeaderFilter.h"
#include "ParamReplacer.h"
#include "SDPFilter.h"
#include "SBCCallLeg.h"

#include "AmEventQueueProcessor.h"

#include "SubscriptionDialog.h"
#include "RegisterDialog.h"
#include "RegisterCache.h"

#include <algorithm>

#include "yeti.h"

using std::map;

EXPORT_MODULE_FACTORY(SBCFactory);
DEFINE_MODULE_INSTANCE(SBCFactory, MOD_NAME);

// helper functions

void assertEndCRLF(string& s) {
  if (s[s.size()-2] != '\r' ||
      s[s.size()-1] != '\n') {
    while ((s[s.size()-1] == '\r') ||
	   (s[s.size()-1] == '\n'))
      s.erase(s.size()-1);
    s += "\r\n";
  }
}

///////////////////////////////////////////////////////////////////////////////////////////

SBCCallLeg* CallLegCreator::create(const SBCCallProfile& call_profile, SqlRouter &router)
{
  return new SBCCallLeg(call_profile, router, new AmSipDialog());
}

SBCCallLeg* CallLegCreator::create(SBCCallLeg* caller, SqlRouter &router)
{
  return new SBCCallLeg(caller, router);
}

SimpleRelayCreator::Relay 
SimpleRelayCreator::createRegisterRelay(SBCCallProfile& call_profile,
					vector<AmDynInvoke*> &cc_modules)
{
  return SimpleRelayCreator::Relay(new RegisterDialog(call_profile, cc_modules),
				   new RegisterDialog(call_profile, cc_modules));
}

SimpleRelayCreator::Relay
SimpleRelayCreator::createSubscriptionRelay(SBCCallProfile& call_profile,
					    vector<AmDynInvoke*> &cc_modules)
{
  return SimpleRelayCreator::Relay(new SubscriptionDialog(call_profile, cc_modules),
				   new SubscriptionDialog(call_profile, cc_modules));
}

SimpleRelayCreator::Relay
SimpleRelayCreator::createGenericRelay(SBCCallProfile& call_profile,
				       vector<AmDynInvoke*> &cc_modules)
{
  return SimpleRelayCreator::Relay(new SimpleRelayDialog(call_profile, cc_modules),
				   new SimpleRelayDialog(call_profile, cc_modules));
}

SBCFactory::SBCFactory(const string& _app_name)
  : AmSessionFactory(_app_name), 
    AmDynInvokeFactory(_app_name),
    core_options_handling(false),
    callLegCreator(new CallLegCreator()),
    simpleRelayCreator(new SimpleRelayCreator())
{
}

SBCFactory::~SBCFactory() {
  RegisterCache::dispose();
  yeti.reset();
}

int SBCFactory::onLoad()
{
  if(cfg.loadFile(AmConfig::ModConfigPath + string(MOD_NAME ".conf"))) {
    ERROR("No configuration for sbc present (%s)\n",
	 (AmConfig::ModConfigPath + string(MOD_NAME ".conf")).c_str()
	 );
    return -1;
  }

  yeti.reset(Yeti::create_instance(router,cdr_list,rctl));
  if(yeti->onLoad()){
      ERROR("yeti configuration error\n");
      return -1;
  }
  yeti_invoke = dynamic_cast<AmDynInvoke *>(yeti.get());

  registrations_enabled = cfg.getParameter("registrations_enabled","yes")=="yes";

  session_timer_fact = AmPlugIn::instance()->getFactory4Seh("session_timer");
  if(!session_timer_fact) {
    WARN("session_timer plug-in not loaded - "
	 "SIP Session Timers will not be supported\n");
  }

  vector<string> regex_maps = explode(cfg.getParameter("regex_maps"), ",");
  for (vector<string>::iterator it =
	 regex_maps.begin(); it != regex_maps.end(); it++) {
    string regex_map_file_name = AmConfig::ModConfigPath + *it + ".conf";
    RegexMappingVector v;
    if (!read_regex_mapping(regex_map_file_name, "=>",
			    ("SBC regex mapping " + *it+":").c_str(), v)) {
      ERROR("reading regex mapping from '%s'\n", regex_map_file_name.c_str());
      return -1;
    }
    regex_mappings.setRegexMap(*it, v);
    INFO("loaded regex mapping '%s'\n", it->c_str());
  }

  core_options_handling = cfg.getParameter("core_options_handling") == "yes";
  DBG("OPTIONS messages handled by the core: %s\n", core_options_handling?"yes":"no");

  if (!AmPlugIn::registerApplication(MOD_NAME, this)) {
    ERROR("registering "MOD_NAME" application\n");
    return -1;
  }

  if (!AmPlugIn::registerDIInterface(MOD_NAME, this)) {
    ERROR("registering "MOD_NAME" DI interface\n");
    return -1;
  }

  // TODO: add config param for the number of threads
  subnot_processor.addThreads(1);
  if(registrations_enabled)
	RegisterCache::instance()->start();

  return 0;
}

AmSession* SBCFactory::onInvite(const AmSipRequest& req, const string& app_name,
				const map<string,string>& app_params)
{
  ParamReplacerCtx ctx;
  ctx.app_param = getHeader(req.hdrs, PARAM_HDR, true);

  CallCtx *call_ctx = yeti->getCallCtx(req,ctx);
  if(!call_ctx) return NULL;

  SBCCallLeg* b2b_dlg = callLegCreator.get()->create(
    *call_ctx->getCurrentProfile(),router);
  if(!b2b_dlg) return NULL;

  b2b_dlg->setCallCtx(call_ctx);

  SBCCallProfile& call_profile = b2b_dlg->getCallProfile();

  //msg_logger* logger = b2b_dlg->getCallProfile().get_logger(req);
  //if (logger && call_profile.log_sip) req.log(logger);

  if (call_profile.auth_aleg_enabled) {
    // adding auth handler
    AmSessionEventHandlerFactory* uac_auth_f =
      AmPlugIn::instance()->getFactory4Seh("uac_auth");
    if (NULL == uac_auth_f)  {
      INFO("uac_auth module not loaded. uac auth for caller session NOT enabled.\n");
    } else {
      AmSessionEventHandler* h = uac_auth_f->getHandler(b2b_dlg);

      // we cannot use the generic AmSessionEventHandler hooks,
      // because the hooks don't work in AmB2BSession
      b2b_dlg->setAuthHandler(h);
      DBG("uac auth enabled for caller session.\n");
    }
  }

  return b2b_dlg;
}

void SBCFactory::onOoDRequest(const AmSipRequest& req)
{
  DBG("processing message %s %s\n", req.method.c_str(), req.r_uri.c_str());  

  if (core_options_handling && req.method == SIP_METH_OPTIONS) {
    DBG("processing OPTIONS in core\n");
    AmSessionFactory::onOoDRequest(req);
    return;
  }
  AmSipDialog::reply_error(req, 405, "Method Not Allowed");
  return;
#if 0
  if(req.max_forwards == 0) {
    AmSipDialog::reply_error(req, 483, SIP_REPLY_TOO_MANY_HOPS);
    return;
  }
  
  SimpleRelayCreator::Relay relay(NULL,NULL);
  if(req.method == SIP_METH_REGISTER) {
	if(registrations_enabled) {
		relay = simpleRelayCreator->createRegisterRelay(call_profile, cc_modules);
	} else {
		AmSipDialog::reply_error(req,405,"Method Not Allowed");
		return;
	}
  }
  else if((req.method == SIP_METH_SUBSCRIBE) ||
	  (req.method == SIP_METH_REFER)){

    relay = simpleRelayCreator->createSubscriptionRelay(call_profile, cc_modules);
  }
  else {
    relay = simpleRelayCreator->createGenericRelay(call_profile, cc_modules);
  }
  if (call_profile.log_sip) {
    relay.first->setMsgLogger(call_profile.get_logger(req));
    relay.second->setMsgLogger(call_profile.get_logger(req));
  }

  if(SBCSimpleRelay::start(relay,req,call_profile)) {
    AmSipDialog::reply_error(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR, 
				 "", call_profile.log_sip ? call_profile.get_logger(req): NULL);
    delete relay.first;
    delete relay.second;
  }
#endif
}

void SBCFactory::invoke(const string& method, const AmArg& args, 
				AmArg& ret)
{
  if (method == "getRegexMapNames"){
    getRegexMapNames(args,ret);
  } else if (method == "setRegexMap"){
    args.assertArrayFmt("u");
    setRegexMap(args,ret);
  } else if (method == "postControlCmd"){
    args.assertArrayFmt("ss"); // at least call-ltag, cmd
    postControlCmd(args,ret);
  } else if(method == "_list"){ 
    ret.push(AmArg("getRegexMapNames"));
    ret.push(AmArg("setRegexMap"));
    ret.push(AmArg("postControlCmd"));
    ret.push(AmArg("printCallStats"));
  } else if(method == "printCallStats"){ 
    B2BMediaStatistics::instance()->getReport(args, ret);
  }  else
    throw AmDynInvoke::NotImplemented(method);
}

void SBCFactory::getRegexMapNames(const AmArg& args, AmArg& ret) {
  AmArg p;
  vector<string> reg_names = regex_mappings.getNames();
  for (vector<string>::iterator it=reg_names.begin();
       it != reg_names.end(); it++) {
    p["regex_maps"].push(*it);
  }
  ret.push(200);
  ret.push("OK");
  ret.push(p);
}

void SBCFactory::setRegexMap(const AmArg& args, AmArg& ret) {
  if (!args[0].hasMember("name") || !args[0].hasMember("file") ||
      !isArgCStr(args[0]["name"]) || !isArgCStr(args[0]["file"])) {
    ret.push(400);
    ret.push("Parameters error: expected ['name': <name>, 'file': <file name>]");
    return;
  }

  string m_name = args[0]["name"].asCStr();
  string m_file = args[0]["file"].asCStr();
  RegexMappingVector v;
  if (!read_regex_mapping(m_file, "=>", "SBC regex mapping", v)) {
    ERROR("reading regex mapping from '%s'\n", m_file.c_str());
    ret.push(401);
    ret.push("Error reading regex mapping from file");
    return;
  }
  regex_mappings.setRegexMap(m_name, v);
  ret.push(200);
  ret.push("OK");
}

void SBCFactory::postControlCmd(const AmArg& args, AmArg& ret) {
  SBCControlEvent* evt;
  if (args.size()<3) {
    evt = new SBCControlEvent(args[1].asCStr());
  } else {
    evt = new SBCControlEvent(args[1].asCStr(), args[2]);
  }
  if (!AmSessionContainer::instance()->postEvent(args[0].asCStr(), evt)) {
    ret.push(404);
    ret.push("Not found");
  } else {
    ret.push(202);
    ret.push("Accepted");
  }
}

ExtendedCCInterface &getExtCCInterface()
{
    return dynamic_cast<ExtendedCCInterface &>(Yeti::instance());
}

