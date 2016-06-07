#pragma once

#include "yeti_version.h"
#include "AmApi.h"
#include "SBCCallProfile.h"
#include "SBCCallLeg.h"
#include "sip/msg_sensor.h"

#include "SBCCallControlAPI.h"
#include "ampi/RadiusClientAPI.h"
#include "ExtendedCCInterface.h"

#include "SqlCallProfile.h"
#include "cdr/Cdr.h"
#include "SqlRouter.h"
#include "hash/CdrList.h"
#include "cdr/CdrWriter.h"
#include "resources/ResourceControl.h"
#include "CallCtx.h"
#include "CodesTranslator.h"
#include "CodecsGroup.h"
#include "Sensors.h"

#include <ctime>
#include <yeti/yeticc.h>

#define YETI_ENABLE_PROFILING 1

#define YETI_CALL_DURATION_TIMER SBC_TIMER_ID_CALL_TIMERS_START
#define YETI_RINGING_TIMEOUT_TIMER (SBC_TIMER_ID_CALL_TIMERS_START+1)
#define YETI_RADIUS_INTERIM_TIMER (SBC_TIMER_ID_CALL_TIMERS_START+2)

#if YETI_ENABLE_PROFILING

#define PROF_START(var) timeval prof_start_##var; gettimeofday(&prof_start_##var,NULL);
#define PROF_END(var) timeval prof_end_##var; gettimeofday(&prof_end_##var,NULL);
#define PROF_DIFF(var) timeval prof_diff_##var; timersub(&prof_end_##var,&prof_start_##var,&prof_diff_##var);
#define PROF_PRINT(descr,var) PROF_DIFF(var); DBG("PROFILING: "descr" took %s",timeval2str_usec(prof_diff_##var).c_str());

#else

#define PROF_START(var) ;
#define PROF_END(var) ;
#define PROF_DIFF(var) (-1)
#define PROF_PRINT(descr,var) ;

#endif

class YetiCfgReader : public AmConfigReader, public yeti::cfg::reader {
  public:
	void on_key_value_param(const string &name,const string &value){
		setParameter(name,value);
	}
};

class Yeti : public AmDynInvoke, public ExtendedCCInterface, AmObject
{
  static Yeti* _instance;

  struct RefuseException {
	  int internal_code,response_code;
	  string internal_reason,response_reason;
	  RefuseException(int ic,string ir,int rc,string rr) :
		  internal_code(ic),internal_reason(ir),
		  response_code(rc),response_reason(rr){}
  };

  CdrList cdr_list;
  ResourceControl rctl;
  SqlRouter router;
  AmArg rpc_cmds;
  YetiCfgReader cfg;
  //config values
  int calls_show_limit;

  void onLastLegDestroy(CallCtx *ctx,SBCCallLeg *call);
  /*! create new B leg (serial fork)*/
  /*! choose next profile, create cdr and check resources */
  bool connectCallee(CallCtx *call_ctx,SBCCallLeg *call,const AmSipRequest &orig_req);
  bool chooseNextProfile(SBCCallLeg *call);
  /*! return true if call refused */
  bool check_and_refuse(SqlCallProfile *profile,Cdr *cdr,
						const AmSipRequest& req,ParamReplacerCtx& ctx,
						bool send_reply = false);
  void onRadiusReply(SBCCallLeg *call, const RadiusReplyEvent &ev);
  void onInterimRadiusTimer(SBCCallLeg *call);

  bool read_config();

  CCChainProcessing onRtpTimeout(SBCCallLeg *call,const AmRtpTimeoutEvent &rtp_event);
  void onServerShutdown(SBCCallLeg *call);
  CCChainProcessing onControlEvent(SBCCallLeg *call,SBCControlEvent *event);
  CCChainProcessing onSystemEvent(SBCCallLeg *call,AmSystemEvent* event);
  CCChainProcessing onTimerEvent(SBCCallLeg *call,int timer_id);
  CCChainProcessing onTearDown(SBCCallLeg *call);

  void terminateLegOnReplyException(SBCCallLeg *call,const AmSipReply& reply, const InternalException &e);

  void setSystemDumpLevel(int dump_level);

 public:
  Yeti();
  ~Yeti();
  static Yeti* instance();
  void invoke(const string& method, const AmArg& args, AmArg& ret);
  int onLoad();
  void init_rpc_cmds();
  int init_radius_module(AmConfigReader& cfg);
  int init_radius_auth_connections(AmDynInvoke* radius_interface);
  int init_radius_acc_connections(AmDynInvoke* radius_interface);
  void process_rpc_cmds(const AmArg cmds_tree, const string& method, const AmArg& args, AmArg& ret);

  struct global_config {
	int node_id;
	int pop_id;
	bool use_radius;
	bool early_100_trying;
	string routing_schema;
	string msg_logger_dir;
	string audio_recorder_dir;
	bool audio_recorder_compress;
	string log_dir;
  } config;

  time_t start_time;

          //!rpc handlers
  typedef void rpc_handler(const AmArg& args, AmArg& ret);

  rpc_handler DropCall;
  rpc_handler ClearStats;
  rpc_handler ClearCache;
  rpc_handler ShowCache;
  rpc_handler GetStats;
  rpc_handler GetConfig;
  rpc_handler GetCall;
  rpc_handler GetCalls;
  rpc_handler GetCallsFields;
  rpc_handler GetCallsCount;
  rpc_handler GetRegistration;
  rpc_handler RenewRegistration;
  rpc_handler GetRegistrations;
  rpc_handler GetRegistrationsCount;
  rpc_handler showVersion;
  rpc_handler closeCdrFiles;
  //rpc_handler reload;
  rpc_handler reloadResources;
  rpc_handler reloadTranslations;
  rpc_handler reloadRegistrations;
  rpc_handler reloadCodecsGroups;
  rpc_handler showMediaStreams;
  rpc_handler showPayloads;
  rpc_handler showInterfaces;
  rpc_handler showRouterCdrWriterOpenedFiles;
  rpc_handler showCallsFields;
  rpc_handler requestSystemLogDump;

  rpc_handler showSystemLogLevel;
  rpc_handler setSystemLogSyslogLevel;
  rpc_handler setSystemLogDiLogLevel;
  rpc_handler setSystemDumpLevelNone;
  rpc_handler setSystemDumpLevelSignalling;
  rpc_handler setSystemDumpLevelRtp;
  rpc_handler setSystemDumpLevelFull;

  rpc_handler showSessions;
  rpc_handler setSessionsLimit;

  rpc_handler requestSystemShutdown;
  rpc_handler requestSystemShutdownImmediate;
  rpc_handler requestSystemShutdownGraceful;
  rpc_handler requestSystemShutdownCancel;

  rpc_handler showSystemStatus;
  rpc_handler showSystemAlarms;
  rpc_handler showSystemDumpLevel;

  rpc_handler getResourceState;
  rpc_handler showResources;
  rpc_handler showResourceTypes;
  rpc_handler showResourceByHandler;
  rpc_handler showResourceByLocalTag;
  rpc_handler showResourcesById;
  rpc_handler requestResourcesInvalidate;

  rpc_handler requestResolverClear;
  rpc_handler requestResolverGet;

  rpc_handler requestReloadSensors;
  rpc_handler showSensorsState;

  rpc_handler showSessionsInfo;
  rpc_handler showSessionsCount;

  rpc_handler showRadiusAuthProfiles;
  rpc_handler showRadiusAuthStat;
  rpc_handler requestRadiusAuthProfilesReload;

  rpc_handler showRadiusAccProfiles;
  rpc_handler showRadiusAccStat;
  rpc_handler requestRadiusAccProfilesReload;

  rpc_handler showRecorderStats;

  rpc_handler showUploadDestinations;
  rpc_handler showUploadStats;
  rpc_handler requestUpload;

  bool check_event_id(int event_id, AmArg &ret);
  bool assert_event_id(const AmArg &args,AmArg &ret);

  void onRoutingReady(SBCCallLeg *call, AmSipRequest &aleg_modified_invite, AmSipRequest &modified_invite);

        //!SBCLogicInterface handlers
  CallCtx *getCallCtx(const AmSipRequest& req,
                          ParamReplacerCtx& ctx);

        //!ExtendedCCInterface handlers
  bool init(SBCCallLeg *call, const map<string, string> &values);

  void onSendRequest(SBCCallLeg *call,AmSipRequest& req, int &flags);
  void onStateChange(SBCCallLeg *call, const CallLeg::StatusChangeCause &cause);
  void onDestroyLeg(SBCCallLeg *call);
  CCChainProcessing onBLegRefused(SBCCallLeg *call,AmSipReply& reply);

  CCChainProcessing onInitialInvite(SBCCallLeg *call, InitialInviteHandlerParams &params);
  void onInviteException(SBCCallLeg *call,int code,string reason,bool no_reply);
  CCChainProcessing onInDialogRequest(SBCCallLeg *call, const AmSipRequest &req);
  CCChainProcessing onInDialogReply(SBCCallLeg *call, const AmSipReply &reply);
  CCChainProcessing onEvent(SBCCallLeg *call, AmEvent *e);
  CCChainProcessing onDtmf(SBCCallLeg *call, AmDtmfEvent* e);
  CCChainProcessing putOnHold(SBCCallLeg *call);
  CCChainProcessing resumeHeld(SBCCallLeg *call, bool send_reinvite);
  CCChainProcessing createHoldRequest(SBCCallLeg *call, AmSdp &sdp);
  CCChainProcessing handleHoldReply(SBCCallLeg *call, bool succeeded);

  CCChainProcessing onRemoteDisappeared(SBCCallLeg *call, const AmSipReply &reply);
  CCChainProcessing onBye(SBCCallLeg *call, const AmSipRequest &req);
  CCChainProcessing onOtherBye(SBCCallLeg *call, const AmSipRequest &req);
  void onCallConnected(SBCCallLeg *call, const AmSipReply& reply);
  void onCallEnded(SBCCallLeg *call);

  void onRTPStreamDestroy(SBCCallLeg *call,AmRtpStream *stream);
  void onSdpCompleted(SBCCallLeg *call, AmSdp& offer, AmSdp& answer);
  bool getSdpOffer(SBCCallLeg *call, AmSdp& offer);

  int relayEvent(SBCCallLeg *call, AmEvent *e);

        //!OoD handlers
  bool init(SBCCallProfile &profile, SimpleRelayDialog *relay, void *&user_data);
  void initUAC(const AmSipRequest &req, void *user_data);
  void initUAS(const AmSipRequest &req, void *user_data);
  void finalize(void *user_data);
  void onSipRequest(const AmSipRequest& req, void *user_data);
  void onSipReply(const AmSipRequest& req,
        const AmSipReply& reply,
        AmBasicSipDialog::Status old_dlg_status,
                void *user_data);
  void onB2BRequest(const AmSipRequest& req, void *user_data);
  void onB2BReply(const AmSipReply& reply, void *user_data);
};

