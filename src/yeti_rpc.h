#pragma once

#include "AmArg.h"
#include "AmApi.h"
#include "CoreRpc.h"
#include "yeti_base.h"
#include "yeti_radius.h"
#include "RpcTreeHandler.h"

class YetiRpc
  : public RpcTreeHandler<YetiRpc>,
    virtual YetiBase,
    virtual YetiRadius
{
  public:
    YetiRpc(YetiBase &base)
      : YetiBase(base),
        YetiRadius(base),
        RpcTreeHandler<YetiRpc>(true)
    { }

    void invoke(const string& method, const AmArg& args, AmArg& ret);

    typedef void rpc_handler(const AmArg& args, AmArg& ret);

  protected:
    int calls_show_limit;
    void init_rpc_tree();
  private:
    AmArg rpc_cmds;

    void process_rpc_cmds(const AmArg cmds_tree, const string& method, const AmArg& args, AmArg& ret);

    bool check_event_id(int event_id, AmArg &ret);
    bool assert_event_id(const AmArg &args,AmArg &ret);

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
    rpc_handler GetRegistrations;
    rpc_handler GetRegistrationsCount;
    rpc_handler showVersion;
    rpc_handler closeCdrFiles;

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
};
