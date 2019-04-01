#include "yeti.h"
#include "sdp_filter.h"

#include <string.h>
#include <ctime>
#include <cstdio>

#include "log.h"
#include "AmPlugIn.h"
#include "AmArg.h"
#include "jsonArg.h"
#include "AmSession.h"
#include "AmUtils.h"
#include "AmAudioFile.h"
#include "AmMediaProcessor.h"
#include "SDPFilter.h"
#include "CallLeg.h"
#include "RegisterDialog.h"
#include "Registration.h"
#include "cdr/TrustedHeaders.h"
#include "CodecsGroup.h"
#include "Sensors.h"
#include "AmEventDispatcher.h"
#include "ampi/SctpBusAPI.h"
#include "sip/resolver.h"

#include "YetiEvent.pb.h"

#define YETI_CFG_PART "signalling"
#define YETI_CFG_DEFAULT_TIMEOUT 5000

#define YETI_DEFAULT_AUDIO_RECORDER_DIR "/var/spool/sems/record"
#define YETI_DEFAULT_LOG_DIR "/var/spool/sems/logdump"

#define YETI_QUEUE_NAME MOD_NAME
#define YETI_SCTP_CONNECTION_ID 0
#define YETI_SCTP_DST_SESSION_NAME "mgmt"
#define YETI_SCTP_RECONNECT_INTERVAL 120
#define YETI_SCTP_DEFAULT_HOST "127.0.0.1"
#define YETI_SCTP_DEFAULT_PORT 4444

static char opt_name_host[] = "address";
static char opt_name_port[] = "port";
static char opt_name_timeout[] = "timeout";
static char section_name_mgmt[] = "management";

static char opt_name_core_options_handling[] = "core_options_handling";
static char opt_name_registrations_enabled[] = "registrations_enabled";

static cfg_opt_t mgmt_opts[] = {
    CFG_STR(opt_name_host,YETI_SCTP_DEFAULT_HOST,CFGF_NONE),
    CFG_INT(opt_name_port,YETI_SCTP_DEFAULT_PORT,CFGF_NONE),
    CFG_INT(opt_name_timeout,YETI_CFG_DEFAULT_TIMEOUT,CFGF_NONE),
    CFG_END()
};

static cfg_opt_t yeti_opts[] = {
    CFG_SEC(section_name_mgmt,mgmt_opts, CFGF_NONE),
    CFG_BOOL(opt_name_core_options_handling, cfg_true, CFGF_NONE),
    CFG_BOOL(opt_name_registrations_enabled, cfg_true, CFGF_NONE),
    CFG_END()
};

#define LOG_BUF_SIZE 2048
void cfg_reader_error(cfg_t *cfg, const char *fmt, va_list ap)
{
    int l = 0;
    char buf[LOG_BUF_SIZE];
    if(cfg->title) {
    //if(cfg->opts->flags & CFGF_TITLE) {
        l = snprintf(buf,LOG_BUF_SIZE,"line:%d section '%s'(%s): ",
            cfg->line,
            cfg->name,
            cfg->title);
    } else {
        l = snprintf(buf,LOG_BUF_SIZE,"line:%d section '%s': ",
            cfg->line,
            cfg->name);
    }
    l+= vsnprintf(buf+l,static_cast<size_t>(LOG_BUF_SIZE-l),fmt,ap);
    ERROR("%.*s",l,buf);
}

Yeti* Yeti::_instance = nullptr;

Yeti *Yeti::create_instance(YetiBaseParams params)
{
    if(!_instance)
        _instance = new Yeti(params);
    return _instance;
}

Yeti& Yeti::instance() {
    return *_instance;
}

Yeti::Yeti(YetiBaseParams &params)
  : YetiBase(params),
    YetiRadius(*this),
    YetiRpc(*this),
    AmEventQueue(this),
    intial_config_received(false),
    cfg_error(false)
{}


Yeti::~Yeti()
{}

static int check_dir_write_permissions(const string &dir)
{
    ofstream st;
    string testfile = dir + "/test";
    st.open(testfile.c_str(),std::ofstream::out | std::ofstream::trunc);
    if(!st.is_open()){
        ERROR("can't write test file in '%s' directory",dir.c_str());
        return 1;
    }
    st.close();
    std::remove(testfile.c_str());
    return 0;
}

bool Yeti::load_config() {

    config.node_id = AmConfig.node_id;

    SctpBusAddConnection *new_connection = new SctpBusAddConnection();
    new_connection->reconnect_interval = YETI_SCTP_RECONNECT_INTERVAL;
    new_connection->remote_address = cfg_remote_address;
    new_connection->connection_id = YETI_SCTP_CONNECTION_ID;
    new_connection->event_sink = YETI_QUEUE_NAME;

    if(!AmEventDispatcher::instance()->post(SCTP_BUS_EVENT_QUEUE,new_connection)) {
        ERROR("failed to add client SCTP connection via sctp_bus queue. ensure sctp_bus module is loaded");
        return false;
    }

    if(!intial_config_received.wait_for_to(cfg_remote_timeout)) {
        ERROR("timeout waiting yeti config via SCTP");
        return false;
    }

    if(cfg_error) //check for error in queue worker
        return false;

    if(!cfg.hasParameter("pop_id")){
        ERROR("Missed parameter 'pop_id'");
        return false;
    }
    config.pop_id = static_cast<int>(cfg.getParameterInt("pop_id"));

    if(!cfg.hasParameter("routing_schema")) {
        ERROR("Missed parameter 'routing_schema'");
        return false;
    }
    config.routing_schema = cfg.getParameter("routing_schema");
    config.use_radius = cfg.getParameterInt("use_radius",0)==1;
    config.early_100_trying = cfg.getParameterInt("early_100_trying",1)==1;

    if(!cfg.hasParameter("msg_logger_dir")){
        ERROR("Missed parameter 'msg_logger_dir'");
        return false;
    }
    config.msg_logger_dir = cfg.getParameter("msg_logger_dir");
    if(check_dir_write_permissions(config.msg_logger_dir))
        return false;

    config.audio_recorder_dir = cfg.getParameter("audio_recorder_dir",YETI_DEFAULT_AUDIO_RECORDER_DIR);
    if(check_dir_write_permissions(config.audio_recorder_dir))
        return false;
    config.audio_recorder_compress = cfg.getParameterInt("audio_recorder_compress",1)==1;

    config.log_dir = cfg.getParameter("log_dir",YETI_DEFAULT_LOG_DIR);
    if(check_dir_write_permissions(config.log_dir))
        return false;

    return true;
}

int Yeti::configure(const std::string& config)
{
    dns_handle dh;
    cfg_t *cfg = nullptr;

    cfg = cfg_init(yeti_opts, CFGF_NONE);
    if(!cfg) {
        ERROR("failed to init cfg opts");
        return -1;
    }

    cfg_set_error_function(cfg,cfg_reader_error);

    switch(cfg_parse_buf(cfg, config.c_str())) {
    case CFG_SUCCESS:
        break;
    case CFG_PARSE_ERROR:
        ERROR("failed to parse Yeti configuration");
        return -1;
    default:
        ERROR("unexpected error on Yeti configuring");
        return -1;
    }

    cfg_t *mgmt_cfg = cfg_getsec(cfg,section_name_mgmt);
    if(!mgmt_cfg) {
        ERROR("yeti: missed 'mgmt' section");
        return -1;
    }

    char *address = cfg_getstr(mgmt_cfg, opt_name_host);
    if(-1==resolver::instance()->resolve_name(address,&dh,&cfg_remote_address,IPv4_only)) {
        ERROR("configuration error. 'mgmt.host' contains invalid address or unresolvable FQDN: %s",
            address);
        return false;
    }
    am_set_port(&cfg_remote_address, static_cast<short>(cfg_getint(mgmt_cfg, opt_name_port)));

    cfg_remote_timeout = static_cast<unsigned long>(cfg_getint(mgmt_cfg, opt_name_timeout));

    registrations_enabled = cfg_getbool(cfg, opt_name_registrations_enabled);
    core_options_handling = cfg_getbool(cfg, opt_name_core_options_handling);

    return 0;
}

int Yeti::onLoad() {

    start_time = time(nullptr);

    start();

    if(!load_config())
        return -1;

    calls_show_limit = static_cast<int>(cfg.getParameterInt("calls_show_limit",100));

    if(TrustedHeaders::instance()->configure(cfg)){
        ERROR("TrustedHeaders configure failed");
        return -1;
    }

    if (cdr_list.configure(cfg)){
        ERROR("CdrList configure failed");
        return -1;
    }

    if (router.configure(cfg)){
        ERROR("SqlRouter configure failed");
        return -1;
    }

	if(configure_filter(&router)){
		ERROR("ActiveCallsFilter configure failed");
		return -1;
	}

    if(init_radius_module(cfg)){
        ERROR("radius module configure failed");
        return -1;
    }

    if(rctl.configure(cfg)){
        ERROR("ResourceControl configure failed");
        return -1;
    }
    rctl.start();

    if(CodecsGroups::instance()->configure(cfg)){
        ERROR("CodecsGroups configure failed");
        return -1;
    }

    if (CodesTranslator::instance()->configure(cfg)){
        ERROR("CodesTranslator configure failed");
        return -1;
    }

    if(Sensors::instance()->configure(cfg)){
    ERROR("Sensors configure failed");
        return -1;
    }

    if(router.run()){
        ERROR("SqlRouter start failed");
        return -1;
    }

    if(Registration::instance()->configure(cfg)){
        ERROR("Registration agent configure failed");
        return -1;
    }

    if(cdr_list.getSnapshotsEnabled())
        cdr_list.start();

    init_rpc();

    return 0;

}

void Yeti::run()
{
    setThreadName("yeti-worker");
    DBG("start yeti-worker");

    AmEventDispatcher::instance()->addEventQueue(YETI_QUEUE_NAME, this);
    stopped = false;
    while(!stopped) {
        waitForEvent();
        processEvents();
    }
    AmEventDispatcher::instance()->delEventQueue(YETI_QUEUE_NAME);

    INFO("yeti-worker finished");
}

void Yeti::on_stop()
{
    DBG("Yeti::on_stop");

    cdr_list.stop();
    rctl.stop();
    router.stop();

    stopped = true;
    ev_pending.set(true);

    join();
}

#define ON_EVENT_TYPE(type) if(type *e = dynamic_cast<type *>(ev))

void Yeti::process(AmEvent *ev)
{
    ON_EVENT_TYPE(SctpBusConnectionStatus) {
        if(e->status == SctpBusConnectionStatus::Connected) {
            //send cfg request
            YetiEvent e;
            CfgRequest &c = *e.mutable_cfg_request();
            c.set_node_id(AmConfig.node_id);
            c.set_cfg_part(YETI_CFG_PART);
            if(!AmEventDispatcher::instance()->post(
                SCTP_BUS_EVENT_QUEUE,
                new SctpBusRawRequest(
                    YETI_QUEUE_NAME,
                    YETI_SCTP_CONNECTION_ID,
                    YETI_SCTP_DST_SESSION_NAME,
                    e.SerializeAsString()
                )))
            {
                ERROR("failed to post config request to the sctp bus queue");
            }
        }
        return;
    }

    ON_EVENT_TYPE(SctpBusRawReply) {
        if(intial_config_received.get())
            return; //ignore subsequent config replies

        YetiEvent y;
        if(!y.ParseFromString(e->data)) {
            ERROR("failed to parse incoming sctp reply");
        }

        if(y.has_cfg_response()) {
            const CfgResponse &r = y.cfg_response();
            switch(r.Response_case()){
            case CfgResponse::kValues: {
                for(const auto &p : r.values().values()) {
                    switch(p.Value_case()) {
                    case CfgResponse_ValuesPair::kI:
                        cfg.setParameter(p.name(),int2str(p.i()));
                        break;
                    case CfgResponse_ValuesPair::kS:
                        cfg.setParameter(p.name(),p.s());
                        break;
                    default:
                        cfg.setParameter(p.name(),string());
                    }
                }
            } break;
            case CfgResponse::kError: {
                ERROR("cfg error from server: %d %s",
                      r.error().code(),
                      r.error().reason().c_str());
                cfg_error = true;
            } break;
            default:
                ERROR("unexpected cfg response");
                cfg_error = true;
            }

            //continue initialization
            intial_config_received.set(true);
        }
        return;
    }

    ON_EVENT_TYPE(AmSystemEvent) {
        if(e->sys_event==AmSystemEvent::ServerShutdown) {
            DBG("got shutdown event");
            stop();
        }
        return;
    }
    DBG("got unknown event");
}
