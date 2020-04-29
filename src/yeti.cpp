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
#include "Registration.h"
#include "cdr/TrustedHeaders.h"
#include "CodecsGroup.h"
#include "Sensors.h"
#include "AmEventDispatcher.h"
#include "ampi/SctpBusAPI.h"
#include "sip/resolver.h"

#include "YetiEvent.pb.h"
#include "RedisConnection.h"

#define EPOLL_MAX_EVENTS 2048

#define DEFAULT_REDIS_HOST "127.0.0.1"
#define DEFAULT_REDIS_PORT 6379
#define DEFAULT_REGISTRAR_KEEPALIVE_INTERVAL 60

#define YETI_CFG_PART "signalling"
#define YETI_CFG_DEFAULT_TIMEOUT 5000

#define YETI_DEFAULT_AUDIO_RECORDER_DIR "/var/spool/sems/record"
#define YETI_DEFAULT_LOG_DIR "/var/spool/sems/logdump"

#define YETI_SCTP_CONNECTION_ID_START 0
#define YETI_SCTP_DST_SESSION_NAME "mgmt"
#define YETI_SCTP_RECONNECT_INTERVAL 120
#define YETI_SCTP_DEFAULT_HOST "127.0.0.1"
#define YETI_SCTP_DEFAULT_PORT 4444

#define YETI_SIGNATURE "yeti-switch"
#define YETI_AGENT_SIGNATURE YETI_SIGNATURE " " YETI_VERSION

static char opt_name_host[] = "address";
static char opt_name_port[] = "port";
static char opt_name_timeout[] = "timeout";
static char section_name_mgmt[] = "management";
static char section_name_mgmt_node[] = "node";

static char opt_name_core_options_handling[] = "core_options_handling";
static char opt_name_pcap_memory_logger[] = "pcap_memory_logger";

static cfg_opt_t mgmt_node_opts[] = {
    CFG_STR(opt_name_host,YETI_SCTP_DEFAULT_HOST,CFGF_NONE),
    CFG_INT(opt_name_port,YETI_SCTP_DEFAULT_PORT,CFGF_NONE),
    CFG_END()
};

static cfg_opt_t mgmt_opts[] = {
    CFG_STR(opt_name_host,YETI_SCTP_DEFAULT_HOST,CFGF_NONE),
    CFG_INT(opt_name_port,YETI_SCTP_DEFAULT_PORT,CFGF_NONE),
    CFG_INT(opt_name_timeout,YETI_CFG_DEFAULT_TIMEOUT,CFGF_NONE),
    CFG_SEC(section_name_mgmt_node, mgmt_node_opts, CFGF_MULTI),
    CFG_END()
};

static cfg_opt_t yeti_opts[] = {
    CFG_SEC(section_name_mgmt,mgmt_opts, CFGF_NONE),
    CFG_BOOL(opt_name_core_options_handling, cfg_true, CFGF_NONE),
    CFG_BOOL(opt_name_pcap_memory_logger, cfg_false, CFGF_NONE),
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
    AmEventFdQueue(this),
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

bool Yeti::add_mgmt_node(cfg_t *node_cfg)
{
    dns_handle dh;

    management_nodes.emplace_back();
    auto &node_adddress = management_nodes.back();

    char *address = cfg_getstr(node_cfg, opt_name_host);
    if(-1==resolver::instance()->resolve_name(address,&dh,&node_adddress,IPv4_only)) {
        ERROR("configuration error. "
              "management node host contains invalid address or unresolvable FQDN: %s",
              address);
        return true;
    }
    am_set_port(&node_adddress, static_cast<short>(cfg_getint(node_cfg, opt_name_port)));

    DBG("add management node %s (%s:%hu)",
        address,
        am_inet_ntop(&node_adddress).data(),
        am_get_port(&node_adddress));

    return false;
}

bool Yeti::request_config()
{
    int i = 0;
    for(auto const &mgmt_node_address: management_nodes) {
        SctpBusAddConnection *new_connection = new SctpBusAddConnection();
        new_connection->reconnect_interval = YETI_SCTP_RECONNECT_INTERVAL;
        new_connection->remote_address = mgmt_node_address;
        new_connection->connection_id = YETI_SCTP_CONNECTION_ID_START + (i++);
        new_connection->event_sink = YETI_QUEUE_NAME;

        if(!AmEventDispatcher::instance()->post(SCTP_BUS_EVENT_QUEUE,new_connection)) {
            ERROR("failed to add client SCTP connection via sctp_bus queue. ensure sctp_bus module is loaded");
            return false;
        }
    }

    return true;
}

bool Yeti::wait_and_apply_config() {
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

int Yeti::configure(const std::string& config_buf)
{
    dns_handle dh;
    cfg_t *cfg = nullptr;

    cfg = cfg_init(yeti_opts, CFGF_NONE);
    if(!cfg) {
        ERROR("failed to init cfg opts");
        return -1;
    }

    cfg_set_error_function(cfg,cfg_reader_error);

    switch(cfg_parse_buf(cfg, config_buf.c_str())) {
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

    auto mgmt_nodes_count = cfg_size(mgmt_cfg, section_name_mgmt_node);
    if(mgmt_nodes_count) {
        for(decltype(mgmt_nodes_count) i = 0; i < mgmt_nodes_count; i++) {
            auto node_cfg = cfg_getnsec(mgmt_cfg, section_name_mgmt_node, i);
            if(add_mgmt_node(node_cfg))
                return -1;
        }
    } else {
        if(add_mgmt_node(mgmt_cfg))
            return -1;
    }

    cfg_remote_timeout = static_cast<unsigned long>(cfg_getint(mgmt_cfg, opt_name_timeout));

    core_options_handling = cfg_getbool(cfg, opt_name_core_options_handling);
    config.pcap_memory_logger = cfg_getbool(cfg, opt_name_pcap_memory_logger);

    return 0;
}

static void apply_yeti_signatures()
{
    if(AmConfig.sdp_origin==DEFAULT_SDP_ORIGIN)
        AmConfig.sdp_origin = YETI_SIGNATURE;

    if(AmConfig.sdp_session_name==DEFAULT_SDP_SESSION_NAME)
        AmConfig.sdp_session_name = YETI_SIGNATURE;

    if(AmConfig.signature==DEFAULT_SIGNATURE)
        AmConfig.signature = YETI_AGENT_SIGNATURE;
}

int Yeti::onLoad() {

    start_time = time(nullptr);

    apply_yeti_signatures();

    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    epoll_link(epoll_fd);

    start();

    if(!wait_and_apply_config())
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

    if(configure_registrar()) {
        ERROR("Failed to configure registrar");
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

    if(config.registrar_enabled) {
        registrar_redis.start();
        if(config.registrar_keepalive_interval) {
            keepalive_timer.link(epoll_fd);
            keepalive_timer.set(config.registrar_keepalive_interval,true);
        }
    }

    if(cdr_list.getSnapshotsEnabled())
        cdr_list.start();

    init_rpc();

    return 0;

}

int Yeti::configure_registrar()
{
    config.registrar_enabled = cfg.getParameterInt("registrar_enabled");
    DBG("registrar_enabled: %d", config.registrar_enabled);
    if(!config.registrar_enabled)
        return 0;

    config.registrar_redis_host = cfg.getParameter("registrar_redis_host");
    if(config.registrar_redis_host.empty()) config.registrar_redis_host = DEFAULT_REDIS_HOST;

    config.registrar_redis_port = cfg.getParameterInt("registrar_redis_port");
    if(!config.registrar_redis_port) config.registrar_redis_port = DEFAULT_REDIS_PORT;

    config.registrar_keepalive_interval =
        cfg.getParameterInt("registrar_keepalive_interval", DEFAULT_REGISTRAR_KEEPALIVE_INTERVAL);
    if(config.registrar_keepalive_interval) config.registrar_keepalive_interval =
        config.registrar_keepalive_interval * 1000000;

    if(0!=registrar_redis.init(
        config.registrar_redis_host,
        config.registrar_redis_port,
        0!=config.registrar_keepalive_interval))
    {
        return -1;
    }

    return 0;
}

void Yeti::run()
{
    int ret, f;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("yeti-worker");
    DBG("start yeti-worker");

    AmEventDispatcher::instance()->addEventQueue(YETI_QUEUE_NAME, this);

    if(!request_config()) {
        ERROR("failed to send config request");
        return;
    }

    stopped = false;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s\n",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            f = e.data.fd;

            if(f==keepalive_timer){
                registrar_redis.on_keepalive_timer();
                keepalive_timer.read();
            } else if(f == -queue_fd()) {
                clear_pending();
                processEvents();
            }
        }
    } while(!stopped);

    AmEventDispatcher::instance()->delEventQueue(YETI_QUEUE_NAME);

    INFO("yeti-worker finished");
}

void Yeti::on_stop()
{
    uint64_t u = 1;

    DBG("Yeti::on_stop");

    cdr_list.stop();
    rctl.stop();
    router.stop();
    registrar_redis.stop();

    stopped = true;
    ::write(queue_fd(), &u, sizeof(uint64_t)); //trigger events processing

    join();
}

#define ON_EVENT_TYPE(type) if(type *e = dynamic_cast<type *>(ev))

void Yeti::process(AmEvent *ev)
{
    ON_EVENT_TYPE(RedisReplyEvent) {
        /*DBG("got RedisReplyEvent id = %d data:\n%s",
            e->user_type_id,
            AmArg::print(e->data).c_str());*/
        switch(e->user_type_id) {
        case YETI_REDIS_REGISTER_TYPE_ID:
            processRedisRegisterReply(*e);
            break;
        case YETI_REDIS_RPC_AOR_LOOKUP_TYPE_ID:
            processRedisRpcAorLookupReply(*e);
            break;
        }
    } else
    ON_EVENT_TYPE(SctpBusConnectionStatus) {
        DBG("on SctpBusConnectionStatus. id:%u, status: %d",
            e->id, e->status);
        if(e->status == SctpBusConnectionStatus::Connected &&
           !intial_config_received.get())
        {
            //send cfg request
            YetiEvent yeti_event;
            CfgRequest &c = *yeti_event.mutable_cfg_request();
            c.set_node_id(AmConfig.node_id);
            c.set_cfg_part(YETI_CFG_PART);
            if(!AmEventDispatcher::instance()->post(
                SCTP_BUS_EVENT_QUEUE,
                new SctpBusRawRequest(
                    YETI_QUEUE_NAME,
                    e->id,
                    YETI_SCTP_DST_SESSION_NAME,
                    yeti_event.SerializeAsString()
                )))
            {
                ERROR("failed to post config request for connection %u",
                      e->id);
            }
        }
        return;
    } else
    ON_EVENT_TYPE(SctpBusRawReply) {
        DBG("on SctpBusRawReply");

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
    } else
    ON_EVENT_TYPE(AmSystemEvent) {
        if(e->sys_event==AmSystemEvent::ServerShutdown) {
            DBG("got shutdown event");
            stop();
        }
        return;
    } else
        DBG("got unknown event");
}

void Yeti::processRedisRegisterReply(RedisReplyEvent &e)
{
    static string contact_hdr = SIP_HDR_COLSP(SIP_HDR_CONTACT);
    static string expires_param_prefix = ";expires=";

    const AmSipRequest &req = *dynamic_cast<AmSipRequest *>(e.user_data.get());
    //DBG("e.data: %s",AmArg::print(e.data).c_str());

    if(RedisReplyEvent::SuccessReply!=e.result) {
        ERROR("error reply from redis %s",AmArg::print(e.data).c_str());
        AmSipDialog::reply_error(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        return;
    }

    if(isArgUndef(e.data)) {
        DBG("nil reply from redis. no bindings");
        AmSipDialog::reply_error(req, 200, "OK");
        return;
    }

    /* response layout:
     * [
     *   [ contact1 , expires1, contact_key1, path1, interface_id1 ]
     *   [ contact2 , expires2, contact_key2, path2, interface_id2 ]
     *   ...
     * ]
     */

    if(!isArgArray(e.data)) {
        ERROR("error/unexpected reply from redis: %s",AmArg::print(e.data).c_str());
        AmSipDialog::reply_error(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        return;
    }

    string hdrs;
    int n = static_cast<int>(e.data.size());
    for(int i = 0; i < n; i++) {
        AmArg &d = e.data[i];
        if(!isArgArray(d) || d.size()!=5) {
            ERROR("unexpected AoR layout in reply from redis: %s. skip it",AmArg::print(d).c_str());
            continue;
        }
        AmArg &contact_arg = d[0];
        if(!isArgCStr(contact_arg)) {
            ERROR("unexpected contact variable type from redis. skip it");
            continue;
        }
        string contact = contact_arg.asCStr();
        if(contact.empty()) {
            ERROR("empty contact in reply from redis. skip it");
            continue;
        }

        AmArg &expires_arg = d[1];
        if(!isArgLongLong(expires_arg)) {
            ERROR("unexpected expires value in redis reply: %s, skip it",AmArg::print(expires_arg).c_str());
            continue;
        }

        AmUriParser c;
        c.uri = contact;
        if(!c.parse_uri()) {
            ERROR("failed to parse contact uri: %s, skip it",contact.c_str());
            continue;
        }

        hdrs+=contact_hdr + c.print();
        hdrs+=expires_param_prefix+longlong2str(expires_arg.asLongLong());
        hdrs+=CRLF;

        //update KeepAliveContexts
        if(config.registrar_keepalive_interval!=0) {
            registrar_redis.updateKeepAliveContext(
                d[2].asCStr(),  //key
                contact,        //aor
                d[3].asCStr(),  //path
                arg2int(d[4])   //interface_id
            );
        }
    }

    AmSipDialog::reply_error(req, 200, "OK", hdrs);
}

void Yeti::processRedisRpcAorLookupReply(RedisReplyEvent &e)
{
    DBG("processRedisRpcAorLookupReply");
    auto &ctx = *dynamic_cast<RegistrarRedisConnection::RpcAorLookupCtx *>(e.user_data.release());
    ctx.data = e.data;
    ctx.result = e.result;
    DBG("ctx.cond: %p",&ctx.cond);
    ctx.cond.set(true);
}
