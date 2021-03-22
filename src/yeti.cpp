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

#include "RedisConnection.h"

#define EPOLL_MAX_EVENTS 2048

#define DEFAULT_REDIS_HOST "127.0.0.1"
#define DEFAULT_REDIS_PORT 6379
#define DEFAULT_REGISTRAR_KEEPALIVE_INTERVAL 60

#define YETI_SIGNATURE "yeti-switch"
#define YETI_AGENT_SIGNATURE YETI_SIGNATURE " " YETI_VERSION

#define YETI_DEFAULT_AUDIO_RECORDER_DIR "/var/spool/sems/record"
#define YETI_DEFAULT_LOG_DIR "/var/spool/sems/logdump"

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
    AmEventFdQueue(this)
{}


Yeti::~Yeti()
{
    stop(true);
}

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

bool Yeti::apply_config() {
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
    return config.configure(config_buf, cfg);
}

static void apply_yeti_signatures()
{
    if(AmConfig.sdp_origin==DEFAULT_SDP_ORIGIN)
        AmConfig.sdp_origin = YETI_SIGNATURE;

    if(AmConfig.sdp_session_name==DEFAULT_SDP_SESSION_NAME)
        AmConfig.sdp_session_name = YETI_SIGNATURE;

    AmLcConfig::instance().applySignature(YETI_AGENT_SIGNATURE);
}

int Yeti::onLoad()
{
    start_time = time(nullptr);

    cfg.dump();

    init_rpc();
    apply_yeti_signatures();

    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    epoll_link(epoll_fd);

    if(!apply_config())
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

    if(options_prober_manager.configure(cfg, config.routing_schema)) {
        ERROR("SipProberManager configure failed");
        return -1;
    }

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

    http_sequencer.setHttpDestinationName(config.http_events_destination);

    //start threads
    router.start();
    rctl.start();
    if(cdr_list.getSnapshotsEnabled())
        cdr_list.start();
    start();

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

    config.registrar_expires_min = cfg.getParameterInt("registrar_expires_min");
    DBG("registrar_expires_min: %d", config.registrar_expires_min);

    config.registrar_expires_max = cfg.getParameterInt("registrar_expires_max");
    DBG("registrar_expires_max: %d", config.registrar_expires_max);

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

    stopped = false;
    do {
        //DBG("epoll_wait...");
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        //DBG("epoll_wait = %d",ret);

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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    ::write(queue_fd(), &u, sizeof(uint64_t)); //trigger events processing
#pragma GCC diagnostic pop
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
    ON_EVENT_TYPE(HttpPostResponseEvent) {
        http_sequencer.processHttpReply(*e);
    } else
    ON_EVENT_TYPE(AmSystemEvent) {
        if(e->sys_event==AmSystemEvent::ServerShutdown) {
            DBG("got shutdown event");
            stop();
        }
        return;
    } else
        DBG("got unknown event %s", typeid(*ev).name());
}

void Yeti::processRedisRegisterReply(RedisReplyEvent &e)
{
    static string contact_hdr = SIP_HDR_COLSP(SIP_HDR_CONTACT);
    static string expires_param_prefix = ";expires=";

    const AmSipRequest &req = *dynamic_cast<AmSipRequest *>(e.user_data.get());
    //DBG("e.data: %s",AmArg::print(e.data).c_str());

    if(RedisReplyEvent::SuccessReply!=e.result) {
        ERROR("error reply from redis %s. for request from %s:%hu",
              AmArg::print(e.data).c_str(),
              req.remote_ip.data(), req.remote_port);
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
        ERROR("error/unexpected reply from redis: %s for request from %s:%hu",
              AmArg::print(e.data).c_str(),
              req.remote_ip.data(), req.remote_port);
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
