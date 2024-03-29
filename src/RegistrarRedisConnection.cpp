#include "RegistrarRedisConnection.h"

#include "yeti.h"
#include "AmSipMsg.h"
#include "cfg/yeti_opts.h"

#define REDIS_REPLY_SCRIPT_LOAD 0
#define REDIS_REPLY_SUBSCRIPTION 1
#define REDIS_REPLY_CONTACTS_DATA 2

#define DEFAULT_REDIS_HOST "127.0.0.1"
#define DEFAULT_REDIS_PORT 6379

static const string REGISTAR_QUEUE_NAME("registrar");

RegistrarRedisConnection::ContactsSubscriptionConnection::ContactsSubscriptionConnection(
    RegistrarRedisConnection* registrar)
  : RedisConnectionPool("reg_sub", "reg_async_redis_sub"),
    registrar(registrar),
    load_contacts_data("load_contacts_data", get_queue_name())
{}

void RegistrarRedisConnection::ContactsSubscriptionConnection::on_connect(RedisConnection* c)
{
    //load contacts data loading script
    if(registrar->use_functions)
        postRedisRequestFmt(c,
            get_queue_name(), get_queue_name(), false, nullptr,
            REDIS_REPLY_CONTACTS_DATA, "FCALL load_contacts 0");
    else
        load_contacts_data.load(c, "/etc/yeti/scripts/load_contacts.lua", REDIS_REPLY_SCRIPT_LOAD);
}

void RegistrarRedisConnection::ContactsSubscriptionConnection::process_reply_event(RedisReplyEvent &event)
{
    /*DBG("ContactsSubscriptionConnection got event %d. data: %s",
        event.user_type_id, AmArg::print(event.data).c_str());*/

    if(event.result!=RedisReplyEvent::SuccessReply) {
        DBG("non-succ reply: %d, data: %s",event.result, AmArg::print(event.data).data());
        if(REDIS_REPLY_SCRIPT_LOAD == event.user_type_id) event.user_data.release();
        return;
    }

    switch(event.user_type_id) {
    case REDIS_REPLY_SUBSCRIPTION:
        if(isArgArray(event.data) &&
           event.data.size() == 3)
        {
            process_expired_key(event.data[2]);
        }
        break;
    case REDIS_REPLY_SCRIPT_LOAD: {
        auto script = dynamic_cast<RedisScript *>(event.user_data.release());
        script->hash = event.data.asCStr();
        DBG("script '%s' loaded with hash '%s'",
            script->name.c_str(),script->hash.c_str());
        //execute load_contacts script
        if(!postRedisRequestFmt(conn,
            get_queue_name(), get_queue_name(), false,
            nullptr, REDIS_REPLY_CONTACTS_DATA,
            "EVALSHA %s 0",
            load_contacts_data.hash.c_str()))
        {
            ERROR("failed to execute load_contacts lua script");
        }
    } break;
    case REDIS_REPLY_CONTACTS_DATA:
        process_loaded_contacts(event.data);
        break;
    default:
        ERROR("unexpected reply event with type: %d",event.user_type_id);
        break;
    }
}

int RegistrarRedisConnection::ContactsSubscriptionConnection::init(const std::string& host, int port)
{
    int ret = RedisConnectionPool::init();
    conn = addConnection(host, port);
    if(ret || !conn) return -1;
    return 0;
}

void RegistrarRedisConnection::ContactsSubscriptionConnection::setAuthData(const std::string& password, const std::string& username)
{
    conn->setAuthData(password, username);
}

void RegistrarRedisConnection::keepalive_ctx_data::dump(
    const std::string &key,
    const std::chrono::system_clock::time_point &now) const
{
    DBG("keepalive_context. key: '%s', "
        "aor: '%s', path: '%s', interface_id: %d, "
        "next_send-now: %d",
        key.c_str(),
        aor.data(), path.data(), interface_id,
        std::chrono::duration_cast<std::chrono::seconds>(
            next_send - now).count());
}

void RegistrarRedisConnection::keepalive_ctx_data::dump(
    const std::string &key, AmArg &ret,
    const std::chrono::system_clock::time_point &now) const
{
    ret["key"] = key;
    ret["aor"] = aor;
    ret["path"] = path;
    ret["interface_id"] = interface_id;
    ret["next_send_in"] =
        std::chrono::duration_cast<std::chrono::seconds>(
            next_send - now).count();
}

void RegistrarRedisConnection::KeepAliveContexts::dump()
{
    //AmLock l(mutex);
    auto now{std::chrono::system_clock::now()};
    DBG("%zd keepalive contexts", size());
    for(const auto &i : *this) {
        i.second.dump(i.first, now);
    }
}

void RegistrarRedisConnection::KeepAliveContexts::dump(AmArg &ret)
{
    ret.assertArray();
    auto now{std::chrono::system_clock::now()};
    AmLock l(mutex);
    for(const auto &i : *this) {
        ret.push(AmArg());
        i.second.dump(i.first, ret.back(), now);
    }
}

void RegistrarRedisConnection::ContactsSubscriptionConnection::process_loaded_contacts(const AmArg &data)
{
    registrar->clearKeepAliveContexts();

    if(!isArgArray(data))
        return;

    std::chrono::seconds keepalive_interval_offset{0};
    auto keepalive_interval = registrar->getKeepAliveInterval();

    DBG("process_loaded_contacts");
    int n = static_cast<int>(data.size());
    for(int i = 0; i < n; i++) {
        AmArg &d = data[i];
        if(!isArgArray(d) || d.size() != 4) //validate
            continue;
        if(arg2int(d[0]) != AmConfig.node_id) //skip other nodes registrations
            continue;
        DBG("process contact: %s",AmArg::print(d).c_str());

        string key(d[3].asCStr());

        auto pos = key.find_first_of(':');
        if(pos == string::npos) {
            ERROR("wrong key format: %s",key.c_str());
            continue;
        }
        pos = key.find_first_of(':',pos+1);
        if(pos == string::npos) {
            ERROR("wrong key format: %s",key.c_str());
            continue;
        }
        pos++;

        registrar->createOrUpdateKeepAliveContext(
            key,
            key.substr(pos), //aor
            d[1].asCStr(),   //path
            arg2int(d[2]),   //interface_id
            keepalive_interval_offset - keepalive_interval);

        keepalive_interval_offset++;
        keepalive_interval_offset %= keepalive_interval;
    }

    //keepalive_contexts.dump();

    //subscribe to del/expire events
    if(!postRedisRequestFmt(conn,
        get_queue_name(), get_queue_name(), true,
        nullptr, REDIS_REPLY_SUBSCRIPTION,
        //"PSUBSCRIBE __keyspace@0__:c:*",
        "SUBSCRIBE __keyevent@0__:expired __keyevent@0__:del"))
    {
        ERROR("failed to subscribe");
    }
}

void RegistrarRedisConnection::ContactsSubscriptionConnection::process_expired_key(const AmArg &key_arg)
{
    if(!isArgCStr(key_arg)) //skip 'subscription' replies
        return;

    DBG("process expired/removed key: '%s'", key_arg.asCStr());

    registrar->removeKeepAliveContext(key_arg.asCStr());
}

RegistrarRedisConnection::RegistrarRedisConnection()
  : RedisConnectionPool("reg", REGISTAR_QUEUE_NAME),
     max_interval_drift(1),
     max_registrations_per_slot(1),
     contacts_subscription(this),
     yeti_register("yeti_register", REGISTAR_QUEUE_NAME),
     yeti_aor_lookup("yeti_aor_lookup", REGISTAR_QUEUE_NAME),
     yeti_rpc_aor_lookup("yeti_rpc_aor_lookup", REGISTAR_QUEUE_NAME),
     conn(0)
{ }

void RegistrarRedisConnection::start()
{
    AmThread::start();
    if(subscription_enabled)
        contacts_subscription.start();
}

void RegistrarRedisConnection::stop()
{
    AmThread::stop();
    if(subscription_enabled)
        contacts_subscription.stop();
}

int RegistrarRedisConnection::configure(cfg_t* cfg)
{
    auto reg_redis = cfg_getsec(cfg, section_name_redis);
    if(!reg_redis)
        return -1;

    use_functions = cfg_getbool(reg_redis, "use_functions");
    auto reg_redis_write = cfg_getsec(reg_redis, section_name_redis_write);
    auto reg_redis_read = cfg_getsec(reg_redis, section_name_redis_read);
    if(!reg_redis_read || !reg_redis_write)
        return -1;

    int ret = RedisConnectionPool::init();
    subscription_enabled = (cfg_getint(cfg, opt_registrar_keepalive_interval) != 0);
    if(ret || !subscription_enabled) return -1;

    if(initConnection(reg_redis_read, read_conn) ||
       initConnection(reg_redis_write, conn))
        return -1;

    keepalive_interval = std::chrono::seconds{
        Yeti::instance().config.registrar_keepalive_interval};
    max_interval_drift = keepalive_interval/10; //allow 10% interval drift

    return 0;
}

void RegistrarRedisConnection::setAuthData(const std::string& password, const std::string& username)
{
    conn->setAuthData(password, username);
    contacts_subscription.setAuthData(password, username);
}

void RegistrarRedisConnection::on_connect(RedisConnection* c) {
    if(use_functions) return;
    if(c == conn)
        yeti_register.load(c, "/etc/yeti/scripts/register.lua", REDIS_REPLY_SCRIPT_LOAD);
    if(c == read_conn) {
        yeti_aor_lookup.load(c, "/etc/yeti/scripts/aor_lookup.lua", REDIS_REPLY_SCRIPT_LOAD);
        yeti_rpc_aor_lookup.load(c, "/etc/yeti/scripts/rpc_aor_lookup.lua", REDIS_REPLY_SCRIPT_LOAD);
    }
}

int RegistrarRedisConnection::initConnection(cfg_t* cfg, RedisConnection*& c)
{
    string host = DEFAULT_REDIS_HOST;
    if(cfg_size(cfg, "host"))
        host = cfg_getstr(cfg, "host");
    int port = DEFAULT_REDIS_PORT;
    if(cfg_size(cfg, "port"))
        port = cfg_getint(cfg, "port");

    c = addConnection(host, port);
    if(!c) return -1;

    int ret = 0;
    if(read_conn == c) {
        ret = contacts_subscription.init(host, port);
    }
    if(ret) return -1;

    if(cfg_size(cfg, "password")) {
        string username;
        string password = cfg_getstr(cfg, "password");
        if(cfg_size(cfg, "username"))
            username = cfg_getstr(cfg, "username");
        c->setAuthData(password, username);
        if(read_conn == c)
            contacts_subscription.setAuthData(password, username);
    }

    return 0;
}

void RegistrarRedisConnection::process(AmEvent* ev)
{
    AmSipReplyEvent *reply_ev;
    if(-1 == ev->event_id && (reply_ev = dynamic_cast<AmSipReplyEvent *>(ev)))
    {
        //DBG("got redis reply. check in local hash");
        AmLock l(uac_dlgs_mutex);
        auto it = uac_dlgs.find(reply_ev->reply.callid);
        if(it != uac_dlgs.end()) {
            //DBG("found ctx. remove dlg");
            delete it->second;
            uac_dlgs.erase(it);
        }
        return;
    }
    RedisConnectionPool::process(ev);
}
void RegistrarRedisConnection::process_reply_event(RedisReplyEvent &event)
{
    //DBG("got event. data: %s",AmArg::print(event.data).c_str());
    RedisScript *script;
    switch(event.user_type_id) {
    case REDIS_REPLY_SCRIPT_LOAD:
        script = dynamic_cast<RedisScript *>(event.user_data.release());
        if(event.result==RedisReplyEvent::SuccessReply) {
            script->hash = event.data.asCStr();
            DBG("script '%s' loaded with hash '%s'",
                script->name.c_str(),script->hash.c_str());
        }
        break;
    default:
        ERROR("unexpected reply event with type: %d",event.user_type_id);
        break;
    }
}

bool RegistrarRedisConnection::fetch_all(const AmSipRequest &req, Auth::auth_id_type auth_id)
{
    return postRedisRequestFmt(
        conn,
        get_queue_name(),
        YETI_QUEUE_NAME,
        false,
        new AmSipRequest(req), YETI_REDIS_REGISTER_TYPE_ID,
        use_functions ? "FCALL %s 1 %d" : "EVALSHA %s 1 %d",
        use_functions ? "register"      : yeti_register.hash.c_str(),
        auth_id);
}

bool RegistrarRedisConnection::unbind_all(const AmSipRequest &req, Auth::auth_id_type auth_id)
{
    return postRedisRequestFmt(
        conn,
        get_queue_name(),
        YETI_QUEUE_NAME,
        false,
        new AmSipRequest(req), YETI_REDIS_REGISTER_TYPE_ID,
        use_functions ? "FCALL %s 1 %d 0" : "EVALSHA %s 1 %d 0",
        use_functions ? "register"        : yeti_register.hash.c_str(),
        auth_id);
}

bool RegistrarRedisConnection::bind(
    const AmSipRequest &req,
    Auth::auth_id_type auth_id,
    const string &contact, int expires,
    const string &user_agent,
    const string &path)
{
    return postRedisRequestFmt(
        conn,
        get_queue_name(),
        YETI_QUEUE_NAME,
        false,
        new AmSipRequest(req), YETI_REDIS_REGISTER_TYPE_ID,
        use_functions ? "FCALL %s 1 %d %d %s %d %d %s %s" : "EVALSHA %s 1 %d %d %s %d %d %s %s",
        use_functions ? "register"                        : yeti_register.hash.c_str(),
        auth_id, expires,
        contact.c_str(),
        AmConfig.node_id, req.local_if,
        user_agent.c_str(), path.c_str());
}

void RegistrarRedisConnection::resolve_aors(
    std::set<int> aor_ids,
    const string &local_tag)
{
    std::unique_ptr<char> cmd;
    size_t aors_count = aor_ids.size();

    DBG("got %ld AoR ids to resolve", aor_ids.size());

    if(!use_functions && yeti_aor_lookup.hash.empty()) {
        ERROR("empty yeti_aor_lookup.hash. lua scripting error");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    std::ostringstream ss;
    if(use_functions) {
        ss << '*' << aors_count+3 << CRLF "$8" CRLF "FCALL_RO" CRLF "$10" CRLF << "aor_lookup" << CRLF;
    } else {
        ss << '*' << aors_count+3 << CRLF "$7" CRLF "EVALSHA" CRLF "$40" CRLF << yeti_aor_lookup.hash << CRLF;
    }
    //args count
    ss << '$' << len_in_chars(aors_count) << CRLF << aors_count << CRLF;
    //args
    for(const auto &id : aor_ids) {
        ss << '$' << len_in_chars(id) << CRLF << id << CRLF;
    }

    auto cmd_size = ss.str().size();
    cmd.reset(new char [cmd_size]);
    ss.str().copy(cmd.get(), cmd_size);

    //send request to redis
    if(false==postRedisRequest(
        read_conn,
        get_queue_name(),
        local_tag,
        cmd.release(),cmd_size, false))
    {
        ERROR("failed to post auth_id resolve request");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }
}

void RegistrarRedisConnection::rpc_resolve_aors_blocking(
    const AmArg &arg,
    RpcAorLookupCtx &ctx)
{
    std::unique_ptr<char> cmd;
    size_t n, i;
    int id;

    if(!use_functions && yeti_rpc_aor_lookup.hash.empty())
        throw AmSession::Exception(500,"registrar is not enabled");

    arg.assertArray();

    n = arg.size();

    std::ostringstream ss;
    if(use_functions) {
        ss << '*' << n+3 << CRLF "$8" CRLF "FCALL_RO" CRLF "$14" CRLF << "rpc_aor_lookup" << CRLF;
    } else {
        ss << '*' << n+3 << CRLF "$7" CRLF "EVALSHA" CRLF "$40" CRLF << yeti_rpc_aor_lookup.hash << CRLF;
    }
    //args count
    ss << '$' << len_in_chars(n) << CRLF << n << CRLF;
    //args
    for(i = 0; i < n; i++) {
        id = arg2int(arg[i]);
        ss << '$' << len_in_chars(id) << CRLF << id << CRLF;
    }

    auto cmd_size = ss.str().size();
    cmd.reset(new char [cmd_size]);
    ss.str().copy(cmd.get(), cmd_size);

    if(false==postRedisRequest(
        read_conn,
        get_queue_name(),
        YETI_QUEUE_NAME,
        cmd.release(),cmd_size, false,
        false,
        &ctx, YETI_REDIS_RPC_AOR_LOOKUP_TYPE_ID))
    {
        //delete ctx;
        throw AmSession::Exception(500, "failed to post yeti_rpc_aor_lookup request");
    }

    //block because of no async support in RPC implementation yet
    ctx.cond.wait_for();
}

void RegistrarRedisConnection::createOrUpdateKeepAliveContext(
    const string &key,
    const string &aor,
    const string &path,
    int interface_id,
    const std::chrono::seconds &keep_alive_interval_offset)
{
    auto next_time =
        std::chrono::system_clock::now() +
        keepalive_interval + keep_alive_interval_offset;

    AmLock l(keepalive_contexts.mutex);

    auto it = keepalive_contexts.find(key);
    if(it == keepalive_contexts.end()) {
        keepalive_contexts.try_emplace(
            key,
            aor, path, interface_id, next_time);
        return;
    }

    it->second.update(aor, path, interface_id, next_time);
}

void RegistrarRedisConnection::removeKeepAliveContext(const std::string &key)
{
    AmLock l(keepalive_contexts.mutex);
    keepalive_contexts.erase(key);
}

void RegistrarRedisConnection::clearKeepAliveContexts()
{
    AmLock l(keepalive_contexts.mutex);
    keepalive_contexts.clear();
}

void RegistrarRedisConnection::on_keepalive_timer()
{
    auto now{std::chrono::system_clock::now()};
    uint32_t sent = 0;
    std::chrono::seconds drift_interval{0};
    auto double_max_interval_drift = max_interval_drift*2;

    //DBG("on keepalive timer");
    AmLock l(keepalive_contexts.mutex);

    for(auto &ctx_it : keepalive_contexts) {
        auto &ctx = ctx_it.second;

        if(now < ctx.next_send) continue;

        sent++;
        //send OPTIONS query for each ctx
        std::unique_ptr<AmSipDialog> dlg(new AmSipDialog());

        dlg->setRemoteUri(ctx.aor);
        dlg->setLocalParty(ctx.aor); //TODO: configurable From
        dlg->setRemoteParty(ctx.aor);

        if(!ctx.path.empty())
            dlg->setRouteSet(ctx.path);
        //dlg->setOutboundInterface(ctx.interface_id);

        dlg->setLocalTag(REGISTAR_QUEUE_NAME); //From-tag and queue to handle replies
        dlg->setCallid(AmSession::getNewId());

        if(0==dlg->sendRequest(SIP_METH_OPTIONS))
        {
            //add dlg to local hash
            AmLock uac_l(uac_dlgs_mutex);
            auto dlg_ptr = dlg.release();
            uac_dlgs.emplace(dlg_ptr->getCallid(), dlg_ptr);
        } else {
            ERROR("failed to send keep alive OPTIONS request for %s",
                ctx.aor.data());
        }

        ctx.next_send += keepalive_interval;

        if(sent > max_registrations_per_slot) {
            //cycle drift_interval over the range: [ 0, 2*max_interval_drift ]
            drift_interval++;
            drift_interval %= double_max_interval_drift;

            /* adjust around keepalive_interval
             * within the range: [ -max_interval_drift, max_interval_drift ] */
            ctx.next_send += drift_interval - max_interval_drift;
        }
    }
}

