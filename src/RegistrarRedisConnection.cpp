#include "RegistrarRedisConnection.h"

#include "yeti.h"
#include "AmSipMsg.h"

#define REDIS_REPLY_SCRIPT_LOAD 0
#define REDIS_REPLY_SUBSCRIPTION 1
#define REDIS_REPLY_CONTACTS_DATA 2

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
        registrar->onKeepAliveContextsChanged();
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

void RegistrarRedisConnection::keepalive_ctx_data::dump(const std::string &key) const
{
    DBG("keepalive_context. key: '%s', aor: '%s', path: '%s', interface_id: %d",
        key.c_str(),
        aor.data(), path.data(), interface_id);
}

void RegistrarRedisConnection::keepalive_ctx_data::dump(const std::string &key, AmArg &ret) const
{
    ret["key"] = key;
    ret["aor"] = aor;
    ret["path"] = path;
    ret["interface_id"] = interface_id;
    ret["next_send"] = next_send;
}

void RegistrarRedisConnection::KeepAliveContexts::dump()
{
    //AmLock l(mutex);
    DBG("%zd keepalive contexts", size());
    for(const auto &i : *this) {
        i.second.dump(i.first);
    }
}

void RegistrarRedisConnection::KeepAliveContexts::dump(AmArg &ret)
{
    ret.assertArray();
    AmLock l(mutex);
    for(const auto &i : *this) {
        ret.push(AmArg());
        i.second.dump(i.first, ret.back());
    }
}

void RegistrarRedisConnection::onKeepAliveContextsChanged()
{
    for(auto& ctx : keepalive_contexts) {
        if(ctx.second.next_send) continue;

        ctx.second.next_send = time(0) + last_time_index;
        last_time_index++;
        if(last_time_index == keepalive_interval)
            last_time_index = 0;
    }
}

void RegistrarRedisConnection::ContactsSubscriptionConnection::process_loaded_contacts(const AmArg &data)
{
    AmLock l(registrar->keepalive_contexts.mutex);

    registrar->keepalive_contexts.clear();

    if(!isArgArray(data))
        return;

    KeepAliveContexts::iterator it;

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

        registrar->keepalive_contexts.emplace(std::make_pair(
            key,
            keepalive_ctx_data(
                key.substr(pos),  //aor
                d[1].asCStr(),    //path
                arg2int(d[2])))); // interface_id
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

    registrar->keepalive_contexts.mutex.lock();
    registrar->keepalive_contexts.erase(key_arg.asCStr());
    registrar->onKeepAliveContextsChanged();
    //keepalive_contexts.dump();
    registrar->keepalive_contexts.mutex.unlock();
}

RegistrarRedisConnection::RegistrarRedisConnection()
  : RedisConnectionPool("reg", REGISTAR_QUEUE_NAME),
     last_time_index(0),
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

int RegistrarRedisConnection::init(const string &_host, int _port, bool _subscription_enabled)
{
    int ret;
    subscription_enabled = _subscription_enabled;

    ret = RedisConnectionPool::init();
    conn = addConnection(_host, _port);
    if(ret || !subscription_enabled || !conn) return -1;

    //TODO: move to ``configure(cfg_t* cfg)` after finish YETI-69
    keepalive_interval = Yeti::instance().config.registrar_keepalive_interval/1000000;

    return contacts_subscription.init(_host, _port);
}

void RegistrarRedisConnection::on_connect(RedisConnection* c) {
    yeti_register.load(c, "/etc/yeti/scripts/register.lua", REDIS_REPLY_SCRIPT_LOAD);
    yeti_aor_lookup.load(c, "/etc/yeti/scripts/aor_lookup.lua", REDIS_REPLY_SCRIPT_LOAD);
    yeti_rpc_aor_lookup.load(c, "/etc/yeti/scripts/rpc_aor_lookup.lua", REDIS_REPLY_SCRIPT_LOAD);
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
        "EVALSHA %s 1 %d",
        yeti_register.hash.c_str(),
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
        "EVALSHA %s 1 %d 0",
        yeti_register.hash.c_str(),
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
        "EVALSHA %s 1 %d %d %s %d %d %s %s",
        yeti_register.hash.c_str(),
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

    if(yeti_aor_lookup.hash.empty()) {
        ERROR("empty yeti_aor_lookup.hash. lua scripting error");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    std::ostringstream ss;
    ss << '*' << aors_count+3 << CRLF "$7" CRLF "EVALSHA" CRLF "$40" CRLF << yeti_aor_lookup.hash << CRLF;
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
        conn,
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

    if(yeti_rpc_aor_lookup.hash.empty())
        throw AmSession::Exception(500,"registrar is not enabled");

    arg.assertArray();

    n = arg.size();

    std::ostringstream ss;
    ss << '*' << n+3 << CRLF "$7" CRLF "EVALSHA" CRLF "$40" CRLF << yeti_rpc_aor_lookup.hash << CRLF;
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
        conn,
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

void RegistrarRedisConnection::updateKeepAliveContext(
    const string &key,
    const string &aor,
    const string &path,
    int interface_id)
{
    AmLock l(keepalive_contexts.mutex);

    auto it = keepalive_contexts.find(key);
    if(it == keepalive_contexts.end()) {
        keepalive_contexts.emplace(std::make_pair(
            key,
            keepalive_ctx_data(aor, path, interface_id)));
        onKeepAliveContextsChanged();
        return;
    }

    it->second.update(aor, path, interface_id);
}

void RegistrarRedisConnection::on_keepalive_timer()
{
    //DBG("on keepalive timer");
    AmLock l(keepalive_contexts.mutex);

    uint64_t current = time(0);
    for(auto &ctx_it : keepalive_contexts) {
        auto &ctx = ctx_it.second;
        if(ctx.next_send && current < ctx.next_send) continue;

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
    }
}

