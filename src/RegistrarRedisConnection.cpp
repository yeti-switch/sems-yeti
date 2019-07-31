#include "RegistrarRedisConnection.h"

#include "yeti.h"
#include "AmSipMsg.h"

#define REDIS_REPLY_SCRIPT_LOAD 0
#define REDIS_REPLY_SUBSCRIPTION 1
#define REDIS_REPLY_CONTACTS_DATA 2

RegistrarRedisConnection::ContactsSubscriptionConnection::ContactsSubscriptionConnection(
    KeepAliveContexts &keepalive_contexts)
  : RedisConnection("reg_subscription", "reg_async_redis_sub"),
    keepalive_contexts(keepalive_contexts),
    load_contacts_data("load_contacts_data", queue_name)
{}

void RegistrarRedisConnection::ContactsSubscriptionConnection::on_connect()
{
    //load contacts data loading script
    load_contacts_data.load("/etc/yeti/scripts/load_contacts.lua", REDIS_REPLY_SCRIPT_LOAD);
}

void RegistrarRedisConnection::ContactsSubscriptionConnection::process_reply_event(RedisReplyEvent &event)
{
    /*DBG("ContactsSubscriptionConnection got event %d. data: %s",
        event.user_type_id, AmArg::print(event.data).c_str());*/

    if(event.result!=RedisReplyEvent::SuccessReply) {
        DBG("error reply: %d, data: %s",event.result, AmArg::print(event.data).data());
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
        if(!postRedisRequestFmt(
            queue_name, queue_name, false,
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

void RegistrarRedisConnection::ContactsSubscriptionConnection::process_loaded_contacts(const AmArg &data)
{
    AmLock l(keepalive_contexts.mutex);

    keepalive_contexts.clear();

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

        keepalive_contexts.emplace(std::make_pair(
            key,
            keepalive_ctx_data(
                key.substr(pos),  //aor
                d[1].asCStr(),    //path
                arg2int(d[2])))); // interface_id
    }

    //keepalive_contexts.dump();

    //subscribe to del/expire events
    if(!postRedisRequestFmt(
        queue_name, queue_name, true,
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

    keepalive_contexts.mutex.lock();
    keepalive_contexts.erase(key_arg.asCStr());
    //keepalive_contexts.dump();
    keepalive_contexts.mutex.unlock();
}

RegistrarRedisConnection::RegistrarRedisConnection()
  : RedisConnection("reg", "reg_async_redis"),
     contacts_subscription(keepalive_contexts),
     yeti_register("yeti_register", queue_name),
     yeti_aor_lookup("yeti_aor_lookup", queue_name),
     yeti_rpc_aor_lookup("yeti_rpc_aor_lookup", queue_name)
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

    ret = RedisConnection::init(_host, _port);
    if(ret || !subscription_enabled) return ret;

    return contacts_subscription.init(_host, _port);
}

void RegistrarRedisConnection::on_connect()
{
    yeti_register.load("/etc/yeti/scripts/register.lua", REDIS_REPLY_SCRIPT_LOAD);
    yeti_aor_lookup.load("/etc/yeti/scripts/aor_lookup.lua", REDIS_REPLY_SCRIPT_LOAD);
    yeti_rpc_aor_lookup.load("/etc/yeti/scripts/rpc_aor_lookup.lua", REDIS_REPLY_SCRIPT_LOAD);
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
        queue_name,
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
        queue_name,
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
        queue_name,
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
    size_t aors_count = aor_ids.size();
    string str_size = long2str(static_cast<long>(aor_ids.size()));
    DBG("got %s AoR ids to resolve", str_size.c_str());

    if(yeti_aor_lookup.hash.empty()) {
        ERROR("empty yeti_aor_lookup.hash. lua scripting error");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }

    char *cmd = static_cast<char *>(malloc(128));
    char *s = cmd;

    s += sprintf(cmd, "*%lu\r\n$7\r\nEVALSHA\r\n$40\r\n%s\r\n$%u\r\n%lu\r\n",
        aors_count+3,
        yeti_aor_lookup.hash.data(),
        len_in_chars(aors_count), aors_count);

    for(const auto &id : aor_ids) {
        s += sprintf(s, "$%u\r\n%d\r\n",
            len_in_chars(id), id);
    }

    //send request to redis
    if(false==postRedisRequest(
        queue_name,
        local_tag,
        cmd,static_cast<size_t>(s-cmd)))
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
    char *s,*start;
    size_t n, i;
    int id;

    if(yeti_rpc_aor_lookup.hash.empty())
        throw AmSession::Exception(500,"registrar is not enabled");

    arg.assertArray();

    cmd.reset(static_cast<char *>(malloc(128)));
    s = start = cmd.get();
    n = arg.size();

    s += std::sprintf(s, "*%lu\r\n$7\r\nEVALSHA\r\n$40\r\n%s\r\n$%u\r\n%lu\r\n",
        n+3,
        yeti_rpc_aor_lookup.hash.data(),
        len_in_chars(n), n);

    for(i = 0; i < n; i++) {
        id = arg2int(arg[i]);
        s += sprintf(s, "$%u\r\n%d\r\n",
            len_in_chars(id), id);
    }

    if(false==postRedisRequest(
        queue_name,
        YETI_QUEUE_NAME,
        cmd.release(),static_cast<size_t>(s-cmd.get()),
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
        return;
    }

    it->second.update(aor, path, interface_id);
}

void RegistrarRedisConnection::on_keepalive_timer()
{
    //DBG("on keepalive timer");
    //keepalive_contexts.dump();
}

