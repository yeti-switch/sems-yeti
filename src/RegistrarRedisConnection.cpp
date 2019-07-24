#include "RegistrarRedisConnection.h"

#include "yeti.h"
#include "AmSipMsg.h"

static string REG_REDIS_QUEUE_NAME("reg_async_redis");

static RedisScript yeti_register("yeti_register", REG_REDIS_QUEUE_NAME);
static RedisScript yeti_aor_lookup("yeti_aor_lookup", REG_REDIS_QUEUE_NAME);
static RedisScript yeti_rpc_aor_lookup("yeti_rpc_aor_lookup", REG_REDIS_QUEUE_NAME);

RegistrarRedisConnection::RegistrarRedisConnection()
  : RedisConnection("reg", REG_REDIS_QUEUE_NAME)
{ }

void RegistrarRedisConnection::on_connect()
{
    scripts_to_load+=3;
    yeti_register.load("/etc/yeti/scripts/register.lua");
    yeti_aor_lookup.load("/etc/yeti/scripts/aor_lookup.lua");
    yeti_rpc_aor_lookup.load("/etc/yeti/scripts/rpc_aor_lookup.lua");
}

bool RegistrarRedisConnection::unbind_all(const AmSipRequest &req, Auth::auth_id_type auth_id)
{
    return postRedisRequestFmt(
        REG_REDIS_QUEUE_NAME,
        YETI_QUEUE_NAME,
        new AmSipRequest(req), YETI_REDIS_REGISTER_TYPE_ID,
        "EVALSHA %s 1 %d",
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
        REG_REDIS_QUEUE_NAME,
        YETI_QUEUE_NAME,
        new AmSipRequest(req), YETI_REDIS_REGISTER_TYPE_ID,
        "EVALSHA %s 1 %d %s %d %d %d %s %s",
        yeti_register.hash.c_str(),
        auth_id, contact.c_str(),
        expires,
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
        REG_REDIS_QUEUE_NAME,
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
        REG_REDIS_QUEUE_NAME,
        YETI_QUEUE_NAME,
        cmd.release(),static_cast<size_t>(s-cmd.get()),
        &ctx, YETI_REDIS_RPC_AOR_LOOKUP_TYPE_ID))
    {
        //delete ctx;
        throw AmSession::Exception(500, "failed to post yeti_rpc_aor_lookup request");
    }

    //block because of no async support in RPC implementation yet
    ctx.cond.wait_for();
}
