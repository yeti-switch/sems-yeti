#pragma once

#include "RedisConnection.h"
#include "Auth.h"

class RegistrarRedisConnection final
  : public RedisConnection
{
  protected:
    void on_connect() override;

  public:
    RegistrarRedisConnection();

    bool unbind_all(
        const AmSipRequest &req,
        Auth::auth_id_type auth_id);

    bool bind(
        const AmSipRequest &req,
        Auth::auth_id_type auth_id,
        const string &contact, int expires,
        const string &user_agent,
        const string &path);

    void resolve_aors(
        std::set<int> aor_ids,
        const string &local_tag);

    struct RpcAorLookupCtx
      : public AmObject
    {
        AmCondition<bool> cond;
        RedisReplyEvent::result_type result;
        AmArg data;
        RpcAorLookupCtx()
        {
            DBG("RpcAorLookupCtx() %p",this);
        }
        ~RpcAorLookupCtx()
        {
            DBG("~RpcAorLookupCtx() %p",this);
        }
    };
    void rpc_resolve_aors_blocking(
        const AmArg &arg,
        RpcAorLookupCtx &ctx);
};
