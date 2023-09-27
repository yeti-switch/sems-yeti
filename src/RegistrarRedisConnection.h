#pragma once

#include "RedisConnectionPool.h"
#include "RedisConnection.h"
#include "Auth.h"

#include <unordered_map>

class RegistrarRedisConnection
  : public RedisConnectionPool
{
  private:
    //contains data to generate correct keepalive OPTIONS requests
    struct keepalive_ctx_data {
        string aor;
        string path;
        int interface_id;
        uint64_t next_send;

        keepalive_ctx_data(const string &aor, const string &path, int interface_id)
          : aor(aor),
            path(path),
            interface_id(interface_id),
            next_send(0)
        {}

        void update(const string &_aor, const string &_path, int _interface_id)
        {
            aor = _aor;
            path = _path;
            interface_id = _interface_id;
        }

        void dump(const std::string &key) const;
        void dump(const std::string &key, AmArg &ret) const;

    };

    /* has 4 modification sources:
     *  add events:
     *   - loading from redis on node start (lua script)
     *  add/update:
     *   - processing of bindings in redis reply (see: Yeti::processRedisRegisterReply)
     *  rm events:
     *   - expire events from redis
     *   - del events from redis
     */
    struct KeepAliveContexts
      : public std::unordered_map<std::string, keepalive_ctx_data>
    {
        AmMutex mutex;
        void dump();
        void dump(AmArg &ret);
    } keepalive_contexts;
    uint64_t keepalive_interval;
    uint64_t last_time_index;

    void onKeepAliveContextsChanged();

    std::unordered_map<std::string, AmSipDialog* > uac_dlgs;
    AmMutex uac_dlgs_mutex;

    class ContactsSubscriptionConnection
      : public RedisConnectionPool
    {
        RedisConnection* conn;
        RegistrarRedisConnection* registrar;
        RedisScript load_contacts_data;

        void process_loaded_contacts(const AmArg &key_arg);
        void process_expired_key(const AmArg &key_arg);
      protected:
        void on_connect(RedisConnection* c) override;

      public:
        ContactsSubscriptionConnection(RegistrarRedisConnection* registrar);
        void process_reply_event(RedisReplyEvent &event) override;
        int init(const string& host, int port);
    } contacts_subscription;

    bool subscription_enabled;

    RedisScript yeti_register;
    RedisScript yeti_aor_lookup;
    RedisScript yeti_rpc_aor_lookup;
    RedisConnection* conn;

  protected:
    void on_connect(RedisConnection* c) override;

public:
    RegistrarRedisConnection();

    void start();
    void stop();
    int init(const string &host, int port, bool subscription_enabled);

    void process(AmEvent* ev) override;
    void process_reply_event(RedisReplyEvent &event) override;

    bool fetch_all(
        const AmSipRequest &req,
        Auth::auth_id_type auth_id);

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
            //DBG("RpcAorLookupCtx() %p",this);
        }
        ~RpcAorLookupCtx()
        {
            //DBG("~RpcAorLookupCtx() %p",this);
        }
    };
    void rpc_resolve_aors_blocking(
        const AmArg &arg,
        RpcAorLookupCtx &ctx);

    void updateKeepAliveContext(
        const string &key,
        const string &aor,
        const string &path,
        int interface_id);
    void dumpKeepAliveContexts(AmArg &ret) { keepalive_contexts.dump(ret); }
    void on_keepalive_timer();
};
