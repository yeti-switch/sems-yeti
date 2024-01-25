#pragma once

#include "RedisConnectionPool.h"
#include "RedisConnection.h"
#include "Auth.h"

#include <unordered_map>
#include <chrono>

class RegistrarRedisConnection
  : public RedisConnectionPool
{
  private:
    //contains data to generate correct keepalive OPTIONS requests
    struct keepalive_ctx_data {
        std::string aor;
        std::string path;
        int interface_id;
        std::chrono::system_clock::time_point next_send;

        keepalive_ctx_data(
            const std::string &aor,
            const std::string &path,
            int interface_id,
            const std::chrono::system_clock::time_point &next_send)
          : aor(aor),
            path(path),
            interface_id(interface_id),
            next_send(next_send)
        {}

        void update(
            const std::string &_aor,
            const std::string &_path,
            int _interface_id,
            const std::chrono::system_clock::time_point &_next_send)
        {
            aor = _aor;
            path = _path;
            interface_id = _interface_id;
            next_send = _next_send;
        }

        void dump(
            const std::string &key,
            const std::chrono::system_clock::time_point &now) const;
        void dump(
            const std::string &key, AmArg &ret,
            const std::chrono::system_clock::time_point &now) const;

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

    std::chrono::seconds keepalive_interval;
    std::chrono::seconds max_interval_drift;
    uint32_t max_registrations_per_slot;

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
        void setAuthData(const string& password, const string& username = "");
    } contacts_subscription;

    bool subscription_enabled;
    bool use_functions;

    RedisScript yeti_register;
    RedisScript yeti_aor_lookup;
    RedisScript yeti_rpc_aor_lookup;
    RedisConnection* conn;
    RedisConnection* read_conn;

  protected:
    void on_connect(RedisConnection* c) override;

    int initConnection(cfg_t* cfg, RedisConnection*& c);

  public:
    RegistrarRedisConnection();

    void start();
    void stop();
    int configure(cfg_t* cfg);
    void setAuthData(const string& password, const string& username = "");


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

    const std::chrono::seconds &getKeepAliveInterval() {
        return keepalive_interval;
    }
    void createOrUpdateKeepAliveContext(
        const string &key,
        const string &aor,
        const string &path,
        int interface_id,
        const std::chrono::seconds &keep_alive_interval_offset = std::chrono::seconds{0});
    void removeKeepAliveContext(const std::string &key);
    void clearKeepAliveContexts();

    void dumpKeepAliveContexts(AmArg &ret) { keepalive_contexts.dump(ret); }
    void on_keepalive_timer();
};
