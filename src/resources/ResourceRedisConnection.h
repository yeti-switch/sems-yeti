#pragma once

#include "ResourceRedisClient.h"
#include "Resource.h"

#include <ampi/JsonRPCEvents.h>
#include <AmEventFdQueue.h>

extern const string RESOURCE_QUEUE_NAME;

struct RedisConfig {
    vector<RedisAddr> addrs;
    RedisRole role;

    int timeout;
    bool need_auth;
    string username;
    string password;

    RedisConfig(RedisRole role)
      : role(role)
    {}
};

enum ResourceResponse {
    RES_SUCC,       //we successful got all resources
    RES_BUSY,       //one of resources is busy
    RES_ERR         //error occured on interaction with cache
};

class ResourceRedisConnection
  : public AmThread,
    public AmEventFdQueue,
    public AmEventHandler,
    public ResourceRedisClient
{
  public:

    /* InvalidateRequest */
    class InvalidateRequest: public Request
    {
        using Request::Request;

      protected:
        bool make_args(const string& script_hash, vector<AmArg> &args) override;
    };

    /* OperationRequest */
    class OperationRequest: public Request
    {
      private:
        ResourcesOperationList operations;
        bool reduce_operations;

        bool make_args_reduce(vector<AmArg> &args);
        bool make_args_no_reduce(vector<AmArg> &args);

      protected:
        bool make_args(const string& script_hash, vector<AmArg> &args) override;

      public:
        OperationRequest(ResourcesOperationList& rol, bool reduce_operations, cb_func *callback = nullptr);
        const ResourcesOperationList& get_resource_operations() const;
    };

    /* GetAllRequest */
    class GetAllRequest: public Request
    {
      private:
        int type;
        int id;
        unique_ptr<JsonRpcRequestEvent> req;

      protected:
        bool make_args(const string& script_hash, vector<AmArg> &args) override;

      public:
        GetAllRequest(int type, int id, cb_func *callback);
        GetAllRequest(const JsonRpcRequestEvent& req);

        void on_finish() override;

        int get_type() const;
        int get_id() const;
        JsonRpcRequestEvent* get_req() const;
    };

    /* CheckRequest */
    class CheckRequest: public Request
    {
      private:
        ResourceList rl;

      protected:
        bool make_args(const string& script_hash, vector<AmArg> &args) override;

      public:
        CheckRequest(const ResourceList& rl);
        const ResourceList& get_resources() const;
    };

    bool invalidate_initial(InvalidateRequest* req);
    bool invalidate(InvalidateRequest* req);
    bool operation(OperationRequest* req);
    bool get_all(GetAllRequest* req);
    bool check(CheckRequest* req);

  private:
    bool reduce_operations;
    int epoll_fd;
    AmEventFd stop_event;
    AmCondition<bool> stopped;
    string queue_name;

    RedisConfig writecfg;
    RedisConfig readcfg;

    AmMutex queue_and_state_mutex;
    bool write_async_is_busy;                           //guarded by queue_and_state_mutex
    ResourcesOperationList resource_operations_queue;   //guarded by queue_and_state_mutex

    AmCondition<bool> resources_inited;

    AtomicCounter &write_queue_size;

    void process_operations_queue_unsafe();

  protected:
    int cfg2RedisCfg(cfg_t *cfg, RedisConfig &rcfg);
    bool is_ready();

    void process_operations_queue();
    void process_operation(const ResourceList& rl, ResourcesOperation::Operation op);
    void process_operations_list(ResourcesOperationList& rol);

    void connect(const Connection &conn) override;
    void on_connect(const string &conn_id, const RedisConnectionInfo &info) override;
    void on_disconnect(const string &conn_id, const RedisConnectionInfo &info) override;

    void get_resource_state(const JsonRpcRequestEvent& req);

    void on_stop() override;
    void process(AmEvent* event) override;
    void process_redis_conn_state_event(RedisConnectionState& event);
    void process_redis_reply_event(RedisReply& event);
    void process_invalidate_resources_initial_reply(RedisReply& ev);
    void process_invalidate_resources_reply(RedisReply& ev);
    void process_operation_resources_reply(RedisReply& ev);
    void process_get_all_resources_reply(RedisReply& ev);
    void process_check_resources_reply(RedisReply& ev);
    void process_jsonrpc_request(const JsonRpcRequestEvent& event);

  public:
    ResourceRedisConnection(const string& queue_name = RESOURCE_QUEUE_NAME);
    virtual ~ResourceRedisConnection();

    int configure(cfg_t *confuse_cfg);
    int init();
    bool invalidate_resources_sync();
    void get_config(AmArg& ret);

    void run() override;

    Request::cb_func *resources_initialized_cb;
    void registerResourcesInitializedCallback(Request::cb_func *func);

    Request::cb_func *operation_result_cb;
    void registerOperationResultCallback(Request::cb_func *func);

    void put(ResourceList &rl);
    void get(ResourceList &rl);
    ResourceResponse get(ResourceList &rl, ResourceList::iterator &resource);

    bool get_resource_state(const string& connection_id, const AmArg& request_id, const AmArg& params);

    Connection* get_write_conn(){ return write_conn; }
    Connection* get_read_conn(){ return read_conn; }

    enum UserTypeId {
        InvalidateInitial = 1000,
        Invalidate,
        Operation,
        GetAll,
        Check,
        None
    };

    bool post_request(Request* req, Connection* conn, const char* script_name = nullptr, UserTypeId user_type_id = None);
    string get_queue_name() { return queue_name; }
};
