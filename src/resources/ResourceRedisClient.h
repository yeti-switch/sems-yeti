#pragma once

#include <ampi/RedisApi.h>
#include <string>
#include <vector>
#include <memory>
#include <atomic>

class YetiTest;

using std::string;
using std::vector;
using std::unique_ptr;

#define READ_CONN_ID    "read"
#define WRITE_CONN_ID   "write"

#define INVALIDATE_RESOURCES_SCRIPT     "invalidate_resources"
#define GET_ALL_RESOURCES_SCRIPT        "get_all_resources"
#define CHECK_RESOURCES_SCRIPT          "check_resources"

class ResourceRedisClient
{
  protected:
    friend YetiTest;

    /* Connection */
    struct Connection {
        string id;
        RedisConnectionInfo info;
        bool is_connected;

        Connection(const string &id);
        virtual ~Connection();
        const RedisScript* script(const string &name);

        // for unit tests
        bool wait_connected() const;
    };

  public:
    /* Request */
    class Request
      : public AmObject
    {
      public:
        typedef void cb_func(bool is_error, const AmArg& result);

      protected:
        cb_func *callback;
        AmCondition<bool> finished;
        bool iserror;
        string error_msg;
        int error_code;
        AmArg result;

        friend ResourceRedisClient;
        virtual bool make_args(Connection *conn, const string& script_hash, vector<AmArg> &args) = 0;

      public:
        Request(cb_func *callback = nullptr);

        bool wait_finish(int timeout);
        virtual void on_finish();
        void on_error(int code, const char* error, ...);

        bool is_error() const;
        bool is_finished();
        void set_result(const AmArg& result);
        const AmArg& get_result() const;
        std::atomic<bool> is_persistent;
    };

  protected:

    Connection* read_conn;
    Connection* write_conn;
    vector<unique_ptr<Connection>> connections;
    string scripts_dir;

    virtual void connect(const Connection &conn) = 0;
    virtual void on_connect(const string &conn_id, const RedisConnectionInfo &info);
    virtual void on_disconnect(const string &conn_id, const RedisConnectionInfo &info);

    bool prepare_request(Request* req, Connection* conn, const char* script_name, vector<AmArg> &args);
    string get_script_path(const string &sript_name) const;

  public:
    ResourceRedisClient(const string &conn_id_prefix);
    virtual ~ResourceRedisClient() {}
    virtual void connect_all();
};
