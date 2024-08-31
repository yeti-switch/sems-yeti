#include <format_helper.h>

#include "ResourceRedisClient.h"
#include <cstdarg>

/* Connection */

ResourceRedisClient::Connection::Connection(const string &id)
  : id(id), info(), is_connected(false)
{
    DBG("ResourceRedisClient::Connection::Connection(..)");
}

ResourceRedisClient::Connection::~Connection()
{
    DBG("ResourceRedisClient::Connection::~Connection()");
}

const RedisScript* ResourceRedisClient::Connection::script(const string &name) {
    for(const auto & s : info.scripts)
        if(s.name == name)
            return &s;

    return nullptr;
}

bool ResourceRedisClient::Connection::wait_connected() const {
    while(!is_connected) { usleep(100); }
    return true;
}

/* Request */

ResourceRedisClient::Request::Request(cb_func callback)
  : callback(callback), finished(false), iserror(false), error_msg(), error_code(0), is_persistent(false)
{}

void ResourceRedisClient::Request::on_finish()
{
    if(callback)
        callback(iserror, result);

    finished.set(true);
}

void ResourceRedisClient::Request::on_error(int code, const char* error, ...)
{
    va_list argptr;
    va_start (argptr, error);
    size_t len = vsnprintf(0, 0, error, argptr);
    error_msg.resize(len + 1);
    vsnprintf(&error_msg[0], len + 1, error, argptr);
    va_end(argptr);
    error_code = code;

    ERROR("error: %d: %s", error_code, error_msg.c_str());

    iserror = true;
    on_finish();
}

bool ResourceRedisClient::Request::wait_finish(int timeout) { return finished.wait_for_to(timeout); }
bool ResourceRedisClient::Request::is_error() const { return iserror; }
bool ResourceRedisClient::Request::is_finished() { return finished.get(); }
void ResourceRedisClient::Request::set_result(const AmArg& result) { this->result = result; }
const AmArg& ResourceRedisClient::Request::get_result() const { return result; }

/* ResourceRedisClient */

ResourceRedisClient::ResourceRedisClient(const string &conn_id_prefix)
{
    read_conn = new Connection(conn_id_prefix + "_" + READ_CONN_ID);
    write_conn = new Connection(conn_id_prefix + "_" + WRITE_CONN_ID);

    connections.emplace_back(read_conn);
    connections.emplace_back(write_conn);
}

void ResourceRedisClient::connect_all()
{
    for(const auto & conn : connections)
        connect(*conn);
}

void ResourceRedisClient::on_connect(const string &conn_id, const RedisConnectionInfo &info)
{
    for(auto & conn : connections)
        if(conn->id == conn_id) {
            conn->is_connected = true;
            conn->info = info;
            break;
        }
}

void ResourceRedisClient::on_disconnect(const string &conn_id, const RedisConnectionInfo &info)
{
    for(auto & conn : connections)
        if(conn->id == conn_id) {
            conn->is_connected = false;
            conn->info = info;
            break;
        }
}

bool ResourceRedisClient::prepare_request(Request* req, Connection* conn, const char* script_name, vector<AmArg> &args)
{
    string script_hash = "";

    if(script_name) {
        auto script = conn->script(script_name);
        if(!script || !script->is_loaded()) {
            req->on_error(500, "%s script not loaded", script_name);
            return false;
        }

        script_hash = script->hash;
    }

    return req->make_args(script_hash, args);
}

string ResourceRedisClient::get_script_path(const string &sript_name) const
{
    return format("{}/{}.lua", scripts_dir, sript_name);
}
