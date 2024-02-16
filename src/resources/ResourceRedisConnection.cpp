#include "ResourceRedisConnection.h"
#include "../yeti.h"
#include "../cfg/yeti_opts.h"

#include <AmEventDispatcher.h>
#include <AmPlugIn.h>
#include <format_helper.h>

#define EPOLL_MAX_EVENTS    2048
#define session_container AmSessionContainer::instance()
#define event_dispatcher AmEventDispatcher::instance()

const string RESOURCE_QUEUE_NAME("resource");

static string get_key(const Resource &r)
{
    return format("r:{}:{}", r.type, r.id);
}

/* InvalidateRequest */

bool ResourceRedisConnection::InvalidateRequest::make_args(Connection *conn, const string& script_hash, vector<AmArg> &args)
{
    args = {"EVALSHA", script_hash.c_str(), 1, AmConfig.node_id};
    return true;
}

/* OperationRequest */

ResourceRedisConnection::OperationRequest::OperationRequest(ResourcesOperationList& rol, bool reduce_operations, cb_func *callback)
  : Request(callback),
    operations(std::move(rol)),
    reduce_operations(reduce_operations)
{}

bool ResourceRedisConnection::OperationRequest::make_args_reduce(const string& script_hash, vector<AmArg> &args)
{
    std::unordered_map<string, int> accumulated_changes;

    for(auto &operation : operations) {
        switch(operation.op) {
        case ResourcesOperation::RES_GET:
            for(const auto &r: operation.resources) {
                if(!r.active) continue;
                auto [it, inserted] = accumulated_changes.try_emplace(
                    get_key(r), r.takes);
                if(!inserted) {
                    it->second += r.takes;
                    if(0 == it->second)
                        accumulated_changes.erase(it);
                }
            }
            break;
        case ResourcesOperation::RES_PUT:
            for(const auto &r: operation.resources) {
                if(!r.taken) continue;
                auto [it, inserted] = accumulated_changes.try_emplace(
                    get_key(r), -(r.takes));
                if(!inserted) {
                    it->second -= r.takes;
                    if(0 == it->second)
                        accumulated_changes.erase(it);
                }
            }
            break;
        } //switch(operation.op)
    }

    if(accumulated_changes.empty()) { //no changes for resources
        on_finish();
        return false;
    }

    args = {"EVALSHA", script_hash.c_str(), 0};

    for(auto &[key, value] : accumulated_changes) {
        args.emplace_back(
            format("{} {} {}",
                key, AmConfig.node_id, value));
    }

    return true;
}

bool ResourceRedisConnection::OperationRequest::make_args_no_reduce(const string& script_hash, vector<AmArg> &args)
{
    size_t operations_count = 0;
    ResourceList::iterator r_it;

    for(auto &operation : operations) {
        switch(operation.op) {
        case ResourcesOperation::RES_GET:
            operation.resources.remove_if([](auto &r) {
                return !r.active;
            });
            operations_count += operation.resources.size();
            break;
        case ResourcesOperation::RES_PUT:
            r_it = operation.resources.begin();
            while(r_it != operation.resources.end()) {
                if(r_it->taken) {
                    //we use HINCRBY with negative value for put
                    r_it->takes = - (r_it->takes);
                    ++r_it;
                } else {
                    r_it = operation.resources.erase(r_it);
                }
            }
            operation.resources.remove_if([](auto &r) {
                return !r.taken;
            });
            operations_count += operation.resources.size();
            break;
        } //switch(operation.op)
    }

    if(0 == operations_count) {
        on_finish();
        return false;
    }

    args = {"EVALSHA", script_hash.c_str(), 0};

    for(auto &operation : operations) {
        for(const auto &r : operation.resources) {
            args.emplace_back(
                format("{} {} {}",
                    get_key(r), AmConfig.node_id, r.takes));
        }
    }

    return true;
}

bool ResourceRedisConnection::OperationRequest::make_args(Connection *, const string& script_hash, vector<AmArg> &args)
{
    if(reduce_operations)
        return make_args_reduce(script_hash, args);

    return make_args_no_reduce(script_hash, args);
}

const ResourcesOperationList& ResourceRedisConnection::OperationRequest::get_resource_operations() const
{
    return operations;
}

/* GetAllRequest */

ResourceRedisConnection::GetAllRequest::GetAllRequest(const JsonRpcRequestEvent& req)
  : Request(), req(new JsonRpcRequestEvent(req))
{
    str2int(req.params.get(0).asCStr(), this->type);
    str2int(req.params.get(1).asCStr(), this->id);
}

ResourceRedisConnection::GetAllRequest::GetAllRequest(int type, int id, cb_func *callback)
  : Request(callback), type(type), id(id), req(nullptr)
{}

bool ResourceRedisConnection::GetAllRequest::make_args(Connection *conn, const string& script_hash, vector<AmArg> &args)
{
    args = {"EVALSHA", script_hash.c_str(), 2, type, id};
    return true;
}

void ResourceRedisConnection::GetAllRequest::on_finish()
{
    Request::on_finish();

    if(req) {
        if(iserror) {
            AmArg ret;
            ret["message"] = error_msg.c_str();
            ret["code"] = error_code;
            postJsonRpcReply(*req, ret, true);
        } else {
            postJsonRpcReply(*req, result);
        }
    }
}

int ResourceRedisConnection::GetAllRequest::get_type() const { return type; };
int ResourceRedisConnection::GetAllRequest::get_id() const { return id; };
JsonRpcRequestEvent* ResourceRedisConnection::GetAllRequest::get_req() const { return req.get(); };

/* CheckRequest */

ResourceRedisConnection::CheckRequest::CheckRequest(const ResourceList& rl)
  : Request(), rl(rl)
{
    is_persistent = true;
}

bool ResourceRedisConnection::CheckRequest::make_args(Connection *conn, const string& script_hash, vector<AmArg> &args)
{
    args = {"EVALSHA", script_hash.c_str(), 0};

    auto make_arg = [](const Resource &r) -> string {
        ostringstream ss;
        ss << "r:" << r.type << ':' << r.id;
        return ss.str();
    };

    for(const auto & res : rl)
        args.emplace_back(make_arg(res));

    return true;
}

const ResourceList& ResourceRedisConnection::CheckRequest::get_resources() const { return rl; }

/* ResourceRedisConnection */

ResourceRedisConnection::ResourceRedisConnection(const string& queue_name)
  : AmEventFdQueue(this),
    ResourceRedisClient(queue_name),
    queue_name(queue_name),
    write_async_is_busy(false),
    resources_inited(false),
    write_queue_size(stat_group(Gauge, "yeti", "resources_write_queue_size").addAtomicCounter()),
    resources_initialized_cb(nullptr),
    operation_result_cb(nullptr)
{
    event_dispatcher->addEventQueue(queue_name, this);
}

ResourceRedisConnection::~ResourceRedisConnection()
{
    event_dispatcher->delEventQueue(queue_name);
}

bool ResourceRedisConnection::post_request(Request* req, Connection* conn, const char* script_name, UserTypeId user_type_id)
{
    unique_ptr<Request> req_ptr(req);
    vector<AmArg> args;
    if(prepare_request(req_ptr.get(), conn, script_name, args) == false) {
        return false;
    }

    return session_container->postEvent(REDIS_APP_QUEUE,
        new RedisRequest(queue_name, conn->id, args, req_ptr.release(), (int)user_type_id));
}

/* AmThread */

void ResourceRedisConnection::run()
{
    void *p;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("resources");
    running = true;

    ResourceRedisClient::connect_all();

    do {
        int ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p = e.data.ptr;

            if(p==static_cast<AmEventFdQueue *>(this)){
                processEvents();
            } else if(p==&stop_event){
                stop_event.read();
                running = false;
                break;
            }
        }
    } while(running);

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("ResourceRedisConnection stopped");

    stopped.set(true);
}

void ResourceRedisConnection::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

/* AmEventHandler */

void ResourceRedisConnection::process(AmEvent* event)
{
    INFO("process ev %d", event->event_id);
    switch(event->event_id) {
        case E_SYSTEM: {
            AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(event);
            if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown)
                stop_event.fire();

            return;
        }
    }

    switch(event->event_id) {
        case RedisEvent::ConnectionState:
            if(auto e = dynamic_cast<RedisConnectionState*>(event)) {
                process_redis_conn_state_event(*e);
                return;
            }
            break;
        case RedisEvent::Reply:
            if(auto e = dynamic_cast<RedisReply*>(event)) {
                process_redis_reply_event(*e);
                return;
            }
            break;
    }

    switch(event->event_id) {
        case JSONRPC_EVENT_ID:
            if(auto e = dynamic_cast<JsonRpcRequestEvent*>(event)) {
                process_jsonrpc_request(*e);
                return;
            }
            break;
    }

    ERROR("got unexpected event ev %d", event->event_id);
}

int ResourceRedisConnection::configure(cfg_t *confuse_cfg, const AmConfigReader& cfg)
{
    reduce_operations = cfg_getbool(confuse_cfg, opt_resources_reduce_operations);
    scripts_dir = cfg_getstr(confuse_cfg, opt_resources_scripts_dir);

    if(cfg2RedisCfg(cfg, writecfg, "write") ||
       cfg2RedisCfg(cfg, readcfg, "read")) {
        return -1;
    }

    // check dependencies
    if(!AmPlugIn::instance()->getFactory4Config("redis")) {
        ERROR("redis module isn't loaded");
        return -1;
    }

    return 0;
}

int ResourceRedisConnection::cfg2RedisCfg(const AmConfigReader &cfg, RedisConfig &rcfg,string prefix)
{
//  DBG("%s()",FUNC_NAME);
    rcfg.server = cfg.getParameter(prefix+"_redis_host");
    if(rcfg.server.empty()){
        ERROR("no host or socket for %s redis",prefix.c_str());
        return -1;
    }
    rcfg.port = cfg.getParameterInt(prefix+"_redis_port");
    if(!rcfg.port){
        ERROR("no port for %s redis",prefix.c_str());
        return -1;
    }
    rcfg.timeout = cfg.getParameterInt(prefix+"_redis_timeout");
    if(!rcfg.port){
        ERROR("no timeout for %s redis",prefix.c_str());
        return -1;
    }
    rcfg.need_auth = cfg.hasParameter(prefix+"_redis_password");
    rcfg.password = cfg.getParameter(prefix+"_redis_password");
    rcfg.username = cfg.getParameter(prefix+"_redis_username");
    return 0;
}

bool ResourceRedisConnection::is_ready()
{
    return write_conn && write_conn->is_connected && resources_inited.get();
}

void ResourceRedisConnection::process_operations_queue_unsafe()
{
    if(!is_ready() || write_async_is_busy) return;

    if(!resource_operations_queue.empty()) {
        ResourcesOperationList operations;
        operations.swap(resource_operations_queue);

        if(operation(new OperationRequest(
            operations,
            reduce_operations,
            operation_result_cb)))
        {
            write_async_is_busy = true;
        }

        write_queue_size.set(0);
    }
}

void ResourceRedisConnection::process_operations_queue()
{
    AmLock l(queue_and_state_mutex);
    process_operations_queue_unsafe();
}

void ResourceRedisConnection::process_operation(const ResourceList& rl, ResourcesOperation::Operation op)
{
    AmLock l(queue_and_state_mutex);

    resource_operations_queue.emplace_back(rl, op);
    write_queue_size.inc();

    process_operations_queue_unsafe();
}

void ResourceRedisConnection::connect(const Connection &conn)
{
    session_container->postEvent(REDIS_APP_QUEUE,
        new RedisAddConnection(queue_name, conn.id, conn.info));
            }

void ResourceRedisConnection::on_connect(const string &conn_id, const RedisConnectionInfo &info)
{
    ResourceRedisClient::on_connect(conn_id, info);

    if(write_conn->id == conn_id) {
        if(!resources_inited.get())
            invalidate_initial(new InvalidateRequest(resources_initialized_cb));
        else
            process_operations_queue();
        }
    }

void ResourceRedisConnection::on_disconnect(const string &conn_id, const RedisConnectionInfo &info)
{
    ResourceRedisClient::on_disconnect(conn_id, info);

    AmLock l(queue_and_state_mutex);
    if(write_conn->id == conn_id) {
        if(write_async_is_busy) {
            resources_inited.set(false);
            write_async_is_busy = false;
        }
    }
}

void ResourceRedisConnection::get_resource_state(const JsonRpcRequestEvent& req)
{
    get_all(new GetAllRequest(req));
}

void ResourceRedisConnection::process_redis_conn_state_event(RedisConnectionState& event)
{
    if(event.state == RedisConnectionState::Connected)
        on_connect(event.conn_id, event.info);
    else
        on_disconnect(event.conn_id, event.info);
}

void ResourceRedisConnection::process_redis_reply_event(RedisReply& ev)
{
    switch (ev.user_type_id) {
        case UserTypeId::InvalidateInitial:
            process_invalidate_resources_initial_reply(ev);
            break;

        case UserTypeId::Invalidate:
            process_invalidate_resources_reply(ev);
            break;

        case UserTypeId::Operation:
            process_operation_resources_reply(ev);
            break;

        case UserTypeId::GetAll:
            process_get_all_resources_reply(ev);
            break;

        case UserTypeId::Check:
            process_check_resources_reply(ev);
            break;

        case UserTypeId::None: {
                auto req = dynamic_cast<Request*>(ev.user_data.get());
                if(!req) break;
                if(ev.result == RedisReply::SuccessReply)
                    req->on_finish();
                else
                    req->on_error(500, "custom request reply failed");
            }
            break;
    }
}

void ResourceRedisConnection::process_invalidate_resources_initial_reply(RedisReply& ev)
{
    auto req = dynamic_cast<InvalidateRequest*>(ev.user_data.get());
    if(!req) return;
    resources_inited.set(true);
                Yeti::instance().postEvent(new YetiComponentInited(YetiComponentInited::Resource));
    process_operations_queue();
    req->on_finish();
}

void ResourceRedisConnection::process_invalidate_resources_reply(RedisReply& ev)
{
    auto req = dynamic_cast<InvalidateRequest*>(ev.user_data.get());
    if(!req) return;
    resources_inited.set(true);
            process_operations_queue();
    req->on_finish();
}

void ResourceRedisConnection::process_operation_resources_reply(RedisReply& ev)
{
    auto req = dynamic_cast<OperationRequest*>(ev.user_data.get());
    if(!req) return;
    const bool is_error = ev.result != RedisReply::SuccessReply;

    if(is_error)
        req->on_error(500, "operation resources reply failed");
    else
        req->on_finish();

    AmLock l(queue_and_state_mutex);
    write_async_is_busy = false;
    if(is_error) {
        // on error have to reset the connection and invalidate resources
        //redis::redisAsyncDisconnect(write_async->get_async_context());//!!!
        //resources_inited.set(false);
    } else if(!resources_inited.get()) {
        // for rpc command of invalidate resources(if connection was busy)
        invalidate(new InvalidateRequest());
    } else {
        // trying the next operation after successful finished previous
        process_operations_queue_unsafe();
    }
}

void ResourceRedisConnection::process_get_all_resources_reply(RedisReply& ev)
{
    auto req = dynamic_cast<GetAllRequest*>(ev.user_data.get());
    if(!req) return;

    if(ev.result != RedisReply::SuccessReply) {
        req->on_error(500, "no reply from storage");
            return;
        }

    if(isArgArray(ev.data) == false) {
        req->on_error(500, "undesired reply from the storage");
        return;
    }

    AmArg result;
    result.assertStruct();
    const bool single_key = req->get_type() != ANY_VALUE && req->get_id() != ANY_VALUE;

    // example: [['r:0:472', [1, 0]], ['r:1:472', [1, 0]]]
    for(size_t i = 0; i < ev.data.size(); ++i) {
        AmArg& item = ev.data[i];
        if(isArgArray(item) == false || item.size() < 2) {
            req->on_error(500, "undesired reply from the storage");
            return;
        }

        AmArg& key = item[0];
        AmArg& all_res = item[1];

        if(isArgCStr(key) == false || isArgArray(all_res) == false) {
            req->on_error(500, "undesired reply from the storage");
            return;
        }

        AmArg &q = single_key ? result : result[key.asCStr()];
        for(size_t j = 0; j < all_res.size(); j+=2) {
            try {
                q.push(
                    int2str(all_res[j].asInt()), //node_id
                    AmArg(all_res[j+1]).asInt()); //value
            } catch(...) {
                req->on_error(500, "can't parse response");
            }
        }
    }

    req->set_result(result);
    req->on_finish();
}

void ResourceRedisConnection::process_check_resources_reply(RedisReply& ev)
{
    auto req = dynamic_cast<CheckRequest*>(ev.user_data.get());
    if(!req) return;

    if(req->is_persistent) {
        // avoid user_data's ptr deletion
        ev.user_data.release();
    }

    if(ev.result != RedisReply::SuccessReply)
        req->on_error(500, "reply error in the request");
    else if(isArgArray(ev.data) == false)
        req->on_error(500, "undesired reply from the storage");
    else
        req->set_result(ev.data);

    req->on_finish();
}

void ResourceRedisConnection::process_jsonrpc_request(const JsonRpcRequestEvent& request)
{
    switch(request.method_id) {
        case MethodGetResourceState:
        get_resource_state(request);
            break;
    }
}

int ResourceRedisConnection::init()
{
    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    epoll_link(epoll_fd, true);
    stop_event.link(epoll_fd,true);

    auto cfg_conn_info = [](const RedisConfig &cfg, RedisConnectionInfo &info) {
        info.host = cfg.server;
        info.port = cfg.port;

        if(cfg.need_auth) {
            info.password = cfg.password;
            info.username = cfg.username;
        }
    };

    cfg_conn_info(readcfg, read_conn->info);
    cfg_conn_info(writecfg, write_conn->info);

    write_conn->info.scripts = {
        {INVALIDATE_RESOURCES_SCRIPT, get_script_path(INVALIDATE_RESOURCES_SCRIPT)},
        {OPERATION_RESOURCES_SCRIPT, get_script_path(OPERATION_RESOURCES_SCRIPT)}
    };

    read_conn->info.scripts = {
        {GET_ALL_RESOURCES_SCRIPT, get_script_path(GET_ALL_RESOURCES_SCRIPT)},
        {CHECK_RESOURCES_SCRIPT, get_script_path(CHECK_RESOURCES_SCRIPT)}
    };

    return 0;
}

bool ResourceRedisConnection::invalidate_resources_sync()
{
    if(!write_conn->is_connected) {
        INFO("resources will be invalidated after the connect");
    } else if(!resources_inited.get()) {
        INFO("resources are in invalidation process");
    } else if(write_async_is_busy) {
        INFO("resources will be invalidated after the job finished");
    } else {
        invalidate(new InvalidateRequest());
    }
    resources_inited.set(false);
    return resources_inited.wait_for_to(writecfg.timeout);
}

void ResourceRedisConnection::registerResourcesInitializedCallback(Request::cb_func *func)
{
    resources_initialized_cb = func;
}

void ResourceRedisConnection::registerOperationResultCallback(Request::cb_func *func)
{
    operation_result_cb = func;
}

void ResourceRedisConnection::put(ResourceList& rl)
{
    process_operation(rl, ResourcesOperation::RES_PUT);
}

void ResourceRedisConnection::get(ResourceList& rl)
{
    for(auto& res : rl) {
        if(!res.active || res.taken) continue;
        res.taken = true;
    }

    process_operation(rl, ResourcesOperation::RES_GET);
}

#define CHECK_STATE_NORMAL 0
#define CHECK_STATE_FAILOVER 1
#define CHECK_STATE_SKIP 2

ResourceResponse ResourceRedisConnection::get(ResourceList &rl, ResourceList::iterator &resource)
{
    ResourceResponse ret = RES_ERR;

    resource = rl.begin();

    unique_ptr<CheckRequest> req(new CheckRequest(rl));

    if(!check(req.get())) {
        //req already cleaned
        req.release();
        return ret;
    }

    if(!req->wait_finish(readcfg.timeout)) {
        req->is_persistent = false;
        req.release();
        return ret;
    }

    if(req->is_error())
        return ret;

    bool resources_available = true;
    int check_state = CHECK_STATE_NORMAL;
    AmArg result = req->get_result();
    for(size_t i = 0; i < result.size(); i++,++resource) {
        Resource &res = *resource;
        if(CHECK_STATE_SKIP==check_state){
            DBG("skip %d:%d intended for failover",res.type,res.id);
            if(!res.failover_to_next) //last failover resource
                check_state = CHECK_STATE_NORMAL;
            continue;
        }

        DBG("check_resource %d:%d %ld/%d",
            res.type,res.id,result[i].asLongLong(),res.limit);
        //check limit
        if(result[i].asLongLong() >= res.limit){
            DBG("resource %d:%d overload ",
                res.type,res.id);
            if(res.failover_to_next){
                DBG("failover_to_next enabled. check the next resource");
                check_state = CHECK_STATE_FAILOVER;
                continue;
            }
            resources_available = false;
            break;
        } else {
            res.active = true;
            if(CHECK_STATE_FAILOVER==check_state) {
                DBG("failovered to the resource %d:%d",res.type,res.id);
                //if(res.failover_to_next)	//skip if not last
                //    check_state = CHECK_STATE_SKIP;
            }
            check_state = res.failover_to_next ?
                CHECK_STATE_SKIP : CHECK_STATE_NORMAL;
        }
    }

    if(!resources_available){
        DBG("resources are unavailable");
        ret = RES_BUSY;
    } else {
        get(rl);
        ret = RES_SUCC;
    }
    return ret;
}

void ResourceRedisConnection::get_config(AmArg& ret)
{
    AmArg& write = ret["write"];
    write["connection"] = writecfg.server+":"+int2str(writecfg.port);
    AmArg& read = ret["read"];
    read["connection"] = readcfg.server+":"+int2str(readcfg.port);
}

bool ResourceRedisConnection::get_resource_state(const std::string& connection_id,
    const AmArg& request_id, const AmArg& params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodGetResourceState, params));
    return true;
}

bool ResourceRedisConnection::invalidate_initial(InvalidateRequest* req)
{
    return post_request(req, write_conn, INVALIDATE_RESOURCES_SCRIPT, UserTypeId::InvalidateInitial);
}

bool ResourceRedisConnection::invalidate(InvalidateRequest* req)
{
    return post_request(req, write_conn, INVALIDATE_RESOURCES_SCRIPT, UserTypeId::Invalidate);
}

bool ResourceRedisConnection::operation(OperationRequest* req)
{
    return post_request(req, write_conn, OPERATION_RESOURCES_SCRIPT, UserTypeId::Operation);
}

bool ResourceRedisConnection::get_all(GetAllRequest* req)
{
    return post_request(req, read_conn, GET_ALL_RESOURCES_SCRIPT, UserTypeId::GetAll);
}

bool ResourceRedisConnection::check(CheckRequest* req)
{
    return post_request(req, read_conn, CHECK_RESOURCES_SCRIPT, UserTypeId::Check);
}
