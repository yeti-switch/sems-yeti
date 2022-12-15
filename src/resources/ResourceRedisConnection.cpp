#include "ResourceRedisConnection.h"
#include "../yeti.h"

enum RpcMethodId {
    MethodGetResourceState
};

const string RESOURCE_QUEUE_NAME("resource");

ResourceRedisConnection::ResourceRedisConnection(const string& queue_name)
  : RedisConnectionPool("resources", queue_name),
    write_async(nullptr), read_async(nullptr),
    inv_seq(this),
    resources_inited(false),
    resources_initialized_cb(nullptr)
{}

ResourceRedisConnection::~ResourceRedisConnection() {}

int ResourceRedisConnection::configure(const AmConfigReader& cfg)
{
    if(cfg2RedisCfg(cfg, writecfg, "write") ||
       cfg2RedisCfg(cfg, readcfg, "read")) {
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
    return 0;
}

bool ResourceRedisConnection::is_ready()
{
    return write_async && write_async->is_connected() && resources_inited.get();
}

void ResourceRedisConnection::process_operations_queue()
{
    AmLock l(queue_and_state_mutex);

    if(!is_ready() || write_async_is_busy) return;

    if(resource_operations_queue.size()) {
        unique_ptr<OperationResources> op_seq(new OperationResources(this, resource_operations_queue));
        if(op_seq->perform()) {
            write_async_is_busy = true;
            op_seq.release(); //will be deleted by redis thread
        }
        resource_operations_queue.clear();
    }
}

void ResourceRedisConnection::process_operations_list(ResourceOperationList& rol)
{
    AmLock l(queue_and_state_mutex);

    if(is_ready() && !write_async_is_busy) {
        unique_ptr<OperationResources> op_seq(new OperationResources(this, rol));
        if(op_seq->perform()) {
            write_async_is_busy = true;
            op_seq.release(); //will be deleted by redis thread
        }
    } else {
        resource_operations_queue.splice(resource_operations_queue.end(), rol);
    }
}

void ResourceRedisConnection::on_connect(RedisConnection* c){
    if(c == write_async) {
        if(!resources_inited.get()) {
            if(inv_seq.get_state()) {
                WARN("initialization of the resources is not finished. Reset the sequence and try again");
                inv_seq.cleanup();
            }
            inv_seq.perform();
        } else {
            process_operations_queue();
        }
    }
}

void ResourceRedisConnection::on_disconnect(RedisConnection* c) {
    if(c == write_async) {
        if(write_async_is_busy) {
            resources_inited.set(false);
            write_async_is_busy = false;
        }
    }
}

void ResourceRedisConnection::get_resource_state(const JsonRpcRequestEvent& req)
{
    int type, id;
    str2int(req.params.get(0).asCStr(),type);
    str2int(req.params.get(1).asCStr(),id);
    (new GetAllResources(this, req, type, id))->perform();
}

void ResourceRedisConnection::process_reply_event(RedisReplyEvent& ev)
{
    if(ev.user_type_id == ResourceSequenceBase::REDIS_REPLY_INITIAL_SEQ) {
        InvalidateResources* seq = dynamic_cast<InvalidateResources*>(ev.user_data.get());
        if(!seq && seq != &inv_seq) {
            ERROR("incorrect user data[%p], expected initial sequence[%p]", seq, &inv_seq);
            return;
        }

        if(!inv_seq.processRedisReply(ev))
            ev.user_data.release();

        if(inv_seq.is_finish()) {
            INFO("resources invalidated");
            resources_inited.set(true);
            if(inv_seq.is_initial()) {
                if(resources_initialized_cb)
                    resources_initialized_cb();

                Yeti::instance().postEvent(new YetiComponentInited(YetiComponentInited::Resource));
            }
            process_operations_queue();
        }
    } else if(ev.user_type_id == ResourceSequenceBase::REDIS_REPLY_OP_SEQ) {
        OperationResources* seq = dynamic_cast<OperationResources*>(ev.user_data.get());
        if(!seq) {
            ERROR("incorrect user data[%p], expected put sequence", ev.user_data.get());
            return;
        }

        if(!seq->processRedisReply(ev))
            ev.user_data.release();

        if(seq->is_finish()) {
            //DBG("resources operation finished %s errors", seq->is_error() ? "with" : "without");
            write_async_is_busy = false;
            if(seq->is_error()) {
                // on error have to reset the connection and invalidate resources
                redis::redisAsyncDisconnect(write_async->get_async_context());
                resources_inited.set(false);
                inv_seq.cleanup();
            } else if(!resources_inited.get()) {
                // for rpc command of invalidate resources(if connection was busy)
                inv_seq.cleanup();
                inv_seq.perform();
            } else {
                // trying the next operation after successful finished previous
                process_operations_queue();
            }
        }
    } else if(ev.user_type_id == ResourceSequenceBase::REDIS_REPLY_GET_ALL_KEYS_SEQ) {
        GetAllResources* seq = dynamic_cast<GetAllResources*>(ev.user_data.get());
        if(!seq) {
            ERROR("incorrect user data[%p], expected get all sequence", ev.user_data.get());
            return;
        }

        if(!seq->processRedisReply(ev))
            ev.user_data.release();

        /*if(seq->is_finish()) {
            DBG("get resources finished %s errors", seq->is_error() ? "with" : "without");
        }*/
    } else if(ev.user_type_id == ResourceSequenceBase::REDIS_REPLY_CHECK_SEQ) {
        CheckResources* seq = dynamic_cast<CheckResources*>(ev.user_data.get());
        if(!seq) {
            ERROR("incorrect user data[%p], expected check sequence", ev.user_data.get());
            return;
        }

        if(!seq->processRedisReply(ev))
            ev.user_data.release();
    }
}

void ResourceRedisConnection::process(AmEvent* event)
{
    auto e = dynamic_cast<JsonRpcRequestEvent *>(event);
    if(event->event_id == JSONRPC_EVENT_ID && e)
        process_jsonrpc_request(*e);
    else RedisConnectionPool::process(event);
}

void ResourceRedisConnection::process_jsonrpc_request(const JsonRpcRequestEvent& request)
{
    switch(request.method_id) {
    case MethodGetResourceState: {
        get_resource_state(request);
    }
    }
}

int ResourceRedisConnection::init()
{
    int ret = RedisConnectionPool::init();
    write_async = addConnection(writecfg.server, writecfg.port);
    read_async = addConnection(readcfg.server, readcfg.port);
    if(ret || !write_async || !read_async) return -1;
    return 0;
}

bool ResourceRedisConnection::invalidate_resources()
{
    if(!write_async->is_connected()) {
        INFO("resources will be invalidated after the connect");
    } else if(!resources_inited.get()) {
        INFO("resources are in invalidation process");
    } else if(write_async_is_busy) {
        INFO("resources will be invalidated after the job finished");
    } else {
        inv_seq.cleanup();
        inv_seq.perform();
    }
    resources_inited.set(false);
    return resources_inited.wait_for_to(writecfg.timeout);
}

void ResourceRedisConnection::registerResourcesInitializedCallback(ResourceRedisConnection::cb_func* func)
{
    resources_initialized_cb = func;
}

void ResourceRedisConnection::put(ResourceList& rl)
{
    ResourceOperationList rol;
    for(auto& res : rl) {
        rol.emplace_back(ResourceOperation::RES_PUT, res);
    }
    process_operations_list(rol);
}

void ResourceRedisConnection::get(ResourceList& rl)
{
    ResourceOperationList rol;
    for(auto& res : rl) {
        res.taken = true;
        rol.emplace_back(ResourceOperation::RES_GET, res);
    }
    process_operations_list(rol);
}

#define CHECK_STATE_NORMAL 0
#define CHECK_STATE_FAILOVER 1
#define CHECK_STATE_SKIP 2

ResourceResponse ResourceRedisConnection::get(ResourceList &rl, ResourceList::iterator &resource)
{
    ResourceResponse ret = RES_ERR;

    resource = rl.begin();

    unique_ptr<CheckResources> cr_seq(new CheckResources(this, rl));

    if(!cr_seq->perform())
        return ret;

    if(!cr_seq->wait_finish(readcfg.timeout)) {
        //cr_seq will be deleted by redis thread
        cr_seq.release();

        return ret;
    }

    bool resources_available = true;
    int check_state = CHECK_STATE_NORMAL;
    AmArg result = cr_seq->get_result();
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
                                                 const AmArg& request_id,
                                                 const AmArg& params)
{
    postEvent(new JsonRpcRequestEvent(
        connection_id, request_id, false,
        MethodGetResourceState, params));
    return true;
}

