#include "ResourceCache.h"
#include "log.h"
#include "AmUtils.h"
#include <sstream>

#include "../yeti.h"

#define REDIS_STRING_ZERO "(null)"

#define CHECK_STATE_NORMAL 0
#define CHECK_STATE_FAILOVER 1
#define CHECK_STATE_SKIP 2

ResourceCache::ResourceCache():
	tostop(false),
	data_ready(true)
{
}

int ResourceCache::configure(const AmConfigReader &cfg){
	int ret = write_pool.configure(cfg,"write",false) ||
			  read_pool.configure(cfg,"read",true);
	//!TODO: remove this dirty hack with proper write_pool class replace
	if(!ret){
		write_pool.setPoolSize(1); //set pool size to 1 for write_pool anyway
	}
	return ret;
}

static bool isArgNumber(AmArg& arg) {
    return isArgInt(arg) || isArgLongLong(arg) || isArgDouble(arg);
}

static void formatCommand(char** cmd, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int ret = vsnprintf(0, 0, fmt, args);
    va_end(args);
    va_start(args, fmt);
    if(ret) *cmd = (char*)malloc(ret + 1);
    vsprintf(*cmd, fmt, args);
    va_end(args);
}

void ResourceCache::run(){
	ResourceList put,get;
	ResourceList filtered_put;
	list <int> desired_response;
	redisContext *write_ctx;

	setThreadName("yeti-res-wr");

	auto &gc = Yeti::instance().config;

	read_pool.start();
	write_pool.start();

	if(!init_resources(true)){
		ERROR("can't init resources. stop");
		kill(getpid(),SIGTERM);
		return;
	}

	Yeti::instance().postEvent(new YetiComponentInited(YetiComponentInited::Resource));

	while(!tostop){
        //INFO("ResrouceCache::run() before data_ready");
		data_ready.wait_for();

        //INFO("ResrouceCache::run() before getConnection");

		write_ctx = write_pool.getConnection();
		while(write_ctx==NULL){
			DBG("get connection can't get connection from write redis pool. retry every 5s");
			sleep(5);
			if(tostop)
				return;
			write_ctx = write_pool.getConnection();
		}

        //INFO("ResrouceCache::run() got Connection");

		queues_mutex.lock();
			put.swap(put_resources_queue);
			get.swap(get_resources_queue);
		queues_mutex.unlock();

        //INFO("ResrouceCache::run() got queues");

		for(ResourceList::const_iterator rit = put.begin();rit!=put.end();++rit)
			if((*rit).taken)
				filtered_put.push_back(*rit);

		if(!filtered_put.size()&&!get.size()){
			data_ready.set(false);
			write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_OK);
			continue;
		}

		try {
			if(get.size()){ //we have resources to grab
                vector<string> commands;
				for(ResourceList::iterator rit = get.begin();rit!=get.end();++rit){
					Resource &r = (*rit);
					string key = get_key(r);
                    char* cmd;
                    formatCommand(&cmd, "HINCRBY %b %d %d",
                                                key.c_str(),key.size(),
                                                AmConfig.node_id,
                                                r.takes);
                    commands.push_back(cmd);
                    free(cmd);
				}

				AmArg res = runMultiCommand(write_ctx, commands, "HINCRBY");
                if(res.size() != get.size()) {
                    DBG("HINCRBY reply->elements = %ld, desired size = %ld",
                        res.size(),get.size());
                    throw ReplyDataException("HINCRBY mismatch responses array size");
                }
				ResourceList::iterator it = get.begin();
				for(size_t i = 0; i < res.size(); i++,++it){
					AmArg& r = res[i];
					if(!isArgNumber(r))
						throw ReplyDataException("HINCRBY integer expected");
					Resource &res = *it;
					DBG("get_resource %d:%d %d %lld",res.type,res.id,AmConfig.node_id,r.asLongLong());
				}
			}

			if(filtered_put.size()){
                vector<string> commands;
				ResourceList::iterator rit = filtered_put.begin();
				for(;rit!=filtered_put.end();++rit){
					Resource &r = (*rit);
					string key = get_key(r);
                    char* cmd;
                    formatCommand(&cmd, "HINCRBY %b %d %d",
						key.c_str(),key.size(),
						AmConfig.node_id,
						-r.takes/*pass negative to increment*/);
                    commands.push_back(cmd);
                    free(cmd);
				}

				AmArg res = runMultiCommand(write_ctx, commands, "HDECRBY");
                if(res.size() != filtered_put.size())
                    throw ReplyDataException("HDECRBY mismatch responses array size");
                ResourceList::iterator it = filtered_put.begin();
                for(size_t i = 0; i < res.size(); i++,++it) {
                    AmArg& r = res[i];
                    if(!isArgNumber(r))
                        throw ReplyDataException("HDECRBY integer expected");
                    Resource &res = *it;
                    DBG("put_resource %d:%d %d %lld",res.type,res.id,AmConfig.node_id,r.asLongLong());
                }
			}
			write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_OK);
		} catch(GetReplyException &e){
			ERROR("GetReplyException %s status: %d",e.what.c_str(),e.status);
			write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_ERR);
		} catch(ReplyTypeException &e){
			ERROR("ReplyTypeException %s type: %d",e.what.c_str(),e.type);
			write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_ERR);
		} catch(ReplyDataException &e){
			ERROR("ReplyDataException %s",e.what.c_str());
			write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_ERR);
		}
		get.clear();
		put.clear();
		filtered_put.clear();
		data_ready.set(false);
	}
}

void ResourceCache::on_stop(){
	tostop = true;
	data_ready.set(true);

	write_pool.stop(true);
	read_pool.stop(true);
}

void ResourceCache::registerReconnectCallback(RedisConnPool::cb_func *func,void *arg){
	write_pool.registerReconnectCallback(func,arg);
}

void ResourceCache::registerResourcesInitializedCallback(cb_func *func){
	resources_initialized_cb = func;
}

string ResourceCache::get_key(Resource &r){
	ostringstream ss;
	ss << "r:" << r.type << ":" << r.id;
	return ss.str();
}

bool ResourceCache::init_resources(bool initial){
	redisContext *write_ctx = NULL;
	redisReply *reply = NULL;
	list <int> desired_response;
	int node_id = AmConfig.node_id;

	try {
		write_ctx = write_pool.getConnection();
		while(write_ctx==NULL){
			if(!initial) {
				ERROR("get connection can't get connection from write redis pool");
				return false;
			}
			ERROR("get connection can't get connection from write redis pool. retry every 1s");
			sleep(1);
			if(tostop) {
				return false;
			}
			write_ctx = write_pool.getConnection();
		}

		queues_mutex.lock();

		put_resources_queue.clear();
		get_resources_queue.clear();


		redis::redisAppendCommand(write_ctx,"KEYS r:*");

		int state = redis::redisGetReply(write_ctx,(void **)&reply);
		if(state!=REDIS_OK)
			throw GetReplyException("KEYS redis::redisGetReply() != REDIS_OK",state);

        AmArg res;
        redisReply2Amarg(res, reply);
		if(!isArgArray(res)){
			if(redis::isReplyError(reply)) {
                redis::freeReplyObject(write_ctx, reply);
				throw ReplyDataException(redis::getReplyError(reply));
            }
			if(isArgUndef(res)){
				INFO("empty database. skip resources initialization");
				write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_OK);
				queues_mutex.unlock();
                redis::freeReplyObject(write_ctx, reply);
				return true;
			}
		}

        redis::freeReplyObject(write_ctx, reply);
		//iterate over keys and set their values to zero
		vector<string> commands;
		for(size_t i = 0;i < res.size(); i++){
			AmArg& r = res[i];
            char* cmd;
			formatCommand(&cmd,"HSET %s %d %d",(char*)r.asCStr(),node_id,0);
            commands.push_back(cmd);
            free(cmd);
		}
		res = runMultiCommand(write_ctx,commands, "SET");

		INFO("resources initialized");

		write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_OK);
		queues_mutex.unlock();

		if(resources_initialized_cb)
			resources_initialized_cb();

		return true;
	} catch(GetReplyException &e){
		ERROR("GetReplyException: %s, status: %d",e.what.c_str(),e.status);
	} catch(ReplyDataException &e){
		ERROR("ReplyDataException: %s",e.what.c_str());
	} catch(ReplyTypeException &e){
		ERROR("ReplyTypeException %s type: %d",e.what.c_str(),e.type);
	}

	write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_ERR);
	queues_mutex.unlock();
	return false;
}

void ResourceCache::pending_get(Resource &r){
	queues_mutex.lock();
		get_resources_queue.insert(get_resources_queue.begin(),r);
	queues_mutex.unlock();
}

void ResourceCache::pending_get_finish(){
	data_ready.set(true);
}

long int Reply2Int(AmArg& r) throw()
{
	long int ret = 0;
	char *s;
	if(isArgNumber(r))
        ret = r.asLongLong();
	else if(isArgUndef(r))//non existent key
        ret = 0;
    else if(isArgCStr(r)) {//string response
        s = (char*)r.asCStr();
        if(!str2long(s,ret)){
            ERROR("Reply2Int: conversion falied for: '%s'",s);
            throw ReplyDataException("invalid response from redis");
        }
    } else if(isArgArray(r)) { //we have array reply. return sum of all elements");
        for(size_t i=0; i < r.size(); i++)
            ret+=Reply2Int(r[i]);
    } else if(isArgStruct(r) && r.hasMember("error")) { 
        ERROR("reply error: '%s'",r["error"].asCStr());
        throw ReplyDataException("undesired reply");
    } else {
        throw ReplyTypeException("reply type not desired",r.getType());
    }

	return ret;
}

ResourceResponse ResourceCache::get(ResourceList &rl,
									ResourceList::iterator &resource)
{
	ResourceResponse ret = RES_ERR;
	resource = rl.begin();

	try {

		//preliminary resources availability check

		bool resources_available = true;
		list <int> desired_response;
		redisContext *redis_ctx = NULL;
		RedisConnPool *redis_pool = &read_pool;

		redis_ctx = redis_pool->getConnection();
		if(redis_ctx==NULL){
			throw ResourceCacheException("can't get connection from read redis pool",0);
		}

			//prepare request
        vector<string> commands;
		ResourceList::iterator rit = rl.begin();
		for(;rit!=rl.end();++rit){
			string key = get_key(*rit);
            char* cmd;
			formatCommand(&cmd, "HVALS %b",
                                    key.c_str(),key.size());
            commands.push_back(cmd);
            free(cmd);
		}

		try {
			//perform request
            AmArg res = runMultiCommand(redis_ctx, commands, "GET");
            if(res.size() != rl.size()) {
                DBG("GET reply->elements = %ld, desired size = %ld",
                    res.size(),rl.size());
                throw ReplyDataException("GET mismatch responses array size");
            }

            //resources availability checking cycle
            int check_state = CHECK_STATE_NORMAL;
            resource = rl.begin();
            for(size_t i = 0; i < res.size(); i++,++resource){
                long int now = Reply2Int(res[i]);
                Resource &res = *resource;

                if(CHECK_STATE_SKIP==check_state){
                    DBG("skip %d:%d intended for failover",res.type,res.id);
                    if(!res.failover_to_next) //last failover resource
                        check_state = CHECK_STATE_NORMAL;
                    continue;
                }

                DBG("check_resource %d:%d %ld/%d",
                    res.type,res.id,now,res.limit);

                //check limit
                if(now >= res.limit){
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
                    if(CHECK_STATE_FAILOVER==check_state){
                        DBG("failovered to resource %d:%d",res.type,res.id);
                        /*if(res.failover_to_next)	//skip if not last
                            check_state = CHECK_STATE_SKIP;*/
                    }
                    check_state = res.failover_to_next ?
                        CHECK_STATE_SKIP : CHECK_STATE_NORMAL;
                }
            }

			redis_pool->putConnection(redis_ctx,RedisConnPool::CONN_STATE_OK);

			//aquire resources if available

			if(!resources_available){
				DBG("resources unavailable");
				ret = RES_BUSY;
			} else {
				bool non_empty = false;
				for(ResourceList::iterator rit = rl.begin();rit!=rl.end();++rit){
					Resource &r = (*rit);
					if(!r.active || r.taken) continue;
					non_empty = true;
					pending_get(r);
					r.taken = true;
				}
				if(non_empty) pending_get_finish();
				ret = RES_SUCC;
			}
		} catch(GetReplyException &e){
			ERROR("GetReplyException: %s, status: %d",e.what.c_str(),e.status);
			redis_pool->putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
		} catch(ReplyTypeException &e){
			ERROR("ReplyTypeException: %s, type: %d",e.what.c_str(),e.type);
			redis_pool->putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
		} catch(ReplyDataException &e){
			ERROR("ReplyDataException: %s",e.what.c_str());
			redis_pool->putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
		}
	} catch(ResourceCacheException &e){
		ERROR("exception: %s %d",e.what.c_str(),e.code);
	}

	return ret;
}

void ResourceCache::put(ResourceList &rl){
	queues_mutex.lock();
		put_resources_queue.insert(
			put_resources_queue.begin(),
			rl.begin(), rl.end());
	queues_mutex.unlock();
	data_ready.set(true);
}

void ResourceCache::getResourceState(int type, int id, AmArg &ret){
	DBG("getResourceState(%d,%d,...)",type,id);

	redisReply *reply = NULL;
	redisContext *redis_ctx = NULL;
	list <int> d;

	ret.assertStruct();

	redis_ctx = read_pool.getConnection();
	if(redis_ctx==NULL){
		throw ResourceCacheException("can't get connection from read_pool",500);
	}

	if(type!=ANY_VALUE and id!=ANY_VALUE){
		//create fake resource
		Resource r;
		r.type = type;
		r.id = id;

		//prepare request
		string key = get_key(r);
		redis::redisAppendCommand(redis_ctx,"HGETALL %b",
			key.c_str(),key.size());

		int state = redis::redisGetReply(redis_ctx,(void **)&reply);

		if(state!=REDIS_OK || reply==NULL){
			read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
			throw ResourceCacheException("no reply from storage",500);
		}

		AmArg res;
        redisReply2Amarg(res, reply);
		if(!isArgArray(res)){
			redis::freeReplyObject(redis_ctx, reply);
			read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
			throw ResourceCacheException("undesired reply from storage",500);
		}

		if(res.size() == 0){
			redis::freeReplyObject(redis_ctx, reply);
			read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_OK);
			throw ResourceCacheException("unknown resource",404);
		}

		for(size_t i = 0; i < res.size(); i+=2){
			ret.push(int2str((unsigned int)Reply2Int(res[i])),	//node_id
					 AmArg(Reply2Int(res[i+1])));				//value
		}

		redis::freeReplyObject(redis_ctx, reply);
	} else { //if(type!=ANY_VALUE and id!=ANY_VALUE){
#define int2key(v) (v==ANY_VALUE) ? "*" : int2str(v)
		string key = int2key(type);
		key.append(":");
		key.append(int2key(id));
#undef int2key
		DBG("%s(): lookup of keys '%s'",FUNC_NAME,key.c_str());
		redis::redisAppendCommand(redis_ctx,"KEYS %s",key.c_str());

		int state = redis::redisGetReply(redis_ctx,(void **)&reply);
		if(state!=REDIS_OK || reply==NULL){
			read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
			throw ResourceCacheException("no reply from storage",500);
		}

		AmArg res;
        redisReply2Amarg(res, reply);
		if(!isArgArray(res)){
			if(isArgUndef(res)){
				redis::freeReplyObject(redis_ctx, reply);
				read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_OK);
				throw ResourceCacheException("no resources matched",404);
			}
			redis::freeReplyObject(redis_ctx, reply);
			read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
			throw ResourceCacheException("undesired reply from storage",500);
		}
		DBG("%s(): got %ld keys",FUNC_NAME,res.size());

		list<string> keys;
        vector<string> commands;
		for(size_t i = 0; i < res.size(); i++){
			AmArg& r = res[i];
            char* cmd;
			formatCommand(&cmd,"HGETALL %s",r.asCStr());
			keys.push_back(r.asCStr());
            commands.push_back(cmd);
            free(cmd);
		}
		try {
            res = runMultiCommand(redis_ctx, commands, "GET ALL");
        } catch(GetReplyException& ) {
            read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
            throw ResourceCacheException("no reply from storage",500);
        } catch(ReplyTypeException& ) {
            read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
            throw ResourceCacheException("undesired reply from storage",500);
        }

        list<string>::const_iterator k = keys.begin();
        for(size_t i = 0; i < res.size(); i++,k++) {
            AmArg& r = res[i];
            if(!isArgArray(r)){
                read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
                throw ResourceCacheException("undesired reply from storage",500);
            }
            ret.push(*k,AmArg());
            AmArg &q = ret[*k];
            for(size_t j = 0; j < r.size(); j+=2){
                try {
                    q.push(int2str((unsigned int)Reply2Int(r[j])),	//node_id
                            AmArg(Reply2Int(r[j+1])));				//value*/
                } catch(...){
                    read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
                    throw ResourceCacheException("can't parse response",500);
                }
            }
        }
	}
	read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_OK);
}

void ResourceCache::GetConfig(AmArg& ret){
	AmArg u;

	read_pool.GetConfig(u);
	ret.push("read_pool",u);

	u.clear();
	write_pool.GetConfig(u);
	ret.push("write_pool",u);
}
