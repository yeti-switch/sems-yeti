#include "ResourceCache.h"
#include "log.h"
#include "AmUtils.h"
#include <sstream>

#include "../yeti.h"

#define REDIS_STRING_ZERO "(null)"

#define CHECK_STATE_NORMAL 0
#define CHECK_STATE_FAILOVER 1
#define CHECK_STATE_SKIP 2

struct GetReplyException {
	string what;
	int status;
	GetReplyException(string w, int s): what(w), status(s) {}
};

struct ReplyTypeException {
	string what;
	int type;
	ReplyTypeException(string w, int t): what(w), type(t) {}
};

struct ReplyDataException {
	string what;
	ReplyDataException(string w): what(w) {}
};


static long int Reply2Int(redisReply *r){
	long int ret = 0;
	char *s;
	switch(r->type) {
		case REDIS_REPLY_INTEGER:	//integer response
			//DBG("Reply2Int: we have integer reply. simply assign it");
			ret = r->integer;
			break;
		case REDIS_REPLY_NIL:		//non existent key
			//DBG("Reply2Int: we have nil reply. consider it as 0");
			ret = 0;
			break;
		case REDIS_REPLY_STRING:	//string response
			//DBG("Reply2Int: we have string reply '%s'. trying convert it",r->str);
			s = r->str;
			if(!str2long(s,ret)){
				ERROR("Reply2Int: conversion falied for: '%s'",r->str);
				throw ReplyDataException("invalid response from redis");
			}
			break;
		case REDIS_REPLY_ARRAY:
			//DBG("Reply2Int: we have array reply. return sum of all elements");
			for(unsigned int i=0;i<r->elements;i++)
				ret+=Reply2Int(r->element[i]);
			break;
		case REDIS_REPLY_ERROR:
			ERROR("reply error: '%s'",r->str);
			throw ReplyDataException("undesired reply");
			break;
		default:
			throw ReplyTypeException("reply type not desired",r->type);
			break;
	}
	return ret;
}

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

void ResourceCache::run(){
	ResourceList put,get;
	ResourceList filtered_put;
	redisReply *reply;
	list <int> desired_response;
	redisContext *write_ctx;

	setThreadName("yeti-res-wr");

	Yeti::global_config &gc = Yeti::instance().config;

	read_pool.start();
	write_pool.start();

	if(!init_resources(true)){
		DBG("can't init resources. stop thread");
		return;
	}

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
				desired_response.clear();
				redisAppendCommand(write_ctx,"MULTI");
				desired_response.push_back(REDIS_REPLY_STATUS);
				for(ResourceList::iterator rit = get.begin();rit!=get.end();++rit){
					Resource &r = (*rit);
					string key = get_key(r);
					redisAppendCommand(write_ctx,"HINCRBY %b %d %d",
						key.c_str(),key.size(),
						gc.node_id,
						r.takes);
					desired_response.push_back(REDIS_REPLY_STATUS);
				}
				redisAppendCommand(write_ctx,"EXEC");
				desired_response.push_back(REDIS_REPLY_ARRAY);

				while(!desired_response.empty()){
					int desired = desired_response.front();
					desired_response.pop_front();
					int state = redisGetReply(write_ctx,(void **)&reply);
					if(state!=REDIS_OK)
						throw GetReplyException("HINCRBY redisGetReply() != REDIS_OK",state);
					if(reply==NULL)
						throw GetReplyException("HINCRBY reply == NULL",state);
					if(reply->type != desired){
						if(reply->type==REDIS_REPLY_ERROR){
							DBG("HINCRBY redis reply_error: %s",reply->str);
						}
						DBG("HINCRBY desired_reply: %d, reply: %d",desired,reply->type);
						throw ReplyTypeException("HINCRBY type not desired",reply->type);
					}
					if(reply->type==REDIS_REPLY_ARRAY){
						size_t n = reply->elements;
						if(n != get.size()){
							DBG("HINCRBY reply->elements = %ld, desired size = %ld",
								n,get.size());
							throw ReplyDataException("HINCRBY mismatch responses array size");
						}

						ResourceList::iterator it = get.begin();
						for(unsigned int i = 0;i<n;i++,++it){
							redisReply *r = reply->element[i];
							if(r->type!=REDIS_REPLY_INTEGER){
								if(r->type==REDIS_REPLY_ERROR)
									DBG("HINCRBY redis reply_error: %s",r->str);
								throw ReplyDataException("HINCRBY integer expected");
							}
							Resource &res = *it;
							DBG("get_resource %d:%d %d %lld",res.type,res.id,gc.node_id,r->integer);
						}
					}
					freeReplyObject(reply);
				}
			}

			if(filtered_put.size()){

				desired_response.clear();
				redisAppendCommand(write_ctx,"MULTI");
				desired_response.push_back(REDIS_REPLY_STATUS);

				ResourceList::iterator rit = filtered_put.begin();
				for(;rit!=filtered_put.end();++rit){
					Resource &r = (*rit);
					string key = get_key(r);
					redisAppendCommand(write_ctx,"HINCRBY %b %d %d",
						key.c_str(),key.size(),
						gc.node_id,
						-r.takes/*pass negative to increment*/);
					desired_response.push_back(REDIS_REPLY_STATUS);
				}

				redisAppendCommand(write_ctx,"EXEC");
				desired_response.push_back(REDIS_REPLY_ARRAY);

				//process replies
				while(!desired_response.empty()){
					int desired = desired_response.front();
					desired_response.pop_front();
					int state = redisGetReply(write_ctx,(void **)&reply);
					if(state!=REDIS_OK)
						throw GetReplyException("HDECRBY redisGetReply() != REDIS_OK",state);
					if(reply==NULL)
						throw GetReplyException("HDECRBY reply == NULL",state);
					if(reply->type != desired){
						if(reply->type==REDIS_REPLY_ERROR){
							DBG("redis reply_error: %s",reply->str);
						}
						DBG("HDECRBY desired_reply: %d, reply: %d",desired,reply->type);
						throw ReplyTypeException("HDECRBY type not desired",reply->type);
					}

					if(reply->type==REDIS_REPLY_ARRAY){ /* process EXEC here */
						redisReply *r;
						if(reply->elements != filtered_put.size())
							throw ReplyDataException("HDECRBY mismatch responses array size");
						ResourceList::iterator it = filtered_put.begin();
						for(unsigned int i = 0;i<reply->elements;i++,++it){
							r = reply->element[i];
							if(r->type!=REDIS_REPLY_INTEGER){
								DBG("HDECRBY r->type!=REDIS_REPLY_INTEGER, r->type = %d",
									r->type);
								throw ReplyDataException("HDECRBY integer expected");
							}
							Resource &res = *it;
							DBG("put_resource %d:%d %d %lld",res.type,res.id,gc.node_id,r->integer);
						}
					}
					freeReplyObject(reply);
				}
			}
			write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_OK);
		} catch(GetReplyException &e){
			ERROR("GetReplyException %s status: %d",e.what.c_str(),e.status);
			//freeReplyObject(reply);
			write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_ERR);
		} catch(ReplyTypeException &e){
			ERROR("ReplyTypeException %s type: %d",e.what.c_str(),e.type);
			freeReplyObject(reply);
			write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_ERR);
		} catch(ReplyDataException &e){
			ERROR("ReplyDataException %s",e.what.c_str());
			freeReplyObject(reply);
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

	write_pool.stop();
	read_pool.stop();
}

void ResourceCache::registerReconnectCallback(RedisConnPool::cb_func *func,void *arg){
	write_pool.registerReconnectCallback(func,arg);
}

void ResourceCache::registerResourcesInitializedCallback(cb_func *func){
	resources_initialized_cb = func;
}

string ResourceCache::get_key(Resource &r){
	ostringstream ss;
	ss << r.type << ":" << r.id;
	return ss.str();
}

bool ResourceCache::init_resources(bool initial){
	redisContext *write_ctx = NULL;
	redisReply *reply = NULL;
	list <int> desired_response;
	int node_id = Yeti::instance().config.node_id;

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


		redisAppendCommand(write_ctx,"KEYS *");

		int state = redisGetReply(write_ctx,(void **)&reply);
		if(state!=REDIS_OK)
			throw GetReplyException("KEYS redisGetReply() != REDIS_OK",state);

		if(reply->type != REDIS_REPLY_ARRAY){
			if(reply->type==REDIS_REPLY_ERROR)
				throw ReplyDataException(reply->str);
			if(reply->type==REDIS_REPLY_NIL){
				INFO("empty database. skip resources initialization");
				write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_OK);
				queues_mutex.unlock();
				return true;
			}
		}

		//iterate over keys and set their values to zero
		redisAppendCommand(write_ctx,"MULTI");
		desired_response.push_back(REDIS_REPLY_STATUS);
		for(unsigned int i = 0;i<reply->elements;i++){
			redisReply *r = reply->element[i];
			redisAppendCommand(write_ctx,"HSET %s %d %d",r->str,node_id,0);
			desired_response.push_back(REDIS_REPLY_STATUS);
		}
		redisAppendCommand(write_ctx,"EXEC");
		desired_response.push_back(REDIS_REPLY_ARRAY);

		freeReplyObject(reply);

		while(!desired_response.empty()){
			int desired = desired_response.front();
			desired_response.pop_front();
			state = redisGetReply(write_ctx,(void **)&reply);
			if(state!=REDIS_OK)
				throw GetReplyException("MULTI HSET redisGetReply() != REDIS_OK, state = %d",state);
			if(reply==NULL)
				throw GetReplyException("MULTI HSET reply == NULL",state);
			if(reply->type!=desired){
				throw ReplyTypeException("MULTI HSET type not desired",reply->type);
			}
			freeReplyObject(reply);
		}

		INFO("resources initialized");

		write_pool.putConnection(write_ctx,RedisConnPool::CONN_STATE_OK);
		queues_mutex.unlock();

		if(resources_initialized_cb)
			resources_initialized_cb();

		return true;
	} catch(GetReplyException &e){
		ERROR("GetReplyException: %s, status: %d",e.what.c_str(),e.status);
	} catch(ReplyDataException &e){
		freeReplyObject(reply);
		ERROR("ReplyDataException: %s",e.what.c_str());
	} catch(ReplyTypeException &e){
		freeReplyObject(reply);
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

ResourceResponse ResourceCache::get(ResourceList &rl,
									ResourceList::iterator &resource)
{
	ResourceResponse ret = RES_ERR;
	resource = rl.begin();

	try {

		//preliminary resources availability check

		bool resources_available = true;
		list <int> desired_response;
		redisReply *reply = NULL;
		redisContext *redis_ctx = NULL;
		RedisConnPool *redis_pool = &read_pool;

		redis_ctx = redis_pool->getConnection();
		if(redis_ctx==NULL){
			throw ResourceCacheException("can't get connection from read redis pool",0);
		}

			//prepare request
		redisAppendCommand(redis_ctx,"MULTI");
		desired_response.push_back(REDIS_REPLY_STATUS);

		ResourceList::iterator rit = rl.begin();
		for(;rit!=rl.end();++rit){
			string key = get_key(*rit);
			//redisAppendCommand(redis_ctx,"GET %b",
			redisAppendCommand(redis_ctx,"HVALS %b",
				key.c_str(),key.size());
			desired_response.push_back(REDIS_REPLY_STATUS);
		}

		redisAppendCommand(redis_ctx,"EXEC");
		desired_response.push_back(REDIS_REPLY_ARRAY);

			//perform request
		try {
			while(!desired_response.empty()){
				int desired = desired_response.front();
				desired_response.pop_front();

				int state = redisGetReply(redis_ctx,(void **)&reply);
				if(state!=REDIS_OK)
					throw GetReplyException("GET redisGetReply() != REDIS_OK",state);
				if(reply==NULL)
					throw GetReplyException("GET reply == NULL",state);
				if(reply->type != desired){
					if(reply->type==REDIS_REPLY_ERROR)
						throw ReplyDataException(reply->str);
					throw ReplyTypeException("GET type not desired",reply->type);
				}
				if(reply->type==REDIS_REPLY_ARRAY){ /* process EXEC here */
					size_t n = reply->elements;
					if(n != rl.size()){
						DBG("GET reply->elements = %ld, desired size = %ld",
							n,rl.size());
						throw ReplyDataException("GET mismatch responses array size");
					}

					//resources availability checking cycle
					int check_state = CHECK_STATE_NORMAL;
					resource = rl.begin();
					for(unsigned int i = 0;i<n;i++,++resource){
						long int now = Reply2Int(reply->element[i]);
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
				}
				freeReplyObject(reply);
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
			freeReplyObject(reply);
			redis_pool->putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
		} catch(ReplyDataException &e){
			ERROR("ReplyDataException: %s",e.what.c_str());
			freeReplyObject(reply);
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
		redisAppendCommand(redis_ctx,"HGETALL %b",
			key.c_str(),key.size());

		int state = redisGetReply(redis_ctx,(void **)&reply);

		if(state!=REDIS_OK || reply==NULL){
			read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
			throw ResourceCacheException("no reply from storage",500);
		}

		if(reply->type != REDIS_REPLY_ARRAY){
			freeReplyObject(reply);
			read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
			throw ResourceCacheException("undesired reply from storage",500);
		}

		size_t n = reply->elements;
		if(0==n){
			freeReplyObject(reply);
			read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_OK);
			throw ResourceCacheException("unknown resource",404);
		}

		for(unsigned int i = 0; i < n; i+=2){
			ret.push(int2str((unsigned int)Reply2Int(reply->element[i])),	//node_id
					 AmArg(Reply2Int(reply->element[i+1])));				//value
		}

		freeReplyObject(reply);
	} else { //if(type!=ANY_VALUE and id!=ANY_VALUE){
#define int2key(v) (v==ANY_VALUE) ? "*" : int2str(v)
		string key = int2key(type);
		key.append(":");
		key.append(int2key(id));
#undef int2key
		DBG("%s(): lookup of keys '%s'",FUNC_NAME,key.c_str());
		redisAppendCommand(redis_ctx,"KEYS %s",key.c_str());

		int state = redisGetReply(redis_ctx,(void **)&reply);
		if(state!=REDIS_OK || reply==NULL){
			read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
			throw ResourceCacheException("no reply from storage",500);
		}


		if(reply->type != REDIS_REPLY_ARRAY){
			if(reply->type==REDIS_REPLY_NIL){
				freeReplyObject(reply);
				read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_OK);
				throw ResourceCacheException("no resources matched",404);
			}
			freeReplyObject(reply);
			read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
			throw ResourceCacheException("undesired reply from storage",500);
		}
		DBG("%s(): got %ld keys",FUNC_NAME,reply->elements);

		list<string> keys;
		redisAppendCommand(redis_ctx,"MULTI");
		d.push_back(REDIS_REPLY_STATUS);
		for(unsigned int i = 0;i<reply->elements;i++){
			redisReply *r = reply->element[i];
			redisAppendCommand(redis_ctx,"HGETALL %s",r->str);
			keys.push_back(r->str);
			d.push_back(REDIS_REPLY_STATUS);
		}
		redisAppendCommand(redis_ctx,"EXEC");
		d.push_back(REDIS_REPLY_ARRAY);

		freeReplyObject(reply);

		while(!d.empty()){
			int desired = d.front();
			d.pop_front();
			state = redisGetReply(redis_ctx,(void **)&reply);
			if(state!=REDIS_OK || reply==NULL){
				read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
				throw ResourceCacheException("no reply from storage",500);
			}
			if(reply->type!=desired){
				freeReplyObject(reply);
				read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
				throw ResourceCacheException("undesired reply from storage",500);
			}
			if(reply->type == REDIS_REPLY_ARRAY){
				list<string>::const_iterator k = keys.begin();
				for(unsigned int i = 0; i < reply->elements; i++,k++){
					redisReply *r = reply->element[i];
					if(r->type!=REDIS_REPLY_ARRAY){
						freeReplyObject(reply);
						read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
						throw ResourceCacheException("undesired reply from storage",500);
					}
					ret.push(*k,AmArg());
					AmArg &q = ret[*k];
					for(unsigned int j = 0; j < r->elements; j+=2){
						try {
						q.push(int2str((unsigned int)Reply2Int(r->element[j])),	//node_id
							 AmArg(Reply2Int(r->element[j+1])));				//value*/
						} catch(...){
							freeReplyObject(reply);
							read_pool.putConnection(redis_ctx,RedisConnPool::CONN_STATE_ERR);
							throw ResourceCacheException("can't parse response",500);
						}
					}
				}
			}
			freeReplyObject(reply);
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
