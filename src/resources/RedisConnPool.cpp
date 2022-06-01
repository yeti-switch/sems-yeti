#include "signal.h"

#include "RedisConnPool.h"
#include "log.h"
#include "AmUtils.h"
#include "exception"
#include "../alarms.h"

#define REDIS_CONN_TIMEOUT 5

RedisConnPool::RedisConnPool():
	tostop(false),
	failed_ready(true),
	active_ready(false),
	failed_count(0),
	reconnect_cb(NULL),
	reconnect_cb_arg(NULL)
{

}

int RedisConnPool::configure(const AmConfigReader &cfg,string name, bool is_readonly){
	pool_name = name;
	readonly = is_readonly;

	pool_size= cfg.getParameterInt(name+"_redis_size",1);

	active_timeout = cfg.getParameterInt(name+"_redis_timeout");
	if(!active_timeout){
		ERROR("no timeout for %s redis",name.c_str());
		return -1;
	}
	if(active_timeout<10 || active_timeout > 5e3){
		ERROR("timeout value must be between 10-5000 msec for %s redis",name.c_str());
		return -1;
	}
	return cfg2RedisCfg(cfg,_cfg,pool_name);
}

void RedisConnPool::registerReconnectCallback(cb_func *func,void *arg){
	reconnect_cb = func;
	reconnect_cb_arg = arg;
}

void RedisConnPool::setPoolSize(unsigned int poolsize){
	pool_size = poolsize;
}

void RedisConnPool::run(){
	redisContext *ctx = NULL;
	list<redisContext *> c;

//	DBG("%s()",FUNC_NAME);
	setThreadName("yeti-redis-cp");

	conn_mtx.lock();
		unsigned int active_count = active_ctxs.size();
		while(active_count < pool_size){
			timeval timeout = { REDIS_CONN_TIMEOUT, 0 };
			if(_cfg.socket.empty()){
				ctx = redis::redisConnectWithTimeout(_cfg.server.c_str(),_cfg.port,timeout);
			} else {
				ctx = redis::redisConnectUnixWithTimeout(_cfg.socket.c_str(),timeout);
			}
			if(ctx != NULL && redis::redisGetErrorNumber(ctx)){
				redis::redisFree(ctx);
				if(_cfg.socket.empty()){
					ERROR("[%p] failed conn for %s redis pool <host = %s:%d>",
						  this,
						pool_name.c_str(),
						_cfg.server.c_str(),
						_cfg.port);
				} else {
					ERROR("[%p] failed conn for %s redis pool <socket = %s>",
						  this,
						pool_name.c_str(),
						_cfg.socket.c_str());
				}
				kill(getpid(),SIGTERM); //commit suicide
				tostop = true;
				break;
			} else {
				active_ctxs.push_back(ctx);
				active_count++;
			}
		}
	conn_mtx.unlock();

	while(!tostop){
//		DBG("failed_ready.wait_for()");
		failed_ready.wait_for();
		if(tostop) break;

		conn_mtx.lock();
			c.swap(failed_ctxs);
		conn_mtx.unlock();

		if(c.empty()){
			failed_ready.set(false);
			continue;
		}

		while(!c.empty()){
			if(tostop)
				break;
			ctx = c.front();
			c.pop_front();
			if(reconnect(ctx)){
				conn_mtx.lock();
					active_ctxs.push_back(ctx);
					failed_count--;
				conn_mtx.unlock();
				CLEAR_ALARM(readonly?alarms::REDIS_READ_CONN:alarms::REDIS_WRITE_CONN);
				active_ready.set(true);
			} else {
				c.push_back(ctx);
				DBG("[%p] can't reconnect sleep %us",this,5);
				sleep(5);
			}
		}
		//all failed connections is reconnected
		on_reconnect();

		conn_mtx.lock();
			failed_ready.set(failed_count>0);
		conn_mtx.unlock();
	}
}

void RedisConnPool::on_stop(){
	redisContext *ctx;

//	DBG("%s()",FUNC_NAME);

	tostop = true;
	failed_ready.set(true);

	conn_mtx.lock();
		while(!active_ctxs.empty()){
			ctx = active_ctxs.front();
			active_ctxs.pop_front();
			redis::redisFree(ctx);
		}
	conn_mtx.unlock();

	conn_mtx.lock();
		while(!failed_ctxs.empty()){
			ctx = failed_ctxs.front();
			failed_ctxs.pop_front();
			redis::redisFree(ctx);
		}
	conn_mtx.unlock();

//	DBG("%s() finished",FUNC_NAME);
}

void RedisConnPool::on_reconnect(){
	if(reconnect_cb){
		DBG("RedisConnPool::on_reconnect() have reconnect call back function. call it");
		(*reconnect_cb)(reconnect_cb_arg);
	}
}

redisContext *RedisConnPool::getConnection(unsigned int timeout){
	redisContext *ctx = NULL;


	//DBG("%s()",FUNC_NAME);

	timeout = timeout > 0 ? timeout : active_timeout;

	while(ctx==NULL){

		conn_mtx.lock();
		if(active_ctxs.size()){
			ctx = active_ctxs.front();
			active_ctxs.pop_front();
			active_ready.set(!active_ctxs.empty());
		}
		conn_mtx.unlock();

		if(ctx==NULL){
			conn_mtx.lock();
			bool all_failed = pool_size == failed_count;
			conn_mtx.unlock();
			if (all_failed){
				ERROR("all connections failed");
				break;
			}

			if(!active_ready.wait_for_to(timeout)){
				DBG("timeout waiting for an active connection (waited %ums)",timeout);
				break;
			}
		} else {
			//DBG("got active connection [%p]",ctx);
		}
	}
	//DBG("%s() = %p",FUNC_NAME,ctx);
	return ctx;
}

void RedisConnPool::putConnection(redisContext *ctx,ConnReturnState state){
	//DBG("RedisConnPool::%s(%p,%d)",FUNC_NAME,ctx,state);

	if(state==CONN_STATE_OK){
		conn_mtx.lock();
			active_ctxs.push_back(ctx);
		conn_mtx.unlock();
		return;
	}
	if(state==CONN_STATE_ERR){
		conn_mtx.lock();
			failed_ctxs.push_back(ctx);
			failed_count++;
		conn_mtx.unlock();
		RAISE_ALARM(readonly?alarms::REDIS_READ_CONN:alarms::REDIS_WRITE_CONN);
		failed_ready.set(true);
		return;
	}
}

int RedisConnPool::cfg2RedisCfg(const AmConfigReader &cfg, RedisCfg &rcfg,string prefix){
//	DBG("%s()",FUNC_NAME);

	rcfg.socket = cfg.getParameter(prefix+"_redis_socket");
	if(!rcfg.socket.empty()){
		return 0;
	}

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
	return 0;
}

bool RedisConnPool::reconnect(redisContext *&ctx){
	DBG("[%p] %s(%p)",this,FUNC_NAME,ctx);

	if(ctx!=NULL){
		redis::redisFree(ctx);
		ctx = NULL;
	}

	timeval timeout = { REDIS_CONN_TIMEOUT, 0 };
	if(_cfg.socket.empty()){
		ctx = redis::redisConnectWithTimeout(_cfg.server.c_str(),_cfg.port,timeout);
	} else {
		ctx = redis::redisConnectUnixWithTimeout(_cfg.socket.c_str(),timeout);
	}
	if (ctx != NULL && redis::redisGetErrorNumber(ctx)) {
		ERROR("[%p] %s() can't connect: %d <%s>",this,FUNC_NAME,redis::redisGetErrorNumber(ctx),redis::redisGetError(ctx));
		redis::redisFree(ctx);
		ctx = NULL;
		return false;
	}
	return true;
}

void RedisConnPool::GetConfig(AmArg& ret){
	ret["pool_size"] = (int)pool_size;
	if(_cfg.socket.empty()){
		ret["connection"] = _cfg.server+":"+int2str(_cfg.port);
	} else {
		ret["connection"] = _cfg.socket;
	}
}

