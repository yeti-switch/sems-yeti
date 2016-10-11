#ifndef RADIUSCACHE_H
#define RADIUSCACHE_H

#include "AmConfigReader.h"
#include "AmThread.h"
#include "AmArg.h"
#include "hiredis/hiredis.h"
#include <list>

using namespace std;

struct RedisCfg {
	short port;
	string server;
	string socket;
};

class RedisConnPool : public
	AmThread
{
	list<redisContext *>active_ctxs;
	list<redisContext *>failed_ctxs;
	unsigned int active_timeout;
	AmMutex conn_mtx;
	AmCondition <bool>failed_ready;
	AmCondition <bool>active_ready;
	bool tostop;
	bool readonly;

	unsigned int pool_size;
	unsigned int failed_count;
	string pool_name;

	RedisCfg _cfg;

	int cfg2RedisCfg(const AmConfigReader &cfg, RedisCfg &rcfg,string prefix);
	bool reconnect(redisContext *&ctx);
public:
	enum ConnReturnState {
		CONN_STATE_OK,
		CONN_STATE_ERR
	};

	typedef void cb_func(void *);

	cb_func *reconnect_cb;
	void *reconnect_cb_arg;
	void registerReconnectCallback(cb_func *func,void *arg);
	void setPoolSize(unsigned int poolsize);

	RedisConnPool();
	int configure(const AmConfigReader &cfg,string name,bool is_readonly);
	void run();
	void on_stop();

	void on_reconnect();

	redisContext *getConnection(unsigned int timeout = 0);
	void putConnection(redisContext *,ConnReturnState state);

	void GetConfig(AmArg& ret);
};

#endif // RADIUSCACHE_H
