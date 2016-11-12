#ifndef RESOURCECONTROL_H
#define RESOURCECONTROL_H

#include "AmConfigReader.h"
#include "ResourceCache.h"
#include "AmArg.h"
#include <map>
#include "log.h"
#include "../db/DbConfig.h"

using namespace std;

#define ResourceAction_Reject 1
#define ResourceAction_NextRoute 2
#define ResourceAction_Accept 3

struct ResourceConfig {
	int id;
	string name;
	int reject_code;
	string reject_reason;
	enum ActionType {
		Reject = 0,
		NextRoute,
		Accept
	} action;
	string str_action;

	ResourceConfig(int i,string n, int c, string r,int a):
		id(i),
		name(n),
		reject_code(c),
		reject_reason(r)
	{
		set_action(a);
	}
	void set_action(int a);
	string print() const;
};

enum ResourceCtlResponse {
	RES_CTL_OK,
	RES_CTL_NEXT,
	RES_CTL_REJECT,
	RES_CTL_ERROR
};

class ResourceControl
{
	ResourceCache cache;
	map<int,ResourceConfig> type2cfg;
	AmMutex cfg_lock;
	DbConfig dbc;
	string db_schema;

	struct handlers_entry {
		ResourceList resources;
		string owner_tag;
		struct timeval created_at;
		bool valid;

		handlers_entry(const ResourceList &l,const string &tag)
			: resources(l), owner_tag(tag), valid(true)
		{
			gettimeofday(&created_at, NULL);
		}
		void invalidate() { valid = false; }
		bool is_valid() { return valid; }
		void info(AmArg &a, const struct timeval &now) const;
	};
	typedef map<string,handlers_entry> Handlers;
	typedef Handlers::const_iterator HandlersIt;

	void handler_info(const HandlersIt &i, const struct timeval &now, AmArg &a) const;

	Handlers handlers;
	AmMutex handlers_lock;
	AmCondition<bool> container_ready;

	void replace(string &s,Resource &r,ResourceConfig &rc);
	void replace(string& s, const string& from, const string& to);
	int load_resources_config();
	int reject_on_error;

	struct {
		unsigned int hits;
		unsigned int overloaded;
		unsigned int rejected;
		unsigned int nextroute;
		unsigned int errors;
		void clear(){
			hits = 0;
			overloaded = 0;
			rejected = 0;
			nextroute = 0;
			errors = 0;
		}
		void get(AmArg &arg){
			arg["hits"] = (long)hits;
			arg["overloaded"] = (long)overloaded;
			arg["rejected"] = (long)rejected;
			arg["nextroute"] = (long)nextroute;
			arg["errors"] = (long)errors;
		}
	} stat;

public:

	ResourceControl();

	int configure(AmConfigReader &cfg);
	void configure_db(AmConfigReader &cfg);
	void start();
	void stop();
	bool reload();
	bool invalidate_resources();
	void on_reconnect();
	void on_resources_initialized();

	ResourceCtlResponse get(ResourceList &rl,
							  string &handler,
							  const string &owner_tag,
							  int &reject_code,
							  string &reject_reason,
							  ResourceList::iterator &rli);

	//void put(ResourceList &rl);
	void put(const string &handler);

	void GetConfig(AmArg& ret,bool types_only = false);
	void clearStats();
	void getStats(AmArg &ret);
	void getResourceState(int type, int id, AmArg &ret);
	void showResources(AmArg &ret);
	void showResourceByHandler(const string &h, AmArg &ret);
	void showResourceByLocalTag(const string &tag, AmArg &ret);
	void showResourcesById(int id, AmArg &ret);
};

#endif // RESOURCECONTROL_H
