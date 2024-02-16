#include "ResourceControl.h"
#include "../yeti.h"
#include "AmUtils.h"
#include "AmSession.h"
#include "../db/DbHelpers.h"
#include "../cfg/yeti_opts.h"

//workaround for callback
static ResourceControl *_instance;

static void on_resources_initialized_static(bool is_error, const AmArg& result){
	_instance->on_resources_initialized();
}

void ResourceControl::handler_info(const HandlersIt &i, const struct timeval &now, AmArg &a) const
{
	a["handler"] = i->first;
	i->second.info(a, now);
}

void ResourceControl::handlers_entry::info(AmArg &a,const struct timeval &now) const
{
	a["onwer_tag"] = owner_tag;
	a["valid"] = valid;
	a["lifetime"] = now.tv_sec-created_at.tv_sec;
	AmArg &r = a["resources"];
	for(ResourceList::const_iterator j = resources.begin(); j!=resources.end();++j){
		r.push(j->print());
	}
}

void ResourceConfig::set_action(int a){
	switch(a){
	case ResourceAction_Reject:
		action = Reject;
		str_action = "Reject";
		break;
	case ResourceAction_NextRoute:
		action = NextRoute;
		str_action = "NextRoute";
		break;
	case ResourceAction_Accept:
		action = Accept;
		str_action = "Accept";
		break;
	default:
		DBG("invalid action type. use Reject instead");
		action = Reject;
	}
}

string ResourceConfig::print() const{
	ostringstream s;
	s << "id: " << id << ", ";
	s << "name: '" << name << "'', ";
	s << "internal_code_id: " << internal_code_id << ", ";
	s << "action: " << str_action;
	return s.str();
}

ResourceControl::ResourceControl():
	container_ready(false)
{
	_instance = this;
	stat.clear();
}

int ResourceControl::configure(cfg_t *confuse_cfg, AmConfigReader &cfg)
{
    cfg_t *resources_sec = cfg_getsec(confuse_cfg, section_name_resources);
    if(!resources_sec) {
        ERROR("missed '%s' section in module config", section_name_resources);
        return -1;
    }

	reject_on_error = cfg.getParameterInt("reject_on_cache_error",-1);
	if(reject_on_error == -1){
		ERROR("missed 'reject_on_error' parameter");
		return -1;
	}

	if(load_resources_config()) {
		ERROR("can't load resources config");
		return -1;
	}

	redis_conn.registerResourcesInitializedCallback(&on_resources_initialized_static);

	return redis_conn.configure(resources_sec, cfg);
}

void ResourceControl::start(){
//	DBG("%s()",FUNC_NAME);
    redis_conn.init();
	redis_conn.start();
}

void ResourceControl::stop(){
	redis_conn.stop(true);
}

bool ResourceControl::invalidate_resources(){
	bool ret = false;

	container_ready.set(false);

	handlers_lock.lock();

	INFO("invalidate_resources. we have %ld handlers to invalidate",
		handlers.size());

	for(Handlers::iterator i = handlers.begin();i!=handlers.end();++i)
		i->second.invalidate();
	ret = redis_conn.invalidate_resources_sync();
	handlers_lock.unlock();
	return ret;
}

void ResourceControl::replace(string& s, const string& from, const string& to){
	size_t pos = 0;
	while ((pos = s.find(from, pos)) != string::npos) {
		 s.replace(pos, from.length(), to);
		 pos += s.length();
	}
}

void ResourceControl::replace(string &s,Resource &r,ResourceConfig &rc){
	replace(s,"$id",int2str(r.id));
	replace(s,"$type",int2str(r.type));
	replace(s,"$takes",int2str(r.takes));
	replace(s,"$limit",int2str(r.limit));
	replace(s,"$name",rc.name);
}

int ResourceControl::load_resources_config()
{
	auto &sync_db = Yeti::instance().sync_db;

	if(sync_db.exec_query("SELECT * from load_resource_types()", "load_resource_types"))
		return 1;

	assertArgArray(sync_db.db_reply_result);
	int id;
	for(size_t i = 0; i < sync_db.db_reply_result.size(); i++) {
		AmArg &a = sync_db.db_reply_result.get(i);
		id = a["id"].asInt();
		type2cfg.try_emplace(
			id,
			id,
			a["name"].asCStr(),
			DbAmArg_hash_get_int(a, "internal_code_id", 0),
			DbAmArg_hash_get_int(a, "action_id", 0));
	}

	for(const auto &it: type2cfg) {
		DBG("resource cfg:     <%s>",it.second.print().c_str());
	}

	return 0;
}

void ResourceControl::on_resources_initialized(){
	DBG("resources reported to be intialized. mark container ready");
	container_ready.set(true);
}

ResourceCtlResponse ResourceControl::get(
	ResourceList &rl,
	string &handler,
	const string &owner_tag,
	ResourceConfig &resource_config,
	ResourceList::iterator &rli)
{
	if(rl.empty()){
		DBG("empty resources list. do nothing");
		return RES_CTL_OK;
	}
	stat.hits++;

	ResourceResponse ret;

	if(container_ready.get()){
		ret = redis_conn.get(rl,rli);
	} else {
		WARN("attempt to get resource from unready container");
		ret = RES_ERR;
	}

	/*for(ResourceList::const_iterator i = rl.begin();i!=rl.end();++i)
		DBG("ResourceControl::get() resource: <%s>",(*i).print().c_str());*/

	switch(ret){
		case RES_SUCC: {
			handler = AmSession::getNewId();
			handlers_lock.lock();
			handlers.emplace(handler,handlers_entry(rl,owner_tag));
			handlers_lock.unlock();
			DBG("ResourceControl::get() return resources handler '%s' for %p",
				handler.c_str(),&rl);
			//TODO: add to internal handlers list
			return RES_CTL_OK;
		} break;
		case RES_BUSY: {
			stat.overloaded++;
			map<int,ResourceConfig>::iterator ti = type2cfg.find(rli->type);
			if(ti==type2cfg.end()) {
				resource_config.internal_code_id = DC_RESOURCE_UNKNOWN_TYPE;
				/*resource_config.reject_code = 404;
				resource_config.reject_reason =
					"Resource with unknown type "+int2str(rli->type)+" overloaded";*/
				stat.rejected++;
				return RES_CTL_REJECT;
			} else {
				ResourceConfig &rc  = ti->second;
				DBG("overloaded resource %d:%d action: %s",rli->type,rli->id,rc.str_action.c_str());
				if(rc.action==ResourceConfig::Accept){
					return RES_CTL_OK;
				} else { /* reject or choose next */
					resource_config = rc;
					ResourceConfig::ActionType a = rc.action;

					if(a==ResourceConfig::NextRoute){
						stat.nextroute++;
						return RES_CTL_NEXT;
					} else {
						stat.rejected++;
						return RES_CTL_REJECT;
					}
				}
			}
		} break;
		case RES_ERR: {
			stat.errors++;
			ERROR("cache error reject_on_error = %d",reject_on_error);
			if(reject_on_error) {
				resource_config.internal_code_id = DC_RESOURCE_CACHE_ERROR;
				return RES_CTL_ERROR;
			}
			return RES_CTL_OK;
		} break;
	}
	return RES_CTL_OK;
}

//void ResourceControl::put(ResourceList &rl){
void ResourceControl::put(const string &handler){

	DBG("ResourceControl::put(%s)",handler.c_str());

	if(handler.empty()){
		DBG("ResourceControl::put() empty handler");
		return;
	}

	handlers_lock.lock();
	Handlers::iterator h = handlers.find(handler);
	if(h==handlers.end()){
		handlers_lock.unlock();
		DBG("ResourceControl::put(%s) attempt to free resources using not existent handler",
			 handler.c_str());
		return;
	}

	//!TODO: validate handler. remove if found but invalid.
	handlers_entry &e = h->second;

	if(!e.is_valid()){
		DBG("ResourceControl::put(%s) invalid handler. remove it",
			handler.c_str());
		handlers.erase(h);
		handlers_lock.unlock();
		return;
	}

	if(!e.resources.empty()){
		redis_conn.put(e.resources);
	} else {
		DBG("ResourceControl::put(%p) empty resources list",&e.resources);
	}

	handlers.erase(h);
	handlers_lock.unlock();
}

void ResourceControl::GetConfig(AmArg& ret,bool types_only){
	DBG("types_only = %d, size = %ld",types_only,type2cfg.size());

	if(types_only) {
		for(map<int,ResourceConfig>::const_iterator it = type2cfg.begin();
			it!=type2cfg.end();++it)
		{
			string key = int2str(it->first);

			ret.push(key,AmArg());

			AmArg &p = ret[key];
			const ResourceConfig &c = it->second;
			p["name"] =  c.name;
			p["internal_code_id"] = c.internal_code_id;
			p["action"] = c.str_action;
		}
		return;
	}

	ret.push("cache",AmArg());
	AmArg &u = ret["cache"];
	redis_conn.get_config(u);
}

void ResourceControl::clearStats(){
	stat.clear();
}

void ResourceControl::getStats(AmArg &ret){
	stat.get(ret);
}

bool ResourceControl::getResourceState(const string& connection_id,
                                      const AmArg& request_id,
                                      const AmArg& params){
	int type, id;

	if(params.size()<2) {
		throw AmSession::Exception(500,"specify type and id of the resource");
	}
	params.assertArrayFmt("ss");
	if(!str2int(params.get(0).asCStr(),type)){
		throw AmSession::Exception(500,"invalid resource type");
	}
	if(!str2int(params.get(1).asCStr(),id)){
		throw AmSession::Exception(500,"invalid resource id");
	}
	if(type!=ANY_VALUE){
		if(type2cfg.find(type)==type2cfg.end()){
			throw AmSession::Exception(500, "unknown resource type");
		}
	}
	return redis_conn.get_resource_state(connection_id,request_id,params);
}

void ResourceControl::showResources(AmArg &ret){
	struct timeval now;
	handlers_lock.lock();
	gettimeofday(&now,NULL);
	for(HandlersIt i = handlers.begin();i!=handlers.end();++i){
		//const handlers_entry &e = i->second;
		ret.push(AmArg());
		handler_info(i,now,ret.back());
	}
	handlers_lock.unlock();
}

void ResourceControl::showResourceByHandler(const string &h, AmArg &ret){
	handlers_lock.lock();
	HandlersIt i = handlers.find(h);
	if(i==handlers.end()){
		handlers_lock.unlock();
		throw AmSession::Exception(500,"no such handler");
	}

	struct timeval now;
	gettimeofday(&now,NULL);
	handler_info(i,now,ret);

	handlers_lock.unlock();
}

void ResourceControl::showResourceByLocalTag(const string &tag, AmArg &ret){
	handlers_lock.lock();

	HandlersIt i = handlers.begin();
	for(;i!=handlers.end();++i){
		const handlers_entry &e = i->second;
		if (e.owner_tag.empty()) continue;
		if(e.owner_tag==tag) break;
	}
	if(i==handlers.end()){
		handlers_lock.unlock();
		throw AmSession::Exception(500,"no such handler");
	}

	struct timeval now;
	gettimeofday(&now,NULL);
	handler_info(i,now,ret);

	handlers_lock.unlock();
}

void ResourceControl::showResourcesById(int id, AmArg &ret){
	struct timeval now;

	handlers_lock.lock();

	ret.assertArray();
	gettimeofday(&now,NULL);

	HandlersIt i = handlers.begin();
	for(;i!=handlers.end();++i){
		const handlers_entry &e = i->second;
		ResourceList::const_iterator j = e.resources.begin();
		for(;j!=e.resources.end();j++){
			const Resource &r = *j;
			if(r.id==id){
				ret.push(AmArg());
				handler_info(i,now,ret.back());
				break; //loop over resources
			}
		}
	}

	handlers_lock.unlock();
}
