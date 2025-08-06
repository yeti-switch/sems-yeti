#include "ResourceControl.h"
#include "../yeti.h"
#include "AmUtils.h"
#include "AmSession.h"
#include "../db/DbHelpers.h"
#include "../cfg/yeti_opts.h"

void ResourceControl::handler_info(const HandlersIt &i, const struct timeval &now, AmArg &a) const
{
    a["handler"] = i->first;
    i->second.info(a, now);
}

void ResourceControl::handlers_entry::info(AmArg &a, const struct timeval &now) const
{
    a["onwer_tag"] = owner_tag;
    a["valid"]     = valid;
    a["lifetime"]  = now.tv_sec - created_at.tv_sec;

    AmArg &r = a["resources"];
    for (ResourceList::const_iterator j = resources.begin(); j != resources.end(); ++j) {
        r.push(j->print());
    }
}

void ResourceConfig::set_action(int a)
{
    switch (a) {
    case ResourceAction_Reject:
        action     = Reject;
        str_action = "Reject";
        break;
    case ResourceAction_NextRoute:
        action     = NextRoute;
        str_action = "NextRoute";
        break;
    case ResourceAction_Accept:
        action     = Accept;
        str_action = "Accept";
        break;
    default: DBG("invalid action type. use Reject instead"); action = Reject;
    }
}

string ResourceConfig::print() const
{
    ostringstream s;
    s << "id: " << id << ", ";
    s << "name: '" << name << "'', ";
    s << "internal_code_id: " << internal_code_id << ", ";
    s << "action: " << str_action;
    return s.str();
}

ResourceControl::ResourceControl()
    : container_ready(false)
{
    stat.clear();
}

int ResourceControl::configure(cfg_t *confuse_cfg, AmConfigReader &cfg)
{
    cfg_t *resources_sec = cfg_getsec(confuse_cfg, section_name_resources);
    if (!resources_sec) {
        ERROR("missed '%s' section in module config", section_name_resources);
        return -1;
    }

    reject_on_error = cfg_getbool(resources_sec, opt_resources_reject_on_error);

    if (load_resources_config()) {
        ERROR("can't load resources config");
        return -1;
    }

    redis_conn.registerResourcesInitializedCallback(std::bind(&ResourceControl::on_resources_initialized, this));

    redis_conn.registerDisconnectCallback(std::bind(&ResourceControl::on_resources_disconnected, this));

    return redis_conn.configure(resources_sec);
}

void ResourceControl::start()
{
    redis_conn.init();
    redis_conn.start();
}

void ResourceControl::stop()
{
    redis_conn.stop(true);
}

void ResourceControl::invalidate_resources()
{
    AmLock lk(handlers_mutex);

    container_ready.set(false);

    INFO("invalidate %ld handlers. mark container unready", handlers.size());

    for (auto &h : handlers)
        h.second.invalidate();
}

bool ResourceControl::invalidate_resources_rpc()
{
    invalidate_resources();
    return redis_conn.invalidate_resources_sync();
}

void ResourceControl::replace(string &s, const string &from, const string &to)
{
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != string::npos) {
        s.replace(pos, from.length(), to);
        pos += s.length();
    }
}

void ResourceControl::replace(string &s, Resource &r, const ResourceConfig &rc)
{
    replace(s, "$id", r.id);
    replace(s, "$type", int2str(r.type));
    replace(s, "$takes", int2str(r.takes));
    replace(s, "$limit", int2str(r.limit));
    replace(s, "$name", rc.name);
}

int ResourceControl::load_resources_config()
{
    auto &sync_db = Yeti::instance().sync_db;

    if (sync_db.exec_query("SELECT * FROM load_resource_types()", "load_resource_types"))
        return 1;

    assertArgArray(sync_db.db_reply_result);
    for (size_t i = 0; i < sync_db.db_reply_result.size(); i++) {
        AmArg &a  = sync_db.db_reply_result.get(i);
        auto   id = a["id"].asInt();
        type2cfg.try_emplace(id, id, a["name"].asCStr(), DbAmArg_hash_get_int(a, "internal_code_id", 0),
                             DbAmArg_hash_get_int(a, "action_id", 0),
                             DbAmArg_hash_get_bool(a, "rate_limit", false) ? ResourceConfig::ResRateLimit
                                                                           : ResourceConfig::ResLimit);
    }

    for (const auto &it : type2cfg) {
        DBG("resource cfg:     <%s>", it.second.print().c_str());
    }

    return 0;
}

void ResourceControl::on_resources_initialized()
{
    INFO("resources reported to be intialized. mark container ready");
    container_ready.set(true);
}

void ResourceControl::on_resources_disconnected()
{
    invalidate_resources();
}

void ResourceControl::eval_resources(ResourceList &rl) const
{
    for (auto &r : rl) {
        auto it = type2cfg.find(r.type);
        if (it != type2cfg.end() && it->second.type == ResourceConfig::ResRateLimit) {
            r.rate_limit = true;
        }
    }
}

ResourceCtlResponse ResourceControl::get(ResourceList &rl, string &handler, const string &owner_tag,
                                         ResourceConfig &resource_config, ResourceList::iterator &rli)
{
    if (rl.empty()) {
        DBG("empty resources list. do nothing");
        return RES_CTL_OK;
    }
    stat.hits++;

    ResourceResponse ret;

    if (container_ready.get()) {
        ret = redis_conn.get(owner_tag, rl, rli);
    } else {
        WARN("%s: attempt to get resource from the unready container", owner_tag.data());
        ret = RES_ERR;
    }

    /*for(ResourceList::const_iterator i = rl.begin();i!=rl.end();++i)
        DBG("ResourceControl::get() resource: <%s>",(*i).print().c_str());*/

    switch (ret) {
    case RES_SUCC:
    {
        handler = AmSession::getNewId();
        {
            AmLock lk(handlers_mutex);
            handlers.emplace(handler, handlers_entry(rl, owner_tag));
        }
        DBG("ResourceControl::get() return resources handler '%s' for %p", handler.c_str(), &rl);
        // TODO: add to internal handlers list
        return RES_CTL_OK;
    } break;
    case RES_BUSY:
    {
        stat.overloaded++;
        map<int, ResourceConfig>::iterator ti = type2cfg.find(rli->type);
        if (ti == type2cfg.end()) {
            resource_config.internal_code_id = DC_RESOURCE_UNKNOWN_TYPE;
            /*resource_config.reject_code = 404;
            resource_config.reject_reason =
                "Resource with unknown type "+int2str(rli->type)+" overloaded";*/
            stat.rejected++;
            return RES_CTL_REJECT;
        } else {
            const ResourceConfig &rc = ti->second;
            DBG("overloaded resource %d:%s action: %s", rli->type, rli->id.data(), rc.str_action.c_str());
            if (rc.action == ResourceConfig::Accept) {
                return RES_CTL_OK;
            } else { /* reject or choose next */
                resource_config              = rc;
                ResourceConfig::ActionType a = rc.action;

                if (a == ResourceConfig::NextRoute) {
                    stat.nextroute++;
                    return RES_CTL_NEXT;
                } else {
                    stat.rejected++;
                    return RES_CTL_REJECT;
                }
            }
        }
    } break;
    case RES_ERR:
    {
        stat.errors++;
        if (reject_on_error) {
            ERROR("%s: reject resource with code: %d", owner_tag.data(), DC_RESOURCE_CACHE_ERROR);
            resource_config.internal_code_id = DC_RESOURCE_CACHE_ERROR;
            return RES_CTL_ERROR;
        }
        return RES_CTL_OK;
    } break;
    }
    return RES_CTL_OK;
}

void ResourceControl::put(const string &handler)
{
    if (handler.empty()) {
        return;
    }

    DBG3("ResourceControl::put(%s)", handler.c_str());

    std::optional<handlers_entry> handler_data;
    {
        AmLock lk(handlers_mutex);

        Handlers::iterator h = handlers.find(handler);
        if (h == handlers.end()) {
            DBG("ResourceControl::put(%s) attempt to free resources using not existent handler", handler.c_str());
            return;
        }

        handlers_entry &e = h->second;

        if (!e.is_valid()) {
            DBG("ResourceControl::put(%s) invalid handler. remove it", handler.c_str());
            handlers.erase(h);
            return;
        }

        if (e.resources.empty()) {
            DBG3("ResourceControl::put(%p) empty resources list", &e.resources);
            handlers.erase(h);
            return;
        }

        handler_data = std::move(e);
        handlers.erase(h);
    }

    redis_conn.put(handler_data.value().owner_tag, handler_data.value().resources);
}

void ResourceControl::GetConfig(AmArg &ret, bool types_only)
{
    DBG3("types_only = %d, size = %ld", types_only, type2cfg.size());

    if (types_only) {
        for (map<int, ResourceConfig>::const_iterator it = type2cfg.begin(); it != type2cfg.end(); ++it) {
            string key = int2str(it->first);

            ret.push(key, AmArg());

            AmArg                &p = ret[key];
            const ResourceConfig &c = it->second;
            p["name"]               = c.name;
            p["internal_code_id"]   = c.internal_code_id;
            p["action"]             = c.str_action;
            p["rate_limit"]         = c.type == ResourceConfig::ResRateLimit;
        }
        return;
    }

    ret.push("cache", AmArg());
    AmArg &u = ret["cache"];
    redis_conn.get_config(u);
}

void ResourceControl::clearStats()
{
    stat.clear();
}

void ResourceControl::getStats(AmArg &ret)
{
    stat.get(ret);
}

bool ResourceControl::getResourceState(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    int type, id;

    if (params.size() < 2) {
        throw AmSession::Exception(500, "specify type and id of the resource");
    }

    params.assertArrayFmt("ss");
    if (!str2int(params.get(0).asCStr(), type)) {
        throw AmSession::Exception(500, "invalid resource type");
    }

    if (!str2int(params.get(1).asCStr(), id)) {
        throw AmSession::Exception(500, "invalid resource id");
    }

    if (type != ANY_VALUE) {
        if (type2cfg.find(type) == type2cfg.end()) {
            throw AmSession::Exception(500, "unknown resource type");
        }
    }

    return redis_conn.get_resource_state(connection_id, request_id, params);
}

void ResourceControl::showResources(AmArg &ret)
{
    struct timeval now;
    AmLock         lk(handlers_mutex);
    gettimeofday(&now, NULL);
    for (HandlersIt i = handlers.begin(); i != handlers.end(); ++i) {
        // const handlers_entry &e = i->second;
        ret.push(AmArg());
        handler_info(i, now, ret.back());
    }
}

void ResourceControl::showResourceByHandler(const string &h, AmArg &ret)
{
    AmLock     lk(handlers_mutex);
    HandlersIt i = handlers.find(h);
    if (i == handlers.end()) {
        throw AmSession::Exception(500, "no such handler");
    }

    struct timeval now;
    gettimeofday(&now, NULL);
    handler_info(i, now, ret);
}

void ResourceControl::showResourceByLocalTag(const string &tag, AmArg &ret)
{
    AmLock lk(handlers_mutex);

    HandlersIt i = handlers.begin();
    for (; i != handlers.end(); ++i) {
        const handlers_entry &e = i->second;
        if (e.owner_tag.empty())
            continue;
        if (e.owner_tag == tag)
            break;
    }

    if (i == handlers.end()) {
        throw AmSession::Exception(500, "no such handler");
    }

    struct timeval now;
    gettimeofday(&now, NULL);
    handler_info(i, now, ret);
}

void ResourceControl::showResourcesById(int id, AmArg &ret)
{
    struct timeval now;

    AmLock lk(handlers_mutex);

    ret.assertArray();
    gettimeofday(&now, NULL);

    HandlersIt i = handlers.begin();
    for (; i != handlers.end(); ++i) {
        const handlers_entry        &e = i->second;
        ResourceList::const_iterator j = e.resources.begin();
        for (; j != e.resources.end(); --j) {
            const Resource &r = *j;
            if (r.id == id) {
                ret.push(AmArg());
                handler_info(i, now, ret.back());
                break; // loop over resources
            }
        }
    }
}
