#include "cfg_helpers.h"

bool add2hash(
    cfg_t *c,
    std::string key,std::string cfg_key,
    AmConfigReader &out)
{
    cfg_opt_t *opt = cfg_getopt(c,cfg_key.c_str());
    if(!opt || !opt->nvalues) return false;

    //setParameter
    switch(opt->type){
    case CFGT_INT:
        if(opt->flags&CFGF_LIST)
            ERROR("list of integers is unsupported. assign first value");
        out.setParameter(key, long2str(cfg_getint(c,cfg_key.c_str())));
        break;
    case CFGT_STR:
        if(opt->flags&CFGF_LIST){
            std::string s;
            for(int i = 0; i < cfg_size(c, cfg_key.c_str()); i++){
                if(!s.empty()) s.append(",");
                s.append(cfg_getnstr(c, cfg_key.c_str(), i));
            }
            out.setParameter(key, s);
        } else {
            out.setParameter(key, cfg_getstr(c,cfg_key.c_str()));
        }
        break;
    case CFGT_BOOL:
        if(opt->flags&CFGF_LIST)
            ERROR("list of booleans is unsupported. assign first value");
        out.setParameter(key, int2str(cfg_getbool(c,cfg_key.c_str())));
        break;
    default:
        ERROR("uknown option type: %d for key: '%s'",
            opt->type,cfg_key.c_str());
    }
    return true;
}

void apply_db_cfg(
    cfg_t *c,std::string prefix,
    AmConfigReader &out)
{
    add2hash(c,prefix+"host","host",out);
    add2hash(c,prefix+"port","port",out);
    add2hash(c,prefix+"name","name",out);
    add2hash(c,prefix+"user","user",out);
    add2hash(c,prefix+"pass","pass",out);
    add2hash(c,prefix+"connect_timeout","connect_timeout",out);
}

void apply_pool_cfg(
    cfg_t *c,std::string prefix,
    AmConfigReader &out)
{
    //apply_db_opts
    apply_db_cfg(c,prefix,out);
    //apply pool-specific opts
    add2hash(c,prefix+"pool_size","size",out);
    add2hash(c,prefix+"check_interval","check_interval",out);
    add2hash(c,prefix+"max_exceptions","max_exceptions",out);
    add2hash(c,prefix+"statement_timeout","statement_timeout",out);
}

void apply_redis_pool_cfg(
    cfg_t *c,std::string prefix,
    AmConfigReader &out)
{
    add2hash(c,prefix+"socket","socket",out);
    add2hash(c,prefix+"host","host",out);
    add2hash(c,prefix+"port","port",out);
    add2hash(c,prefix+"size","size",out);
    add2hash(c,prefix+"timeout","timeout",out);
}
