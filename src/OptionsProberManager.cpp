#include "OptionsProberManager.h"

#include <pqxx/pqxx>
#include "AmLcConfig.h"
#include "AmSessionContainer.h"
#include "ampi/OptionsProberAPI.h"

int OptionsProberManager::configure(AmConfigReader &cfg, string &cfg_routing_schema)
{
    string prefix("master");
    dbc.cfg2dbcfg(cfg,prefix);
    db_routing_schema = cfg_routing_schema;

    AmArg options_probers;
    if(load_probers(options_probers)) {
        ERROR("failed to perform an initial load of options probers. possibly old database. ignore");
        return 0;
    }

    if(options_probers.size()) {
        if(!AmSessionContainer::instance()->postEvent(
            OPTIONS_PROBER_QUEUE,
            new OptionsProberCtlEvent(OptionsProberCtlEvent::Add, options_probers)))
        {
            ERROR("failed to send probes ctl event. check if options_prober module is loaded");
            return 1;
        }
    }

    return 0;
}

void OptionsProberManager::pqxx_row_to_amarg(const pqxx::row &r, AmArg &a)
{
    for(const auto &f: r) {
        if(f.is_null())
            continue;
        switch(f.type()) {
        case 21:
        case 23: 
            //integer
            a[f.name()] = f.as<int>(0);
            break;
        case 1043:
            //string
            a[f.name()] = f.c_str();
        case 1184:
            //skip timestamp fields
            break;
        default:
            DBG("field %s has uknown type oid %d. skip",f.name(), f.type());
        }
    }
}

int OptionsProberManager::load_probers(AmArg &probers, int prober_id)
{
    probers.assertArray();

    try {
        pqxx::connection c(dbc.conn_str());
        c.set_variable("search_path",db_routing_schema+", public");

        pqxx::nontransaction tnx(c);
        pqxx::result r;
        if(prober_id != -1) {
            r =  tnx.exec_params("SELECT * FROM load_sip_options_probers($1,$2)",
                AmConfig.node_id, prober_id); 
        } else {
            r =  tnx.exec_params("SELECT * FROM load_sip_options_probers($1)",
                AmConfig.node_id);
        }

        for(pqxx::row_size_type i = 0; i < r.size();++i) {
            probers.push(AmArg());
            pqxx_row_to_amarg(r[i], probers.back());
        }
        //DBG("probers: %s", AmArg::print(probers).data());

    } catch(const pqxx::pqxx_exception &e) {
        ERROR("pqxx_exception: %s ",e.base().what());
        return 1;
    }
    return 0;
}

int OptionsProberManager::reload_probers(int prober_id)
{
    AmArg probers;
    if(load_probers(probers, prober_id))
        return 1;

    if(prober_id==-1) {
        //flush all probers
        AmSessionContainer::instance()->postEvent(
            OPTIONS_PROBER_QUEUE,
            new OptionsProberCtlEvent(OptionsProberCtlEvent::Flush, AmArg()));
    } else {
        //remove prober by id
        AmArg p;
        p.push(prober_id);
        AmSessionContainer::instance()->postEvent(
            OPTIONS_PROBER_QUEUE,
            new OptionsProberCtlEvent(OptionsProberCtlEvent::Remove, p));
    }

    //add probes loaded from db
    if(probers.size()) {
        AmSessionContainer::instance()->postEvent(
            OPTIONS_PROBER_QUEUE,
            new OptionsProberCtlEvent(OptionsProberCtlEvent::Add, probers));
    }

    return 0;
}
