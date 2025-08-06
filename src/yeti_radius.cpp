#include "yeti_radius.h"

// #include "AmPlugIn.h"
#include "AmApi.h"
#include "jsonArg.h"

int YetiRadius::init_radius_module()
{
    AmArg ret;

    AmDynInvokeFactory *radius_client_factory = AmPlugIn::instance()->getFactory4Di("radius_client");
    if (nullptr == radius_client_factory) {
        config.use_radius = false;
        return 0;
    }

    config.use_radius = true;

    radius_client = radius_client_factory->getInstance();
    if (nullptr == radius_client) {
        ERROR("radius_client module factory error");
        return 1;
    }

    radius_client->invoke("init", AmArg(), ret);
    if (0 != ret.asInt()) {
        ERROR("can't init radius client module");
        return 1;
    }

    radius_client->invoke("start", AmArg(), ret);

    return 0;
}

void YetiRadius::load_radius_auth_connections(const AmArg &data)
{
    AmArg ret;
    radius_client->invoke("clearAuthConnections", AmArg(), ret);

    if (!isArgArray(data))
        return;

    DBG("got %ld radius auth profiles from db", data.size());
    for (size_t i = 0; i < data.size(); i++) {
        auto &a = data[i];

        AmArg args;
        args.push(a["id"]);
        args.push(a["name"]);
        args.push(a["server"]);
        args.push(a["port"]);
        args.push(a["secret"]);
        args.push(a["reject_on_error"]);
        args.push(a["timeout"]);
        args.push(a["attempts"]);
        args.push(a["avps"]);

        ret.clear();
        try {
            radius_client->invoke("addAuthConnection", args, ret);
            if (0 != ret.asInt()) {
                ERROR("can't add radius auth connection for profile %d", a["id"].asInt());
            }
        } catch (AmDynInvoke::NotImplemented &e) {
            ERROR("got AmDynInvoke error during radius module configuration: %s", e.what.c_str());
        } catch (const string &s) {
            ERROR("got exception during radius module configuration: %s", s.c_str());
        } catch (...) {
            ERROR("got exception during radius module configuration");
        }
    }
}

void YetiRadius::load_radius_acc_connections(const AmArg &data)
{
    AmArg ret;
    radius_client->invoke("clearAccConnections", AmArg(), ret);

    if (!isArgArray(data))
        return;

    DBG("got %ld radius accounting profiles from db", data.size());
    for (size_t i = 0; i < data.size(); i++) {
        auto &a = data[i];

        AmArg args;
        args.push(a["id"]);
        args.push(a["name"]);
        args.push(a["server"]);
        args.push(a["port"]);
        args.push(a["secret"]);
        args.push(a["timeout"]);
        args.push(a["attempts"]);
        args.push(a["start_avps"]);
        args.push(a["interim_avps"]);
        args.push(a["stop_avps"]);
        args.push(a["enable_start_accounting"]);
        args.push(a["enable_interim_accounting"]);
        args.push(a["enable_stop_accounting"]);
        args.push(a["interim_accounting_interval"]);

        ret.clear();
        try {
            radius_client->invoke("addAccConnection", args, ret);
            if (0 != ret.asInt()) {
                ERROR("can't add radius acc connection for profile %d", a["id"].asInt());
            }
        } catch (AmDynInvoke::NotImplemented &e) {
            ERROR("got AmDynInvoke error during radius module configuration: %s", e.what.c_str());
        } catch (const string &s) {
            ERROR("got exception for addAccConnection: %s", s.c_str());
        } catch (...) {
            ERROR("got exception for addAccConnection");
        }
    }
}

void YetiRadius::radius_invoke(const string &method, const AmArg &args, AmArg &ret)
{
    if (!config.use_radius)
        throw AmSession::Exception(500, "radius usage is not enabled");

    radius_client->invoke(method, args, ret);
}
