#include "yeti.h"

#include "sdp_filter.h"
#include "log.h"
#include "format_helper.h"
#include "AmPlugIn.h"
#include "AmArg.h"
#include "jsonArg.h"
#include "AmSession.h"
#include "AmUtils.h"
#include "AmAudioFile.h"
#include "AmMediaProcessor.h"
#include "SDPFilter.h"
#include "CallLeg.h"
#include "Registration.h"
#include "CodecsGroup.h"
#include "Sensors.h"
#include "AmEventDispatcher.h"
#include "ampi/SctpBusAPI.h"
#include "ampi/PostgreSqlAPI.h"
#include "ampi/SipRegistrarApi.h"
#include "ampi/IdentityValidatorApi.h"
#include "sip/resolver.h"
#include "ObjectsCounter.h"

#include "cfg/yeti_opts.h"
#include "cfg/statistics_opts.h"
#include "cfg/cfg_helpers.h"

#include "IPTree.h"

#include <string.h>
#include <ctime>
#include <cstdio>

#define EPOLL_MAX_EVENTS 2048

#define YETI_SIGNATURE       "yeti-switch"
#define YETI_AGENT_SIGNATURE YETI_SIGNATURE " " YETI_VERSION

#define LOG_BUF_SIZE 2048

string yeti_auth_feedback_header("X-Yeti-Auth-Error: ");

void cfg_reader_error(cfg_t *cfg, const char *fmt, va_list ap)
{
    int  l = 0;
    char buf[LOG_BUF_SIZE];
    if (cfg->title) {
        // if(cfg->opts->flags & CFGF_TITLE) {
        l = snprintf(buf, LOG_BUF_SIZE, "line:%d section '%s'(%s): ", cfg->line, cfg->name, cfg->title);
    } else {
        l = snprintf(buf, LOG_BUF_SIZE, "line:%d section '%s': ", cfg->line, cfg->name);
    }
    l += vsnprintf(buf + l, static_cast<size_t>(LOG_BUF_SIZE - l), fmt, ap);
    ERROR("%.*s", l, buf);
}

Yeti *Yeti::_instance = nullptr;

Yeti *Yeti::create_instance()
{
    if (!_instance)
        _instance = new Yeti();
    return _instance;
}

Yeti &Yeti::instance()
{
    return *_instance;
}

void Yeti::cfg_timer_mapping_entry::init_exceptions_counter(const string &key)
{
    exceptions_counter = &stat_group(Counter, MOD_NAME, "config_exceptions").addAtomicCounter().addLabel("type", key);
}

Yeti::Yeti()
    : AmEventFdQueue(this)
{
    initCfgTimerMappings();
}

Yeti::~Yeti()
{
    stop(true);

    if (confuse_cfg)
        cfg_free(confuse_cfg);

    CodecsGroups::dispose();
    CodesTranslator::dispose();
    Sensors::dispose();
    Registration::dispose();
}

int Yeti::configure(const std::string &config_buf)
{
    confuse_cfg = cfg_init(yeti_opts, CFGF_NONE);
    if (!confuse_cfg) {
        ERROR("failed to init cfg opts");
        return -1;
    }

    cfg_set_error_function(confuse_cfg, cfg_reader_error);

    switch (cfg_parse_buf(confuse_cfg, config_buf.c_str())) {
    case CFG_SUCCESS:     break;
    case CFG_PARSE_ERROR: ERROR("failed to parse Yeti configuration"); return -1;
    default:              ERROR("unexpected error on Yeti configuring"); return -1;
    }

    if (config.configure(confuse_cfg, cfg))
        return -1;

    return 0;
}

static void apply_yeti_signatures()
{
    if (AmConfig.sdp_origin == DEFAULT_SDP_ORIGIN)
        AmConfig.sdp_origin = YETI_SIGNATURE;

    if (AmConfig.sdp_session_name == DEFAULT_SDP_SESSION_NAME)
        AmConfig.sdp_session_name = YETI_SIGNATURE;

    AmLcConfig::instance().applySignature(YETI_AGENT_SIGNATURE);
}

static void init_counters()
{
    ObjCounterInit(Cdr);
    ObjCounterInit(AuthCdr);
    ObjCounterInit(SqlCallProfile);
}

int Yeti::onLoad()
{
    start_time = time(nullptr);

    init_rpc();
    init_counters();
    apply_yeti_signatures();

    if ((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    epoll_link(epoll_fd);

    start(); // start yeti thread

    calls_show_limit = static_cast<int>(cfg.getParameterInt("calls_show_limit", 100));

    /*if(TrustedHeaders::instance()->configure(cfg)){
        ERROR("TrustedHeaders configure failed");
        return -1;
    }*/

    if (router.configure(confuse_cfg, cfg)) {
        ERROR("SqlRouter configure failed");
        return -1;
    }

    if (cdr_list.configure(confuse_cfg)) {
        ERROR("CdrList configure failed");
        return -1;
    }

    if (configure_filter(&router)) {
        ERROR("ActiveCallsFilter configure failed");
        return -1;
    }

    if (init_radius_module()) {
        ERROR("radius module configure failed");
        return -1;
    }

    if (rctl.configure(confuse_cfg, cfg)) {
        ERROR("ResourceControl configure failed");
        return -1;
    }

    if (options_prober_manager.configure()) {
        ERROR("SipProberManager configure failed");
        return -1;
    }

    if (CodecsGroups::instance()->configure(cfg)) {
        ERROR("CodecsGroups configure failed");
        return -1;
    }

    if (CodesTranslator::instance()->configure(cfg)) {
        ERROR("CodesTranslator configure failed");
        return -1;
    }

    if (Sensors::instance()->configure(cfg)) {
        ERROR("Sensors configure failed");
        return -1;
    }

    if (Registration::instance()->configure(cfg)) {
        ERROR("Registration agent configure failed");
        return -1;
    }

    if (!verifyHttpDestinations()) {
        return -1;
    }

    db_cfg_reload_timer.link(epoll_fd);
    db_cfg_reload_timer.set(std::chrono::duration_cast<std::chrono::microseconds>(config.db_refresh_interval).count(),
                            true);

    http_sequencer.setHttpDestinationName(config.http_events_destination);

    // start threads
    rctl.start();
    if (cdr_list.getSnapshotsEnabled())
        cdr_list.start();

    configuration_finished = true;

    checkStates();

    // check dependencies
    is_registrar_availbale          = (AmPlugIn::instance()->getFactory4Config("registrar") != nullptr);
    is_identity_validator_availbale = (AmPlugIn::instance()->getFactory4Config("identity_validator") != nullptr);

    return 0;
}

void Yeti::run()
{
    int                ret, f;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("yeti-worker");
    DBG3("start yeti-worker");

    AmEventDispatcher::instance()->addEventQueue(YETI_QUEUE_NAME, this);

    // load configurations from DB without waiting for timer
    // onDbCfgReloadTimer();

    stopped = false;
    do {
        // DBG("epoll_wait...");
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        // DBG("epoll_wait = %d",ret);

        if (ret == -1 && errno != EINTR) {
            ERROR("epoll_wait: %s", strerror(errno));
        }

        if (ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            f                     = e.data.fd;

            if (f == db_cfg_reload_timer) {
                checkStates();
                db_cfg_reload_timer.read();
            } else if (f == -queue_fd()) {
                clear_pending();
                processEvents();
            }
        }
    } while (!stopped);

    AmEventDispatcher::instance()->delEventQueue(YETI_QUEUE_NAME);

    DBG("yeti-worker finished");
}

void Yeti::on_stop()
{
    uint64_t u = 1;

    DBG("Yeti::on_stop");

    cdr_list.stop();
    rctl.stop();

    stopped = true;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    ::write(queue_fd(), &u, sizeof(uint64_t)); // trigger events processing
#pragma GCC diagnostic pop
}

#define ON_EVENT_TYPE(type) if (type *e = dynamic_cast<type *>(ev))

void Yeti::process(AmEvent *ev)
{
    ON_EVENT_TYPE(HttpPostResponseEvent)
    {
        http_sequencer.processHttpReply(*e);
    }
    else ON_EVENT_TYPE(JsonRpcRequestEvent) {
        if (e->method_id == MethodReloadDBStates) {
            checkStates();
            postJsonRpcReply(*e, true);
        } else if (e->method_id == MethodShowDBStates) {
            showStates(*e);
        } else {
            ERROR("unknown rpc request: %s", e->method.c_str());
        }
    }
    else ON_EVENT_TYPE(PGResponse) {
        if (configuration_finished) {
            auto it_req     = db_requests.find(e->token);
            auto it_cfg_map = db_config_timer_mappings.find(e->token);
            if (it_req != db_requests.end()) {
                it_req->second.on_db_response(*e);
                db_requests.erase(it_req);
            } else if (it_cfg_map != db_config_timer_mappings.end()) {
                bool exception = true;
                try {
                    DBG("call on_db_response() for '%s'", e->token.data());
                    it_cfg_map->second.on_db_response(*e);
                    exception = false;
                } catch (AmArg::OutOfBoundsException &) {
                    ERROR("AmArg::OutOfBoundsException in cfg timer handler: %s", e->token.data());
                } catch (AmArg::TypeMismatchException &) {
                    ERROR("AmArg::TypeMismatchException in cfg timer handler: %s", e->token.data());
                } catch (std::exception &exception) {
                    ERROR("std::exception in cfg timer handler '%s': %s", e->token.data(), exception.what());
                } catch (std::string &s) {
                    ERROR("cfg timer handler %s exception: %s", e->token.data(), s.data());
                } catch (...) {
                    ERROR("exception in cfg timer handler: %s", e->token.data());
                }

                if (exception) {
                    it_cfg_map->second.exceptions_counter->inc();
                }
            } else {
                ERROR("unknown db response token: %s", e->token.data());
            }
        } else {
            sync_db.db_reply_token  = e->token;
            sync_db.db_reply_result = e->result;
            sync_db.db_reply_condition.set(sync_db::DB_REPLY_RESULT);
        }
    }
    else ON_EVENT_TYPE(PGResponseError) {
        ERROR("got PGResponseError '%s' for token: %s", e->error.data(), e->token.data());
        if (configuration_finished) {
            auto it_req     = db_requests.find(e->token);
            auto it_cfg_map = db_config_timer_mappings.find(e->token);
            if (it_req != db_requests.end()) {
                it_req->second.on_db_error(*e);
                db_requests.erase(it_req);
            } else if (it_cfg_map != db_config_timer_mappings.end()) {
                it_cfg_map->second.exceptions_counter->inc();
            } else {
                ERROR("unknown db response token: %s", e->token.data());
            }
        } else {
            sync_db.db_reply_token = e->token;
            sync_db.db_reply_condition.set(sync_db::DB_REPLY_ERROR);
        }
    }
    else ON_EVENT_TYPE(PGTimeout) {
        ERROR("got PGTimeout for token: %s", e->token.data());
        if (configuration_finished) {
            auto it_req     = db_requests.find(e->token);
            auto it_cfg_map = db_config_timer_mappings.find(e->token);
            if (it_req != db_requests.end()) {
                it_req->second.on_db_timeout(*e);
                db_requests.erase(it_req);
            } else if (it_cfg_map != db_config_timer_mappings.end()) {
                it_cfg_map->second.exceptions_counter->inc();
            } else {
                ERROR("unknown db response token: %s", e->token.data());
            }
        } else {
            sync_db.db_reply_token = e->token;
            sync_db.db_reply_condition.set(sync_db::DB_REPLY_TIMEOUT);
        }
    }
    else ON_EVENT_TYPE(YetiComponentInited) {
        component_inited[e->type] = true;
    }
    else ON_EVENT_TYPE(AmSystemEvent) {
        if (e->sys_event == AmSystemEvent::ServerShutdown) {
            DBG("got shutdown event");
            stop();
        }
        return;
    }
    else DBG("got unknown event %s", typeid(*ev).name());
}

bool Yeti::isAllComponentsInited()
{
    for (int i = 0; i < YetiComponentInited::MaxType; i++) {
        if (!component_inited[i])
            return false;
    }
    return true;
}

void Yeti::initCfgTimerMappings()
{
    db_config_timer_mappings = {

        // identity_validator
        {   "stir_shaken_trusted_certificates",
         { [&](const string &key) {
         if (!isIdentityValidatorAvailbale())
         return;
         AmEventDispatcher::instance()->post(IDENTITY_VALIDATOR_APP_QUEUE, new LoadTrustedCertsRequest());
         },
         [&](const PGResponse &e) {} }                                                                        },
        {   "stir_shaken_trusted_repositories",
         { [&](const string &key) {
         if (!isIdentityValidatorAvailbale())
         return;
         AmEventDispatcher::instance()->post(IDENTITY_VALIDATOR_APP_QUEUE, new LoadTrustedReposRequest());
         },
         [&](const PGResponse &e) {} }                                                                        },
        // signing_key_cache
        {   "stir_shaken_signing_certificates",
         { [&](const string &key) {
         if (!isIdentityValidatorAvailbale())
         return;
         yeti_routing_db_query("SELECT * FROM load_stir_shaken_signing_certificates()", key);
         },
         [&](const PGResponse &e) { signing_keys_cache.reloadSigningKeys(e.result); } }                       },

        // orig_pre_auth
        {                            "ip_auth",
         { [&](const string &key) {
         auto query = new PGParamExecute(PGQueryData(yeti_routing_pg_worker, "SELECT * FROM load_ip_auth($1,$2)",
         true, /* single */
         YETI_QUEUE_NAME, key),
         PGTransactionData(), false);
         query->addParam(AmConfig.node_id).addParam(config.pop_id);
         AmEventDispatcher::instance()->post(POSTGRESQL_QUEUE, query);
         },
         [&](const PGResponse &e) { orig_pre_auth.reloadLoadIPAuth(e.result); } }                             },
        {                         "trusted_lb",
         { [&](const string &key) { yeti_routing_db_query("SELECT * FROM load_trusted_lb()", key); },
         [&](const PGResponse &e) { orig_pre_auth.reloadLoadBalancers(e.result); } }                          },

        // Sensors
        {                            "sensors",
         { [&](const string &key) { yeti_routing_db_query("SELECT * FROM load_sensor()", key); },
         [&](const PGResponse &e) { Sensors::instance()->load_sensors_config(e.result); } }                   },

        /* CodesTranslator performs 6 SQL queries to load data.
         * use artifical subkeys to distinguish them */
        {                       "translations",
         { [&](const string &) {
         // iterate subkeys
         auto end_it = db_config_timer_mappings.lower_bound("translations/");
         for (auto it = db_config_timer_mappings.upper_bound("translations."); it != end_it; ++it) {
         it->second.on_reload(it->first);
         }
         },
         [&](const PGResponse &) {
         // never called. alias key
         } }                                                                                                  },
        {          "translations.dc_rerouting",
         { [&](const string &key) { yeti_routing_db_query("SELECT * FROM load_disconnect_code_rerouting()", key); },
         [&](const PGResponse &e) { CodesTranslator::instance()->load_disconnect_code_rerouting(e.result); } } },
        {            "translations.dc_rewrite",
         { [&](const string &key) { yeti_routing_db_query("SELECT * FROM load_disconnect_code_rewrite()", key); },
         [&](const PGResponse &e) { CodesTranslator::instance()->load_disconnect_code_rewrite(e.result); } }  },
        {             "translations.dc_refuse",
         { [&](const string &key) { yeti_routing_db_query("SELECT * FROM load_disconnect_code_refuse()", key); },
         [&](const PGResponse &e) { CodesTranslator::instance()->load_disconnect_code_refuse(e.result); } }   },
        {    "translations.dc_refuse_override",
         { [&](const string &key) {
         yeti_routing_db_query("SELECT * FROM load_disconnect_code_refuse_overrides()", key);
         },
         [&](const PGResponse &e) {
         CodesTranslator::instance()->load_disconnect_code_refuse_overrides(e.result);
         } }                                                                                                  },
        { "translations.dc_rerouting_override",
         { [&](const string &key) {
         yeti_routing_db_query("SELECT * FROM load_disconnect_code_rerouting_overrides()", key);
         },
         [&](const PGResponse &e) {
         CodesTranslator::instance()->load_disconnect_code_rerouting_overrides(e.result);
         } }                                                                                                  },
        {   "translations.dc_rewrite_override",
         { [&](const string &key) {
         yeti_routing_db_query("SELECT * FROM load_disconnect_code_rewrite_overrides()", key);
         },
         [&](const PGResponse &e) {
         CodesTranslator::instance()->load_disconnect_code_rewrite_overrides(e.result);
         } }                                                                                                  },

        // CodecsGroups
        {                       "codec_groups",
         { [&](const string &key) {
         yeti_routing_db_query(router.is_new_codec_groups() ? "SELECT * FROM load_codec_groups()"
         : "SELECT * FROM load_codecs()",
         key);
         },
         [&](const PGResponse &e) {
         if (router.is_new_codec_groups())
         CodecsGroups::instance()->load_codec_groups(e.result);
         else
         CodecsGroups::instance()->load_codecs(e.result);
         } }                                                                                                  },

        // Registration
        {                      "registrations",
         { [&](const string &key) {
         auto query = new PGParamExecute(
         PGQueryData(yeti_routing_pg_worker, "SELECT * FROM load_registrations_out($1,$2)", true, /* single */
         YETI_QUEUE_NAME, key),
         PGTransactionData(), false);
         query->addParam(config.pop_id).addParam(AmConfig.node_id);
         AmEventDispatcher::instance()->post(POSTGRESQL_QUEUE, query);
         },
         [&](const PGResponse &e) { Registration::instance()->load_registrations(e.result); } }               },

        // YetiRadius
        {      "radius_authorization_profiles",
         { [&](const string &key) {
         if (config.use_radius)
         yeti_routing_db_query("SELECT * FROM load_radius_profiles()", key);
         },
         [&](const PGResponse &e) { load_radius_auth_connections(e.result); } }                               },
        {         "radius_accounting_profiles",
         { [&](const string &key) {
         if (config.use_radius)
         yeti_routing_db_query("SELECT * FROM load_radius_accounting_profiles()", key);
         },
         [&](const PGResponse &e) { load_radius_acc_connections(e.result); } }                                },

        // Auth
        {                   "auth_credentials",
         { [&](const string &key) { yeti_routing_db_query("SELECT * FROM load_incoming_auth()", key); },
         [&](const PGResponse &e) { router.reload_credentials(e.result); } }                                  },

        // OptionsProberManager
        {                    "options_probers",
         { [&](const string &key) {
         auto query = new PGParamExecute(
         PGQueryData(yeti_routing_pg_worker, "SELECT * FROM load_sip_options_probers($1)", true, /* single */
         YETI_QUEUE_NAME, key),
         PGTransactionData(), false);
         query->addParam(AmConfig.node_id);
         AmEventDispatcher::instance()->post(POSTGRESQL_QUEUE, query);
         },
         [&](const PGResponse &e) { options_prober_manager.load_probers(e.result); } }                        },
        {                     "gateways_cache",
         { [&](const string &key) {
         if (!(router.get_lega_gw_cache_key().empty() and router.get_legb_gw_cache_key().empty()))
         yeti_routing_db_query("SELECT * FROM load_gateway_attributes_cache()", key);
         },
         [&](const PGResponse &e) { gateways_cache.update(e.result); } }                                      },
        // CallProfilesCache
        {                       "callprofiles",
         { [&](const string &key) { yeti_routing_db_query("SELECT * FROM load_callprofiles()", key); },
         [&](const PGResponse &e) { callprofiles_cache.load_callprofiles(e); } }                              },
    };

    for (auto &mapping : db_config_timer_mappings)
        mapping.second.init_exceptions_counter(mapping.first);
}

void Yeti::checkStates() noexcept
{
    string token = AmSession::getNewId();
    yeti_routing_db_query("SELECT * FROM check_states()", token);
    db_requests.emplace(token, db_req_entry(
                                   [&](const PGResponse &e) {
                                       try {
                                           const AmArg &r = e.result[0];
                                           for (auto &a : r) {
                                               // DBG("%s: %d",a.first.data(),a.second.asInt());
                                               if (!db_cfg_states.hasMember(a.first) ||
                                                   a.second.asInt() > db_cfg_states[a.first].asInt()) {
                                                   DBG("new or newer db_state %d for: %s", a.second.asInt(),
                                                       a.first.data());
                                                   auto it = db_config_timer_mappings.find(a.first);
                                                   if (it != db_config_timer_mappings.end()) {
                                                       it->second.on_reload(it->first);
                                                   } else {
                                                       ERROR("unknown db_state: %s", a.first.data());
                                                   }
                                               }
                                           }
                                           db_cfg_states = r;
                                       } catch (...) {
                                           DBG("exception on check db state response processing");
                                       }
                                   },
                                   [](const PGResponseError &err) {}, [](const PGTimeout &timeout) {}));
}

void Yeti::showStates(const JsonRpcRequestEvent &e)
{
    string token = AmSession::getNewId();
    yeti_routing_db_query("SELECT * FROM check_states()", token);
    db_requests.emplace(token, db_req_entry(
                                   [&, e](const PGResponse &resp) {
                                       AmArg ret;
                                       ret.assertStruct();
                                       const AmArg &r = resp.result[0];
                                       for (auto &a : r) {
                                           if (db_cfg_states.hasMember(a.first))
                                               ret[a.first]["local"] = db_cfg_states[a.first];
                                           ret[a.first]["db"] = a.second;
                                       }
                                       postJsonRpcReply(e, ret);
                                   },
                                   [e](const PGResponseError &err) { postJsonRpcReply(e, err.error); },
                                   [e](const PGTimeout &timeout) { postJsonRpcReply(e, "timeout"); }));
}

bool Yeti::verifyHttpDestinations()
{
    std::multimap<string, string> destinations;

    // TODO: check "fcm" destination from SBCCallLeg::process_push_token_profile

    if (!config.http_events_destination.empty())
        destinations.emplace(opt_name_http_events_destination, config.http_events_destination);

    if (!config.audio_recorder_http_destination.empty())
        destinations.emplace(opt_name_audio_recorder_http_destination, config.audio_recorder_http_destination);

    for (auto &shapshot_dst : cdr_list.getSnapshotsDestinations())
        destinations.emplace(format("{}.{}.{}.{}", string(section_name_statistics), string(section_name_active_calls),
                                    string(section_name_clickhouse), string(opt_name_destinations)),
                             shapshot_dst);

    if (destinations.empty())
        return true;

    AmDynInvokeFactory *di_f = AmPlugIn::instance()->getFactory4Di("http_client");
    if (!di_f) {
        ERROR("unable to get http_client factory");
        return false;
    }
    AmDynInvoke *http_client = di_f->getInstance();
    if (!http_client) {
        ERROR("unable to get http_client invoke instance");
        return false;
    }
    AmArg args, ret;
    http_client->invoke("show.destinations", args, ret);
    if (!isArgStruct(ret))
        return false;

    auto result = true;
    for (const auto &[dst_opt, dst_name] : destinations) {
        if (!ret.hasMember(dst_name)) {
            ERROR("absent destination '%s' in the http_client. option: %s", dst_name.c_str(), dst_opt.c_str());
            result = false;
        }
    }
    return result;
}
