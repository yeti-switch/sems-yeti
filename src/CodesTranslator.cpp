#include "CodesTranslator.h"
#include "yeti.h"
#include "sip/defs.h"

#include "AmSession.h"
#include "db/DbHelpers.h"

CodesTranslator *CodesTranslator::_instance = 0;


InternalException::InternalException(unsigned int code, int override_id)
    : icode(code)
{
    CodesTranslator::instance()->translate_db_code(icode, internal_code, internal_reason, response_code,
                                                   response_reason, override_id);
}

CodesTranslator::CodesTranslator()
{
    stat.clear();
}

CodesTranslator::~CodesTranslator() {}

CodesTranslator *CodesTranslator::instance()
{
    if (!_instance)
        _instance = new CodesTranslator();
    return _instance;
}

void CodesTranslator::dispose()
{
    if (_instance)
        delete _instance;
}

int CodesTranslator::configure(AmConfigReader &)
{
    return 0;
}

void CodesTranslator::pref::getInfo(AmArg &ret) const
{
    ret["is_stop_hunting"] = is_stop_hunting;
}

void CodesTranslator::trans::getInfo(AmArg &ret) const
{
    ret["rewrite_code"]              = rewrite_code;
    ret["rewrite_reason"]            = rewrite_reason;
    ret["pass_reason_to_originator"] = pass_reason_to_originator;
}

void CodesTranslator::icode::getInfo(AmArg &ret) const
{
    ret["internal_code"]   = internal_code;
    ret["internal_reason"] = internal_reason;
    ret["response_code"]   = response_code;
    ret["response_reason"] = response_reason;
    ret["store_cdr"]       = store_cdr;
    ret["silently_drop"]   = silently_drop;
}

void CodesTranslator::load_disconnect_code_rerouting(const AmArg &data)
{
    Code2PrefContainer _code2pref;
    if (isArgArray(data)) {
        for (size_t i = 0; i < data.size(); i++) {
            auto &row = data[i];
            auto  it  = _code2pref.emplace(DbAmArg_hash_get_int(row, "received_code", 0),
                                           DbAmArg_hash_get_bool(row, "stop_rerouting", true));
            DBG("ResponsePref:     %d -> stop_hunting: %d", it.first->first, it.first->second.is_stop_hunting);
        }
    }

    AmLock l(code2pref_mutex);
    code2pref.swap(_code2pref);
}

void CodesTranslator::load_disconnect_code_rewrite(const AmArg &data)
{
    Code2TransContainer _code2trans;
    if (isArgArray(data)) {
        for (size_t i = 0; i < data.size(); i++) {
            auto  &row             = data[i];
            int    code            = DbAmArg_hash_get_int(row, "o_code", 0);
            string rewrited_reason = DbAmArg_hash_get_str(row, "o_rewrited_reason");
            if (rewrited_reason.empty()) {
                rewrited_reason = DbAmArg_hash_get_str(row, "o_reason");
            }

            auto it = _code2trans.try_emplace(code, DbAmArg_hash_get_bool(row, "o_pass_reason_to_originator", false),
                                              DbAmArg_hash_get_int(row, "o_rewrited_code", code), rewrited_reason);

            DBG("ResponseTrans:     %d -> %d:'%s' pass_reason: %d", code, it.first->second.rewrite_code,
                it.first->second.rewrite_reason.c_str(), it.first->second.pass_reason_to_originator);
        }
    }

    AmLock l(code2trans_mutex);
    code2trans.swap(_code2trans);
}

void CodesTranslator::load_disconnect_code_refuse(const AmArg &data)
{
    Icode2RespContainer _icode2resp;

    if (isArgArray(data)) {
        for (size_t i = 0; i < data.size(); i++) {
            auto        &row             = data[i];
            unsigned int code            = DbAmArg_hash_get_int(row, "o_id", 0);
            int          internal_code   = DbAmArg_hash_get_int(row, "o_code", 0);
            string       internal_reason = DbAmArg_hash_get_str(row, "o_reason");
            int          response_code   = DbAmArg_hash_get_int(row, "o_rewrited_code", internal_code);
            string       response_reason = DbAmArg_hash_get_str(row, "o_rewrited_reason");
            if (response_reason.empty()) // no difference between null and empty string for us
                response_reason = internal_reason;

            _icode2resp.try_emplace(code, internal_code, internal_reason, response_code, response_reason,
                                    DbAmArg_hash_get_bool(row, "o_store_cdr", true),
                                    DbAmArg_hash_get_bool(row, "o_silently_drop", false));

            DBG("DbTrans:     %d -> <%d:'%s'>, <%d:'%s'>", code, internal_code, internal_reason.c_str(), response_code,
                response_reason.c_str());
        }
    }

    AmLock l(icode2resp_mutex);
    icode2resp.swap(_icode2resp);
}

void CodesTranslator::load_disconnect_code_refuse_overrides(const AmArg &data)
{
    Icode2RespOverridesContainer _overrides;

    if (isArgArray(data)) {
        for (size_t i = 0; i < data.size(); i++) {
            auto &row         = data[i];
            int   override_id = DbAmArg_hash_get_int(row, "policy_id");

            unsigned int code = DbAmArg_hash_get_int(row, "o_id", 0); // database internal code

            int    internal_code   = DbAmArg_hash_get_int(row, "o_code", 0);
            string internal_reason = DbAmArg_hash_get_str(row, "o_reason");
            int    response_code   = DbAmArg_hash_get_int(row, "o_rewrited_code", internal_code);
            string response_reason = DbAmArg_hash_get_str(row, "o_rewrited_reason");

            _overrides.emplace(override_id, Icode2RespContainer())
                .first->second.emplace(code, icode(internal_code, internal_reason, response_code, response_reason,
                                                   DbAmArg_hash_get_bool(row, "o_store_cdr", true),
                                                   DbAmArg_hash_get_bool(row, "o_silently_drop", false)));
        }
    }

    AmLock l(icode2resp_mutex);
    icode2resp_overrides.swap(_overrides);
}

void CodesTranslator::load_disconnect_code_rerouting_overrides(const AmArg &data)
{
    Code2PrefOverridesContainer _overrides;

    if (isArgArray(data)) {
        for (size_t i = 0; i < data.size(); i++) {
            auto &row         = data[i];
            int   override_id = DbAmArg_hash_get_int(row, "policy_id");
            int   code        = DbAmArg_hash_get_int(row, "received_code", 0);

            auto it = _overrides.emplace(override_id, Code2PrefContainer())
                          .first->second.emplace(code, DbAmArg_hash_get_bool(row, "stop_rerouting", true));

            DBG("Override %d ResponsePref:     %d -> stop_hunting: %d", override_id, code,
                it.first->second.is_stop_hunting);
        }
    }

    AmLock l(code2pref_mutex);
    code2prefs_overrides.swap(_overrides);
}

void CodesTranslator::load_disconnect_code_rewrite_overrides(const AmArg &data)
{
    Code2TransOverridesContainer _overrides;

    if (isArgArray(data)) {
        for (size_t i = 0; i < data.size(); i++) {
            auto  &row             = data[i];
            int    override_id     = DbAmArg_hash_get_int(row, "o_policy_id");
            int    code            = DbAmArg_hash_get_int(row, "o_code", 0);
            string rewrited_reason = DbAmArg_hash_get_str(row, "o_rewrited_reason");
            if (rewrited_reason.empty()) {
                rewrited_reason = DbAmArg_hash_get_str(row, "o_reason");
            }

            auto it =
                _overrides.emplace(override_id, Code2TransContainer())
                    .first->second.try_emplace(code, DbAmArg_hash_get_bool(row, "o_pass_reason_to_originator", false),
                                               DbAmArg_hash_get_int(row, "o_rewrited_code", code), rewrited_reason);

            auto &t = it.first->second;
            DBG("Override %d ResponseTrans:     %d -> %d:'%s' pass_reason: %d", override_id, code, t.rewrite_code,
                t.rewrite_reason.c_str(), t.pass_reason_to_originator);
        }
    }

    AmLock l(code2trans_mutex);
    code2trans_overrides.swap(_overrides);
}

void CodesTranslator::rewrite_response(unsigned int code, const string &reason, unsigned int &out_code,
                                       string &out_reason, int override_id)
{
    AmLock l(code2trans_mutex);

    if (override_id != 0) {
        const auto oit = code2trans_overrides.find(override_id);
        if (oit != code2trans_overrides.end()) {
            const auto tit = oit->second.find(code);
            if (tit != oit->second.end()) {
                const trans &t       = tit->second;
                string       treason = reason;
                out_code             = t.rewrite_code;
                out_reason           = t.pass_reason_to_originator ? treason : t.rewrite_reason;
                DBG("translated %d:'%s' -> %d:'%s' with override<%d>", code, treason.c_str(), out_code,
                    out_reason.c_str(), override_id);
                return;
            } else {
                DBG("override<%d> has no translation for code '%d'. use global config", override_id, code);
            }
        } else {
            DBG("unknown override<%d>. use global config", override_id);
        }
    }

    const auto it = code2trans.find(code);
    if (it != code2trans.end()) {
        const trans &t       = it->second;
        string       treason = reason;
        out_code             = t.rewrite_code;
        out_reason           = t.pass_reason_to_originator ? treason : t.rewrite_reason;
        DBG("translated %d:'%s' -> %d:'%s'", code, treason.c_str(), out_code, out_reason.c_str());
    } else {
        stat.unknown_response_codes++;
        DBG("no translation for response with code '%d'. leave it 'as is'", code);
        out_code   = code;
        out_reason = reason;
    }
}

bool CodesTranslator::stop_hunting(unsigned int code, int override_id)
{
    bool ret = true;

    AmLock l(code2pref_mutex);

    if (override_id != 0) {
        const auto oit = code2prefs_overrides.find(override_id);
        if (oit != code2prefs_overrides.end()) {
            const auto tit = oit->second.find(code);
            if (tit != oit->second.end()) {
                ret = tit->second.is_stop_hunting;
                DBG("stop_hunting = %d for code '%d' with override<%d>", ret, code, override_id);
                return ret;
            } else {
                DBG("override<%d> has no translation for code '%d'. use global config", override_id, code);
            }
        } else {
            DBG("unknown override<%d>. use global config", override_id);
        }
    }

    const auto it = code2pref.find(code);
    if (it != code2pref.end()) {
        ret = it->second.is_stop_hunting;
        DBG("stop_hunting = %d for code '%d'", ret, code);
    } else {
        stat.missed_response_configs++;
        DBG("no preference for code '%d', so simply stop hunting", code);
    }
    return ret;
}

bool CodesTranslator::apply_internal_code_translation(const CodesTranslator::icode &c, unsigned int &internal_code,
                                                      string &internal_reason, unsigned int &response_code,
                                                      string &response_reason)
{
    internal_code   = c.internal_code;
    internal_reason = c.internal_reason;
    if (c.silently_drop && !Yeti::instance().config.early_100_trying) {
        response_code   = NO_REPLY_DISCONNECT_CODE;
        response_reason = "";
    } else {
        response_code   = c.response_code;
        response_reason = c.response_reason;
    }
    DBG("translation result: internal = <%d:'%s'>, response = <%d:'%s'>, silently_drop = %d, store_cdr = %d",
        internal_code, internal_reason.c_str(), response_code, response_reason.c_str(), c.silently_drop, c.store_cdr);
    return c.store_cdr;
}

bool CodesTranslator::translate_db_code(unsigned int code, unsigned int &internal_code, string &internal_reason,
                                        unsigned int &response_code, string &response_reason, int override_id)
{
    DBG("translate_db_code: %d, override_id: %d", code, override_id);

    AmLock l(icode2resp_mutex);

    while (override_id != 0) {
        const auto oit = icode2resp_overrides.find(override_id);
        if (oit == icode2resp_overrides.end()) {
            DBG("unknown override<%d> for db code %d. use global config", override_id, code);
            break;
        }
        const auto it = oit->second.find(code);
        if (it == oit->second.end()) {
            DBG("override<%d> has no translation for db code '%d'. use global config", override_id, code);
            break;
        }
        return apply_internal_code_translation(it->second, internal_code, internal_reason, response_code,
                                               response_reason);
    }

    const auto it = icode2resp.find(code);
    if (it == icode2resp.end()) {
        stat.unknown_internal_codes++;
        DBG("no translation for db code '%d'. reply with 500", code);
        internal_code = response_code = 500;
        internal_reason               = "Internal code " + int2str(code);
        response_reason               = SIP_REPLY_SERVER_INTERNAL_ERROR;
        return true; // write cdr for unknown internal codes
    }

    return apply_internal_code_translation(it->second, internal_code, internal_reason, response_code, response_reason);
}

template <typename ContainerType, typename OverridesContainerType>
void addTranslationsToResponse(ContainerType &container, OverridesContainerType &overrides_container, AmMutex &mutex,
                               const std::string &key, AmArg &ret)
{
    AmLock l(mutex);

    AmArg &mapping = ret[key];
    for (const auto &it : container)
        it.second.getInfo(mapping[int2str(it.first)]);

    AmArg &overrides_mapping = ret["overrides"][key];
    for (const auto &oit : overrides_container) {
        AmArg &u = overrides_mapping[int2str(oit.first)];
        for (const auto &it : oit.second)
            it.second.getInfo(u[int2str(it.first)]);
    }
}

void CodesTranslator::GetConfig(AmArg &ret)
{
    addTranslationsToResponse(code2pref, code2prefs_overrides, code2pref_mutex, "hunting", ret);

    addTranslationsToResponse(code2trans, code2trans_overrides, code2trans_mutex, "response_translations", ret);

    addTranslationsToResponse(icode2resp, icode2resp_overrides, icode2resp_mutex, "internal_translations", ret);
}

void CodesTranslator::clearStats()
{
    stat.clear();
}

void CodesTranslator::getStats(AmArg &ret)
{
    stat.get(ret);
}
