#include "CallCtx.h"
#include "CodesTranslator.h"
#include "SqlRouter.h"
#include "AmSession.h"
#include "sip/defs.h"


int fake_logger::log(const char *buf, int len, sockaddr_storage *src_ip, sockaddr_storage *dst_ip, cstring method,
                     int reply_code)
{
    /* DBG("fake_logger called for reply_code = %d, buf = %p, len = %d",
         reply_code, buf,len); */
    if (0 != reply_code) {
        if (msg.buf)
            delete[] msg.buf;
        msg.buf = new char[len];
        memcpy(msg.buf, buf, len);
        msg.len = len;

        msg.local_ip  = *src_ip;
        msg.remote_ip = *dst_ip;
        code          = reply_code;

        msg.type = SIP_REPLY;
    }
    return 0;
}

int fake_logger::relog(msg_logger *logger)
{
    if (NULL == msg.buf || msg.type != SIP_REPLY)
        return -1;
    return logger->log(msg.buf, msg.len, &msg.local_ip, &msg.remote_ip, cstring(), code);
}

bool CallCtx::setRejectCdr(int disconnect_code_id)
{
    if (cdr) {
        ERROR("attempt to override existent CDR with reject one for code: %d", disconnect_code_id);
        return false;
    }

    cdr.reset(new Cdr());

    unsigned int internal_code, response_code;
    string       internal_reason, response_reason;

    if (!CodesTranslator::instance()->translate_db_code(disconnect_code_id, internal_code, internal_reason,
                                                        response_code, response_reason))
    {
        cdr->setSuppress(true);
        return false;
    }

    cdr->update_internal_reason(DisconnectByTS, internal_reason, internal_code, disconnect_code_id);

    cdr->update_aleg_reason(response_reason, response_code);

    return true;
}

SqlCallProfile *CallCtx::getFirstProfile()
{
    // DBG("%s() this = %p",FUNC_NAME,this);
    if (profiles.empty())
        return nullptr;
    current_profile = profiles.begin();

    cdr.reset(new Cdr(*current_profile));

    return &(*current_profile);
}

/*
 *we should not change the cdr or increase the number of attempts in early_state
 */
SqlCallProfile *CallCtx::getNextProfile(get_profile_cdr_behavior       cdr_behavior,
                                        get_profile_filtering_behavior profiles_filtering_behavior)
{
    auto next_profile     = current_profile;
    int  attempts_counter = cdr->attempt_num;

    /*DBG("cdr_behavior:%d, profiles_filtering_behavior:%d, attempts_counter: %d",
        cdr_behavior, profiles_filtering_behavior, attempts_counter);*/

    ++next_profile;
    if (next_profile == profiles.end())
        return nullptr;

    std::list<std::unique_ptr<Cdr>> skipped_cdrs;
    while ((*next_profile).skip_code_id != 0) {
        unsigned int          internal_code, response_code;
        string                internal_reason, response_reason;
        const SqlCallProfile &p = *next_profile;

        bool write_cdr = CodesTranslator::instance()->translate_db_code(
            p.skip_code_id, internal_code, internal_reason, response_code, response_reason, p.aleg_override_id);

        ++next_profile;

        if (write_cdr) {
            auto skip_cdr = new Cdr(*cdr, p);
            skip_cdr->update_internal_reason(DisconnectByTS, internal_reason, internal_code, p.skip_code_id);
            skipped_cdrs.emplace_back(skip_cdr);
        }

        if (next_profile == profiles.end())
            break;
    }

    auto write_skipped_cdrs = [this, &skipped_cdrs, &cdr_behavior, &attempts_counter](bool no_more_profiles) {
        auto new_cdr = cdr_behavior == GET_PROFILE_CDR_NEW;
        if (new_cdr) {
            bool last_cdr = skipped_cdrs.empty() && no_more_profiles;
            router.write_cdr(cdr, last_cdr);
            attempts_counter++;
        }

        while (!skipped_cdrs.empty()) {
            auto &skip_cdr = skipped_cdrs.front();
            auto  last_cdr = new_cdr && no_more_profiles && skipped_cdrs.size() == 1;

            if (!last_cdr)
                skip_cdr->update_aleg_reason(string(), 0);
            skip_cdr->attempt_num = attempts_counter++;

            router.write_cdr(skip_cdr, last_cdr);

            skipped_cdrs.pop_front();
        }

        if (no_more_profiles && !new_cdr) {
            cdr->attempt_num = attempts_counter;
        }
    };

    if (next_profile == profiles.end()) {
        write_skipped_cdrs(true);
        return nullptr;
    }

    switch (profiles_filtering_behavior) {
    case GET_PROFILE_PROFILES_NO_REFUSING:
        if ((*next_profile).disconnect_code_id != 0) {
            write_skipped_cdrs(true);
            return nullptr;
        }
        break;
    case GET_PROFILE_PROFILES_ALL: break;
    }

    switch (cdr_behavior) {
    case GET_PROFILE_CDR_NEW:
    {
        std::unique_ptr<Cdr> new_cdr(new Cdr(*cdr, *next_profile));
        write_skipped_cdrs(false);
        cdr.reset(new_cdr.release());
    } break;
    case GET_PROFILE_CDR_UPDATE:
        write_skipped_cdrs(false);
        cdr->update_sql(*next_profile);
        break;
    }

    cdr->attempt_num = attempts_counter;
    current_profile  = next_profile;

    return &(*current_profile);
}

SqlCallProfile *CallCtx::getCurrentProfile()
{
    if (current_profile == profiles.end())
        return NULL;
    return &(*current_profile);
}

int CallCtx::getOverrideId(bool aleg)
{
    if (current_profile == profiles.end())
        return 0;
    if (aleg) {
        return (*current_profile).aleg_override_id;
    }
    return (*current_profile).bleg_override_id;
}

ResourceList &CallCtx::getCurrentResourceList()
{
    if (current_profile == profiles.end()) {
        ERROR("empty profiles ci:%s r_uri: %s", initial_invite ? initial_invite->callid.data() : "empty",
              initial_invite ? initial_invite->r_uri.data() : "empty");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }
    return (*current_profile).rl;
}

string &CallCtx::getResourceHandler(SqlCallProfile &profile, bool a_leg)
{
    return profile.legab_res_mode_enabled ? (a_leg ? lega_resource_handler : profile.resource_handler)
                                          : profile.resource_handler;
}

vector<SdpMedia> &CallCtx::get_self_negotiated_media(bool a_leg)
{
    if (a_leg)
        return aleg_negotiated_media;
    else
        return bleg_negotiated_media;
}

vector<SdpMedia> &CallCtx::get_other_negotiated_media(bool a_leg)
{
    if (a_leg)
        return bleg_negotiated_media;
    else
        return aleg_negotiated_media;
}

CallCtx::CallCtx(SqlRouter &router)
    : references(0)
    , initial_invite(NULL)
    , SQLexception(false)
    , on_hold(false)
    , bleg_early_media_muted(false)
    , ringing_timeout(false)
    , ringing_sent(false)
    , transfer_intermediate_state(false)
    , router(router)
{
    current_profile = profiles.end();
    // DBG("%s() this = %p",FUNC_NAME,this);
}

CallCtx::~CallCtx()
{
    // DBG("%s() this = %p",FUNC_NAME,this);
    if (initial_invite)
        delete initial_invite;
}
