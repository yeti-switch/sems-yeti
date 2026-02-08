#pragma once

#include <list>

#include "sip/sip_parser.h"
#include "AmThread.h"

#include "cdr/Cdr.h"
#include "SqlCallProfile.h"
#include "resources/Resource.h"

class SqlRouter;

class fake_logger : public msg_logger {
    sip_msg msg;
    int     code;

  public:
    int log(const char *buf, int len, sockaddr_storage *src_ip, sockaddr_storage *dst_ip, cstring method,
            int reply_code = 0);
    int relog(msg_logger *logger);
};

enum get_profile_cdr_behavior {
    GET_PROFILE_CDR_NEW,   // write old CDR and replace 'CallCtx::cdr' ptr with new one
    GET_PROFILE_CDR_UPDATE // update CallCtx::cdr ptr with new call_profile
};

enum get_profile_filtering_behavior {
    GET_PROFILE_PROFILES_ALL,        // return next non-skipping profile
    GET_PROFILE_PROFILES_NO_REFUSING // return nullptr instead of tail refusing profile
};

struct CallCtx {
    unsigned int references;

    std::unique_ptr<Cdr>           cdr;
    list<SqlCallProfile>           profiles;
    list<SqlCallProfile>::iterator current_profile;
    AmSipRequest                  *initial_invite;
    vector<SdpMedia>               aleg_negotiated_media;
    vector<SdpMedia>               bleg_negotiated_media;
    bool                           SQLexception;
    bool                           on_hold;
    bool                           bleg_early_media_muted;
    bool                           ringing_timeout;
    bool                           ringing_sent;

    string referrer_session;
    bool   transfer_intermediate_state;

    AmSdp bleg_initial_offer;

    string lega_resource_handler;

    SqlRouter &router;

    CallCtx(SqlRouter &router);
    ~CallCtx();

    /* init cdr to refuse with disconnect_code_id */
    bool setRejectCdr(int disconnect_code_id);

    SqlCallProfile *getFirstProfile();
    SqlCallProfile *getNextProfile(get_profile_cdr_behavior       cdr_behavior,
                                   get_profile_filtering_behavior profiles_filtering_behavior);

    SqlCallProfile *getCurrentProfile();

    void setRingingTimeout() { ringing_timeout = true; }
    bool isRingingTimeout() { return ringing_timeout; }

    vector<SdpMedia> &get_self_negotiated_media(bool a_leg);
    vector<SdpMedia> &get_other_negotiated_media(bool a_leg);

    ResourceList &getCurrentResourceList();
    int           getOverrideId(bool aleg = true);

    string &getResourceHandler(SqlCallProfile &profile, bool a_leg = false);
};
