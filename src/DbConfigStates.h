#pragma once

#include "AmArg.h"

struct DbConfigStates {
    unsigned long auth_credentials;
    unsigned long codec_groups;
    unsigned long ip_auth;
    unsigned long options_probers;
    unsigned long radius_accounting_profiles;
    unsigned long radius_authorization_profiles;
    unsigned long registrations;
    unsigned long sensors;
    unsigned long stir_shaken_trusted_certificates;
    unsigned long stir_shaken_trusted_repositories;
    unsigned long translations;
    unsigned long trusted_lb;

    DbConfigStates()
        : auth_credentials(0)
        , codec_groups(0)
        , ip_auth(0)
        , options_probers(0)
        , radius_accounting_profiles(0)
        , radius_authorization_profiles(0)
        , registrations(0)
        , sensors(0)
        , stir_shaken_trusted_certificates(0)
        , stir_shaken_trusted_repositories(0)
        , translations(0)
        , trusted_lb(0)
    {
    }

    DbConfigStates(const AmArg &r) { readFromDbReply(r); }

    void readFromDbReply(const AmArg &r);
};
