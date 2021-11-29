#pragma once

#include <pqxx/pqxx>

struct DbConfigStates {
    unsigned long trusted_lb;
    unsigned long ip_auth;
    unsigned long stir_shaken_trusted_certificates;
    unsigned long stir_shaken_trusted_repositories;

    DbConfigStates()
      : trusted_lb(0),
        ip_auth(0),
        stir_shaken_trusted_certificates(0),
        stir_shaken_trusted_repositories(0)
    {}

    void readFromDbReply(const pqxx::result &r);
};
