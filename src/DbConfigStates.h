#pragma once

#include <pqxx/pqxx>

struct DbConfigStates {
    unsigned long trusted_lb;
    unsigned long ip_auth;

    DbConfigStates()
      : trusted_lb(0),
        ip_auth(0)
    {}

    void readFromDbReply(const pqxx::result &r);
};
