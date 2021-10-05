#include "DbConfigStates.h"

void DbConfigStates::readFromDbReply(const pqxx::result &r)
{
    if(r.empty()) return;

    const auto &row = r.front();
    ip_auth = row["ip_auth"].as<unsigned long>();
    trusted_lb = row["trusted_lb"].as<unsigned long>();
}
