#pragma once

#include <AmArg.h>

#include <string>

bool DbAmArg_hash_get_bool(const AmArg &a, const std::string &key, bool default_value = false);

bool DbAmArg_hash_get_bool_any(const AmArg &a, const std::string &key, bool default_value = false);

std::string DbAmArg_hash_get_str(const AmArg &a, const std::string &key,
                                 const std::string &default_string = std::string());

std::string DbAmArg_hash_get_str_any(const AmArg &a, const std::string &key,
                                     const std::string &default_string = std::string());

int DbAmArg_hash_get_int(const AmArg &a, const std::string &key, int default_value = 0);

int DbAmArg_hash_get_int(const AmArg &a, const std::string &key, int default_value, int failover_value);
