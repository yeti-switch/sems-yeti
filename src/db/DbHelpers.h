#pragma once

#include <AmArg.h>

#include <string>

bool DbAmArg_hash_get_bool(
    const AmArg &a,
    const string &key,
    bool default_value = false);

bool DbAmArg_hash_get_bool_any(
    const AmArg &a,
    const string &key,
    bool default_value = false);

string DbAmArg_hash_get_str(
    const AmArg &a,
    const string &key,
    const string &default_string = string());

string DbAmArg_hash_get_str_any(
    const AmArg &a,
    const string &key,
    const string &default_string = string());

int DbAmArg_hash_get_int(
    const AmArg &a,
    const string &key,
    int default_value = 0);

int DbAmArg_hash_get_int(
    const AmArg &a,
    const string &key,
    int default_value,
    int failover_value);
