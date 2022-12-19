#ifndef REDIS_TEST_SERVER_H
#define REDIS_TEST_SERVER_H

#include <unit_tests/TestServer.h>
#include <hiredis/read.h>
#include <stdarg.h>

#include "../src/RedisInstance.h"

class RedisTestServer : protected TestServer
{
    map<string, int> statuses;
public:
    RedisTestServer(){}
    ~RedisTestServer(){}

    void addCommandResponse(const string& cmd, int status, AmArg response, ...)
    {
        va_list args;
        va_start(args, response);
        char* command;
        redis::redisvFormatCommand(&command, cmd.c_str(), args);
        statuses.emplace(command, status);
        if(status != REDIS_REPLY_STATUS)
            addResponse(command, response);
        redis::redisFreeCommand(command);
        va_end(args);
    }

    void addFormattedCommandResponse(const string& cmd, int status, AmArg response)
    {
        statuses.insert(std::make_pair(cmd, status));
        if(status != REDIS_REPLY_STATUS)
            addResponse(cmd, response);
    }

    void addTail(const string& cmd, int sec, ...)
    {
        va_list args;
        va_start(args, sec);
        char* command;
        redis::redisvFormatCommand(&command, cmd.c_str(), args);
        TestServer::addTail(command, sec);
        redis::redisFreeCommand(command);
        va_end(args);
    }

    int getStatus(const string& cmd)
    {
        if(statuses.find(cmd) != statuses.end()) {
            return statuses[cmd];
        }
        return REDIS_REPLY_NIL;
    }

    bool getResponse(const string& cmd, AmArg& res)
    {
        while(checkTail(cmd)){}
        return TestServer::getResponse(cmd, res);
    }

    void clear() {
        statuses.clear();
        TestServer::clear();
    }
};

#endif/*REDIS_TEST_SERVER_H*/
