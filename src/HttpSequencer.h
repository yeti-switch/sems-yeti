#pragma once

#include <AmThread.h>
#include "ampi/HttpClientAPI.h"

#include <string>
#include <map>

class HttpSequencer {

    enum sequencer_stage_t {
        StartedHookIsQueued = 0,
        StartedHookReplyReceived,
        ConnectedHookIsQueued,
        ConnectedHookReplyReceived
    };

    struct sequencer_state_t {
        sequencer_stage_t stage;

        AmArg connected_data;
        AmArg disconnected_data;

        sequencer_state_t(sequencer_stage_t initial_stage)
          : stage(initial_stage)
        {}
    };

    using states_t = map<string, sequencer_state_t>;
    states_t states;
    AmMutex states_mutex;

    string http_destination_name;

    //true if posted successfully
    bool postHttpRequest(const string &token, const AmArg &data);

  public:
    enum call_stage_type_t {
        CallStarted = 0,
        CallConnected,
        CallDisconnected
    };

    void setHttpDestinationName(const std::string &queue_name);
    void serialize(AmArg &ret);

    void processHook(call_stage_type_t type, const string &local_tag, const AmArg &data);
    void processHttpReply(const HttpPostResponseEvent &reply);
};
