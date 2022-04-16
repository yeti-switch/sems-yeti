#include "HttpSequencer.h"

#include "jsonArg.h"
#include "yeti_base.h"

HttpSequencer::HttpSequencer()
{
    if(AmConfig.session_limit)
        states.reserve(AmConfig.session_limit);
}

bool HttpSequencer::postHttpRequest(const string &token, const AmArg &data)
{
    if(!AmSessionContainer::instance()->postEvent(
      HTTP_EVENT_QUEUE,
      new HttpPostEvent(
        http_destination_name,
        arg2json(data),
        token, YETI_QUEUE_NAME)))
    {
        ERROR("can't post http event. "
              "remove http_events_destination opt or configure http_client module");
        return false;
    }
    return true;
}

bool HttpSequencer::postHttpRequestNoReply(const AmArg &data)
{
    static string empty_token;
    if(!AmSessionContainer::instance()->postEvent(
      HTTP_EVENT_QUEUE,
      new HttpPostEvent(
        http_destination_name,
        arg2json(data),
        empty_token)))
    {
        ERROR("can't post http event. "
              "remove http_events_destination opt or configure http_client module");
        return false;
    }
    return true;
}

void HttpSequencer::setHttpDestinationName(const std::string &name)
{
    http_destination_name = name;
}

void HttpSequencer::serialize(AmArg &ret)
{
    AmLock l(states_mutex);
    ret.assertStruct();
    for(const auto &it : states) {
        auto &v = ret[it.first];
        v["stage"] = it.second.stage;
        v["connected_data"] = !isArgUndef(it.second.connected_data);
        v["disconnected_data"] = !isArgUndef(it.second.disconnected_data);
    }
}

void HttpSequencer::processHook(call_stage_type_t type, const string &local_tag, const AmArg &data)
{
    AmLock l(states_mutex);

    //DBG("processHook(%d, %s)", type, local_tag.data());

    switch(type) {
    case CallStarted:
        if(postHttpRequest(local_tag, data)) {
            states.emplace(local_tag, StartedHookIsQueued);
        }
        break;
    case CallConnected: {
        auto it = states.find(local_tag);
        if(it == states.end()) {
            ERROR("no sequencer state found on CallConnected http hook for %s", local_tag.data());
            return;
        }
        switch(it->second.stage) {
        case StartedHookIsQueued:
            it->second.connected_data = data;
            break;
        case StartedHookReplyReceived:
            if(postHttpRequest(local_tag, data)) {
                it->second.stage = ConnectedHookIsQueued;
            } else {
                ERROR("failed to post CallConnected after the successfull posting of CallStarted for: %s",
                      local_tag.data());
                it->second.stage = ConnectedHookReplyReceived;
            }
            break;
        default:
            ERROR("got CallConnected for sequencer in unexpected stage %d for %s",
                  it->second.stage, local_tag.data());
            break;
        }
    } break;
    case CallDisconnected: {
        auto it = states.find(local_tag);
        if(it == states.end()) {
            ERROR("no sequencer state found on CallDisconnected http hook for %s", local_tag.data());
            return;
        }
        switch(it->second.stage) {
        case StartedHookIsQueued:
        case ConnectedHookIsQueued:
            it->second.disconnected_data = data;
            break;
        case StartedHookReplyReceived:
        case ConnectedHookReplyReceived:
            postHttpRequestNoReply(data);
            states.erase(it);
            break;
        default:
            ERROR("got CallDisconnected for sequencer in unexpected stage %d for %s",
                  it->second.stage, local_tag.data());
            break;
        }
    } break;
    } //switch(type)
}

void HttpSequencer::processHttpReply(const HttpPostResponseEvent &reply)
{
    AmLock l(states_mutex);

    auto it = states.find(reply.token);
    if(it == states.end()) {
        ERROR("got http reply for nx state for session: %s", reply.token.data());
        return;
    }

    //DBG("processHttpReply for %s stage:%d", it->first.data(),it->second.stage);

    switch(it->second.stage) {
    case StartedHookIsQueued:
        if(!isArgUndef(it->second.connected_data)) {
            if(postHttpRequest(it->first, it->second.connected_data)) {
                it->second.stage = ConnectedHookIsQueued;
                return;
            } else {
                ERROR("failed to post CallConnected after the successfull posting of CallStarted for: %s",
                      it->first.data());
            }
            it->second.connected_data.clear();
        }

        if(!isArgUndef(it->second.disconnected_data)) {
            postHttpRequestNoReply(it->second.disconnected_data);
            states.erase(it);
            return;
        }

        if(it->second.invalidated) {
            states.erase(it);
            return;
        }

        it->second.stage = StartedHookReplyReceived;
        break;
    case ConnectedHookIsQueued:
        if(!isArgUndef(it->second.disconnected_data)) {
            postHttpRequestNoReply(it->second.disconnected_data);
            states.erase(it);
            return;
        }

        if(it->second.invalidated) {
            states.erase(it);
            return;
        }

        it->second.stage = ConnectedHookReplyReceived;
        break;
    default:
        ERROR("got http reply for state at unexpected stage %d for %s",
              it->second.stage, it->first.data());
        break;
    } //switch(it->second.stage)
}

void HttpSequencer::cleanup(const string &local_tag)
{
    AmLock l(states_mutex);

     auto it = states.find(local_tag);
     if(it == states.end())
        return;

     switch(it->second.stage) {
     case StartedHookIsQueued:
     case ConnectedHookIsQueued:
         //hint got processHttpReply to erase state on no more data to send
         it->second.invalidated = true;
         break;
     case StartedHookReplyReceived:
     case ConnectedHookReplyReceived:
         //sequencer waits for new hooks but they will never be executed
         states.erase(it);
         break;
     }
}
