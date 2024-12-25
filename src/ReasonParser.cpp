#include "ReasonParser.h"
#include "HeaderFilter.h"
#include "log.h"

#include <cstring>
#include <limits>

const std::string reason_header_value("reason");

void ReasonParser::Reason::serialize(AmArg &ret)
{
    ret["cause"] = cause;
    if(!text.empty())
        ret["text"] = text;
    if(!params.empty())
        ret["params"] = params;
}

void ReasonParser::parse_reason(const std::string &hdrs, size_t reason_begin, size_t reason_end)
{
    /* https://www.rfc-editor.org/rfc/rfc3326#section-2
     *
     * Reason            =  "Reason" HCOLON reason-value *(COMMA reason-value)
     * reason-value      =  protocol *(SEMI reason-params)
     * protocol          =  "SIP" / "Q.850" / token
     * reason-params     =  protocol-cause / reason-text / reason-extension
     * protocol-cause    =  "cause" EQUAL cause
     * cause             =  1*DIGIT
     * reason-text       =  "text" EQUAL quoted-string
     * reason-extension  =  generic-param
     *
     *  Reason: SIP ;cause=200 ;text="Call completed elsewhere"
     *  Reason: Q.850 ;cause=16 ;text="Terminated"
     *  Reason: SIP ;cause=600 ;text="Busy Everywhere"
     *  Reason: SIP ;cause=580 ;text="Precondition Failure"
     */

    /*DBG(">> parse Reason header: %s",
        hdrs.substr(reason_begin, reason_end - reason_begin).data());*/

    auto pos = hdrs.find_first_not_of(' ', reason_begin);

    char last_c = 0;
    string::size_type name_start_pos {}, name_end_pos {},
                      value_start_pos {}, value_end_pos {};
    enum {
        ST_START,
        ST_NAME_SKIP_WS_BEFORE, ST_NAME, ST_NAME_SKIP_WS_AFTER,
        ST_VALUE_SKIP_WS_BEFORE, ST_VALUE, ST_ESCAPED_VALUE, ST_VALUE_SKIP_WS_AFTER
    } st = ST_START;

    bool wait_for_proto_name = true;

    static string reason_proto_sip("SIP");
    static string reason_proto_q850("Q.850");
    static string reason_param_cause("cause");
    static string reason_param_text("text");

    Reason *current_reason = nullptr;

    auto on_name = [&]() -> void {
        /*DBG(">> got name: '%.*s'",
            name_end_pos - name_start_pos, hdrs.c_str() + name_start_pos);*/
        if(wait_for_proto_name) {
            wait_for_proto_name = false;

            //check proto. SIP/Q.850
            auto len = name_end_pos - name_start_pos;
            if(0==hdrs.compare(name_start_pos, len, reason_proto_sip)) {
                current_reason = &sip_reason;
            } else if (0==hdrs.compare(name_start_pos, len, reason_proto_q850)) {
                current_reason = &q850_reason;
            } else {
                current_reason = nullptr;
            }

            return;
        }

        if(!current_reason) {
            //unknown proto. skip attribute processing
            return;
        }

        //apppend unknown params
        auto &params = current_reason->params;
        if(!params.empty()) {
            params.append(";");
        }
        params.append(hdrs, name_start_pos, name_end_pos - name_start_pos);
    };

    auto on_name_value = [&]() -> bool {
        /*DBG(">> got name value: '%.*s' = '%.*s'",
            name_end_pos - name_start_pos, hdrs.c_str() + name_start_pos,
            value_end_pos - value_start_pos, hdrs.c_str() + value_start_pos);*/

        if(wait_for_proto_name) {
            //malformed Reason. reason-param before proto
            return false;
        }

        if(!current_reason) {
            //unknown proto. skip attribute processing
            return true;
        }

        //process reason and text attributes
        auto name_len = name_end_pos - name_start_pos;
        if(0==hdrs.compare(name_start_pos, name_len, reason_param_cause)) {
            if(str2int(
                hdrs.substr(value_start_pos, value_end_pos - value_start_pos),
                current_reason->cause))
            {
                current_reason->parsed = true;
            }
        } else if (0==hdrs.compare(name_start_pos, name_len, reason_param_text)) {
            current_reason->text = hdrs.substr(value_start_pos, value_end_pos - value_start_pos);
        } else {
            //append unknown reason param
            auto &params = current_reason->params;
            if(!params.empty()) {
                params.append("; ");
            }
            params.append(hdrs, name_start_pos, name_end_pos - name_start_pos);
            params.append("=");
            params.append(hdrs, value_start_pos, value_end_pos - value_start_pos);
        }

        return true;
    };

    auto process_attribute_end = [&](bool tail_processing) -> bool {
        switch(st) {
        case ST_NAME:
            st = ST_START;
            name_end_pos = pos;
            on_name();
            break;
        case ST_NAME_SKIP_WS_AFTER:
            st = ST_START;
            on_name();
            name_start_pos = pos;
            break;
        case ST_VALUE_SKIP_WS_BEFORE:
            st = ST_START;
            if(!on_name_value()) return false;
            name_start_pos = pos;
            break;
        case ST_VALUE:
            st = ST_START;
            value_end_pos = pos;
            if(!on_name_value()) return false;
            name_start_pos = pos;
            break;
        case ST_VALUE_SKIP_WS_AFTER:
            st = ST_START;
            if(!on_name_value()) return false;
            name_start_pos = pos;
            break;
        case ST_ESCAPED_VALUE:
        case ST_START:
            break;
        default:
            if (!tail_processing) {
                ERROR("unexpected comma or semicolon at %lu. hdr: %s", pos, hdrs.data());
                return false;
            }
        }
        return true;
    };

    while(pos < reason_end) {
        auto &c = hdrs[pos];
        //DBG("c: '%c' st:%d", c, st);
        switch(c) {
        case '\"':
            switch(st) {
            case ST_VALUE_SKIP_WS_BEFORE:
                st = ST_ESCAPED_VALUE;
                value_start_pos = pos+1;
                last_c = c;
                break;
            case ST_ESCAPED_VALUE:
                if(last_c != '\\') {
                    st = ST_VALUE_SKIP_WS_AFTER;
                    value_end_pos = pos;
                }
                break;
            default:
                ERROR("unexpected dquote at %lu. hdr: %s", pos, hdrs.data());
            }
            break;
        case '=':
            switch(st) {
            case ST_NAME:
                st = ST_VALUE_SKIP_WS_BEFORE;
                name_end_pos = value_start_pos = pos;
                break;
            case ST_NAME_SKIP_WS_AFTER:
                st = ST_VALUE_SKIP_WS_BEFORE;
                value_start_pos = pos;
                break;
            case ST_ESCAPED_VALUE:
                break;
            default:
                ERROR("unexpected equal sign at %lu. hdr: %s", pos, hdrs.data());
                return;
            }
            break;
        case ';':
            if(!process_attribute_end(false))
                return;
            break;
        case ',':
            if(st != ST_ESCAPED_VALUE) {
                if(!process_attribute_end(false))
                    return;
                wait_for_proto_name = true;
                current_reason = nullptr;
            }
            break;
        case ' ':
            switch(st) {
            case ST_START:
                st = ST_NAME_SKIP_WS_BEFORE;
                break;
            case ST_NAME:
                st = ST_NAME_SKIP_WS_AFTER;
                name_end_pos = pos;
                break;
            case ST_VALUE:
                st = ST_VALUE_SKIP_WS_AFTER;
                value_end_pos = pos;
                break;
            case ST_NAME_SKIP_WS_BEFORE:
            case ST_NAME_SKIP_WS_AFTER:
            case ST_VALUE_SKIP_WS_BEFORE:
            case ST_VALUE_SKIP_WS_AFTER:
            case ST_ESCAPED_VALUE:
                break;
            default:
                ERROR("unexpected space at %lu. hdr: %s", pos, hdrs.data());
                return;
            }
            break;
        default:
            switch(st) {
            case ST_START:
                st = ST_NAME;
                name_start_pos = pos;
                break;
            case ST_NAME_SKIP_WS_BEFORE:
                st = ST_NAME;
                name_start_pos = pos;
                break;
            case ST_VALUE_SKIP_WS_BEFORE:
                st = ST_VALUE;
                value_start_pos = pos;
                break;
            case ST_ESCAPED_VALUE:
                last_c = c;
                break;
            case ST_VALUE:
            case ST_NAME:
                break;
            default:
                ERROR("unexpected '%c' at %lu. hdr: %s", c, pos, hdrs.data());
                return;
            }
            break;
        } //switch(c)
        pos++;
    } //while(pos < reason_end)

    process_attribute_end(true);
}

void ReasonParser::parse_headers(const std::string &hdrs)
{
    size_t start_pos = 0, name_end, val_begin, val_end, hdr_end;
    while(start_pos < hdrs.length()) {
        if (skip_header(hdrs, start_pos,
            name_end, val_begin, val_end, hdr_end) != 0)
        {
            break;
        }

        if(0==strncasecmp(
            hdrs.c_str() + start_pos,
            reason_header_value.c_str(), name_end-start_pos))
        {
            parse_reason(hdrs, val_begin, val_end);
        }

        start_pos = hdr_end;
    }
}

bool ReasonParser::has_data(const YetiCfg::headers_processing_config::leg_reasons &cfg)
{
    return
        (sip_reason.parsed && cfg.add_sip_reason) ||
        (q850_reason.parsed && cfg.add_q850_reason);
}

void ReasonParser::serialize(
    AmArg &ret,
    const YetiCfg::headers_processing_config::leg_reasons &cfg)
{
    if(sip_reason.parsed && cfg.add_sip_reason)
        sip_reason.serialize(ret["sip"]);
    if(q850_reason.parsed && cfg.add_q850_reason)
        q850_reason.serialize(ret["q850"]);
}

inline bool validate_cause(int cause) {
    /* ensure cause value is within pg smallint
     * https://www.postgresql.org/docs/current/datatype-numeric.html */
    return cause >= std::numeric_limits<int16_t>::min() &&
           cause <= std::numeric_limits<int16_t>::max();
}

void ReasonParser::serialize_flat(
    AmArg &ret,
    const YetiCfg::headers_processing_config::leg_reasons &cfg,
    const string &local_tag)
{
    if(sip_reason.parsed && cfg.add_sip_reason) {
        if(validate_cause(sip_reason.cause)) {
            ret["sip_cause"] = sip_reason.cause;
        } else {
            WARN("[%s] SIP cause value %d is out of range for pg type smallint. use null",
                local_tag.data(), sip_reason.cause);
            ret["sip_cause"] = AmArg();
        }

        if(!sip_reason.text.empty())
            ret["sip_text"] = sip_reason.text;
        if(!sip_reason.params.empty())
            ret["sip_params"] = sip_reason.params;
    }

    if(q850_reason.parsed && cfg.add_q850_reason) {
        if(validate_cause(q850_reason.cause)) {
            ret["q850_cause"] = q850_reason.cause;
        } else {
            WARN("[%s] Q850 cause value %d is out of range for pg type smallint. use null",
                local_tag.data(), q850_reason.cause);
            ret["q850_cause"] = AmArg();
        }

        if(!q850_reason.text.empty())
            ret["q850_text"] = q850_reason.text;
        if(!q850_reason.params.empty())
            ret["q850_params"] = q850_reason.params;
    }
}
