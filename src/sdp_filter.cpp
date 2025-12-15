#include "sdp_filter.h"
#include "log.h"

#include <algorithm>
#include "SDPFilter.h"
#include "CodecsGroup.h"
#include "CodesTranslator.h"
#include "CallLeg.h"

#define DBG_SDP_PROCESSING

#if defined DBG_SDP_PROCESSING
#define DBG_SDP_PAYLOAD(payload, prefix) dump_SdpPayload(payload, prefix)
#define DBG_SDP_MEDIA(media, prefix)     dump_SdpMedia(media, prefix)
#define DBG_SDP(sdp, prefix)             dump_Sdp(sdp, prefix)
#else
#define DBG_SDP_PAYLOAD(payload, prefix) ;
#define DBG_SDP_MEDIA(media, prefix)     ;
#define DBG_SDP(sdp, prefix)             ;
#endif

const char *conn_location2str(int location_id)
{
    static const char *both         = "both";
    static const char *session_only = "session_only";
    static const char *media_only   = "media_only";
    static const char *unknown      = "unknown";
    switch (location_id) {
    case BOTH:         return both; break;
    case SESSION_ONLY: return session_only; break;
    case MEDIA_ONLY:   return media_only; break;
    default:           return unknown; break;
    }
}

int AmMimeBody2Sdp(const AmMimeBody &body, AmSdp &sdp)
{
    const AmMimeBody *sdp_body = body.hasContentType(SIP_APPLICATION_SDP);
    if (!sdp_body)
        return -1;
    int res = sdp.parse((const char *)sdp_body->getPayload());
    if (0 != res) {
        DBG("%s() SDP parsing failed: %d", FUNC_NAME, res);
        return res;
    }
    return 0;
}

void dump_SdpPayload(const vector<SdpPayload> &p, const string &prefix)
{
    DBG("        dump SdpPayloads %s %p:", prefix.c_str(), &p);
    if (!p.size()) {
        DBG("            empty payloads container");
        return;
    }
    for (std::vector<SdpPayload>::const_iterator p_it = p.begin(); p_it != p.end(); p_it++) {
        const SdpPayload &s = *p_it;
        /*DBG("    type: %d, payload_type: %d, encoding_name: '%s'', format: '%s'', sdp_format_parameters: '%s'",
            s.type,s.payload_type,s.encoding_name.c_str(),
            s.format.c_str(),s.sdp_format_parameters.c_str());*/
        DBG("            %d %s '%s'/'%s'", s.payload_type, s.encoding_name.c_str(), s.format.c_str(),
            s.sdp_format_parameters.c_str());
    }
}

void dump_SdpMedia(const vector<SdpMedia> &m, const string &prefix)
{
    DBG("DUMP SdpMedia %s %p:", prefix.c_str(), &m);
    if (m.empty()) {
        DBG("    SdpMedia %s is empty", prefix.c_str());
        return;
    }

    unsigned stream_idx = 0;
    for (vector<SdpMedia>::const_iterator j = m.begin(); j != m.end(); ++j) {
        const SdpMedia &media = *j;
        DBG("    media[%p] conn = %s, transport = %s", &media, media.conn.debugPrint().c_str(),
            transport_p_2_str(media.transport).data());
        if (media.type == MT_AUDIO) {
            DBG("    sdpmedia '%s' audio stream %d, port %d:", prefix.c_str(), stream_idx, media.port);
            dump_SdpPayload(j->payloads, prefix);
            stream_idx++;
        } else {
            DBG("    sdpmedia '%s' %s stream, port %d", prefix.c_str(), media.type2str(media.type).c_str(), media.port);
        }
    }
}

void dump_Sdp(const AmSdp &sdp, const string &prefix)
{
    DBG("DUMP Sdp %s %p:", prefix.c_str(), &sdp);
    DBG("    sdp[%p] conn = %s", &sdp, sdp.conn.debugPrint().c_str());
    dump_SdpMedia(sdp.media, prefix);
}

static const SdpPayload *findPayload(const std::vector<SdpPayload> &payloads, const SdpPayload &payload, int transport)
{
// #define DBG_FP(...) DBG(__VA_ARGS__)
#define DBG_FP(...) ;

    string pname = payload.encoding_name;
    transform(pname.begin(), pname.end(), pname.begin(), ::tolower);

    DBG_FP("findPayload: payloads[%p] transport = %d, payload = {%d,'%s'/%d/%d}", &payloads, transport,
           payload.payload_type, payload.encoding_name.c_str(), payload.clock_rate, payload.encoding_param);

    bool static_payload =
        ((transport == TP_RTPAVP || transport == TP_RTPAVPF || transport == TP_RTPSAVP || transport == TP_RTPSAVPF ||
          transport == TP_UDPTLSRTPSAVP || transport == TP_UDPTLSRTPSAVPF) &&
         payload.payload_type >= 0 && payload.payload_type < DYNAMIC_PAYLOAD_TYPE_START);

    for (const auto &p : payloads) {
        DBG_FP("findPayload: next payload payload = {%d,'%s'/%d/%d}", p->payload_type, p->encoding_name.c_str(),
               p->clock_rate, p->encoding_param);

        // fix for clients using non-standard names for static payload type (SPA504g: G729a)
        if (static_payload) {
            if (payload.payload_type != p.payload_type) {
                string s = p.encoding_name;
                transform(s.begin(), s.end(), s.begin(), ::tolower);
                if (s != pname) {
                    DBG_FP("findPayload: static payload. types not matched. names not matched");
                    continue;
                }
            }
        } else {
            string s = p.encoding_name;
            transform(s.begin(), s.end(), s.begin(), ::tolower);
            if (s != pname) {
                DBG_FP("findPayload: dynamic payload. names not matched");
                continue;
            }
        }
        if (p.clock_rate > 0 && (p.clock_rate != payload.clock_rate)) {
            DBG_FP("findPayload: clock rates not matched");
            continue;
        }
        if ((p.encoding_param >= 0) && (payload.encoding_param >= 0) && (p.encoding_param != payload.encoding_param)) {
            DBG_FP("findPayload: encoding params not matched");
            continue;
        }
        DBG_FP("findPayload: payloads matched");
        return &p;
    }

    return nullptr;
#undef DBG_FP
}

static bool containsPayload(const std::vector<SdpPayload> &payloads, const SdpPayload &payload, int transport)
{
    return findPayload(payloads, payload, transport) != NULL;
}

static bool all_media_conn_equal(const AmSdp &sdp, SdpConnection &conn)
{
    bool all_is_equal = true;
    for (std::vector<SdpMedia>::const_iterator m = sdp.media.begin(); m != sdp.media.end(); ++m) {
        const SdpConnection &c = m->conn;
        if (!c.address.empty()) {
            if (conn.address.empty()) {
                conn = c;
                continue;
            } else if (!(conn == c)) {
                DBG("%s mismatched with %s", conn.debugPrint().c_str(), c.debugPrint().c_str());
                all_is_equal = false;
                break;
            }
        }
    }

    return all_is_equal;
}

static bool assert_session_conn(AmSdp &sdp)
{
    if (!sdp.conn.address.empty())
        return true; // already have session conn

    bool have_session_level = false;

    if (sdp.media.size() > 1) {
        // we have several streams. check conn eq for them
        // it's cheking for global conn line possibility
        SdpConnection conn;
        bool          all_is_equal = all_media_conn_equal(sdp, conn);
        if (all_is_equal && !conn.address.empty()) {
            sdp.conn           = conn;
            have_session_level = true;
            DBG("propagate media level conn %s to session level", sdp.conn.debugPrint().c_str());
        }
    } else {
        // just [0..1] stream. propagate it's address to the session level
        if (sdp.media.size()) {
            const SdpConnection &conn = sdp.media.begin()->conn;
            if (!conn.address.empty()) {
                sdp.conn           = conn;
                have_session_level = true;
                DBG("propagate media level conn %s to session level", sdp.conn.debugPrint().c_str());
            }
        }
    }

    return have_session_level;
}

static void fix_media_activity(AmSdp &sdp)
{
    HoldMethod method;

    if (!isHoldRequest(sdp, method))
        return;

    for (auto &m : sdp.media) {
        // sendonly -> recvonly
        if (m.send && !m.recv) {
            m.send = false;
            m.recv = true;
        }
    }
}

static bool assert_media_conn(AmSdp &sdp)
{
    if (sdp.conn.address.empty()) {
        DBG("assert_media_conn no session level conn");
        return false; // no session level conn. give up
    }

    bool changed    = false;
    int  stream_idx = 0;
    for (std::vector<SdpMedia>::iterator m = sdp.media.begin(); m != sdp.media.end(); ++m, ++stream_idx) {
        if (m->conn.address.empty()) {
            m->conn = sdp.conn;
            changed = true;
            DBG("propagate session level %s for media stream %d", sdp.conn.debugPrint().c_str(), stream_idx);
        }
    }

    return changed;
}

static void remove_media_conn(AmSdp &sdp)
{
    int stream_idx = 0;
    for (std::vector<SdpMedia>::iterator m = sdp.media.begin(); m != sdp.media.end(); ++m, ++stream_idx) {
        if (!m->conn.address.empty()) {
            DBG("remove conn %s from media stream %d", m->conn.debugPrint().c_str(), stream_idx);
            m->conn = SdpConnection();
        }
    }
}

void normalize_conn_location(AmSdp &sdp, int location_id)
{
    DBG("normalise_conn_location(%p,%s)", &sdp, conn_location2str(location_id));
    switch (location_id) {
    case BOTH:
    {
        assert_session_conn(sdp);
        assert_media_conn(sdp);
    } break;
    case SESSION_ONLY:
    {
        if (assert_session_conn(sdp)) {
            // we got session level conn. clean conn from all streams
            remove_media_conn(sdp);
        }
    } break;
    case MEDIA_ONLY:
    {
        assert_session_conn(sdp);
        assert_media_conn(sdp);
        sdp.conn = SdpConnection();
    } break;
    default: ERROR("unknown conn_location_id = %d", location_id);
    }
}

void clear_ice_params(AmSdp &sdp)
{
    sdp.ice_pwd.clear();
    sdp.ice_ufrag.clear();
    sdp.use_ice = false;
    for (auto &m : sdp.media) {
        m.ice_pwd.clear();
        m.ice_ufrag.clear();
        m.ice_candidate.clear();
        m.is_ice = false;
    }
}

inline void clear_zrtp_params(AmSdp &sdp)
{
    if (sdp.media.empty())
        return;
#ifdef WITH_ZRTP
    for (auto &m : sdp.media) {
        m.zrtp_hash.is_use = false;
        m.zrtp_hash.hash.clear();
    }
#endif
}

inline bool is_telephone_event(const SdpPayload &p)
{
    string c = p.encoding_name;
    std::transform(c.begin(), c.end(), c.begin(), ::toupper);
    return (c == DTMF_ENCODING_NAME);
}

int filter_arrange_SDP(AmSdp &sdp, const std::vector<SdpPayload> &static_payloads, bool add_codecs, int ptime)
{
    // DBG("filter_arrange_SDP() add_codecs = %s", add_codecs?"yes":"no");

    bool media_line_filtered_out = false;
    bool media_line_left         = false;

    DBG_SDP(sdp, "filter_arrange_SDP_in");

    for (vector<SdpMedia>::iterator m_it = sdp.media.begin(); m_it != sdp.media.end(); m_it++) { // iterate over
                                                                                                 // SdpMedia
        vector<SdpPayload> new_pl;
        SdpMedia          &media = *m_it;

        if (media.type != MT_AUDIO) { // skip non audio media
            continue;
        }

        // check ptime
        if (ptime && media.frame_size != ptime) {
            DBG("override ptime from %d to %d", media.frame_size, ptime);
            media.frame_size = ptime;
        }

        for (vector<SdpPayload>::const_iterator f_it = static_payloads.begin(); f_it != static_payloads.end(); ++f_it)
        { // iterate over arranged(!) filter entries
            const SdpPayload *p = findPayload(media.payloads, *f_it, media.transport);
            if (p != NULL) {
                /*! TODO: should be changed to replace with params from codec group */
                if (add_codecs) {
                    SdpPayload new_p = *p;
                    new_p.format.clear();
                    // override sdp_format_parameters and encoding_name from static codecs
                    new_p.sdp_format_parameters = f_it->sdp_format_parameters;
                    new_p.encoding_name         = f_it->encoding_name;
                    // override payload_type
                    if (new_p.payload_type >= DYNAMIC_PAYLOAD_TYPE_START && f_it->payload_type != -1) {
                        new_p.payload_type = f_it->payload_type;
                    }
                    new_pl.push_back(new_p);
                } else {
                    new_pl.push_back(*p);
                }
            } else if (add_codecs) {
                new_pl.push_back(*f_it);
            }
        }
        // dump_SdpPayload(new_pl);

        if ((!new_pl.size() && media.payloads.size())                      // no payloads remained after filtering
            || (new_pl.size() == 1 && is_telephone_event(new_pl.front()))) // the last payload is telephone-event
        {
            new_pl.push_back(*media.payloads.begin());
            media.port              = 0;
            media_line_filtered_out = true;
        } else {
            media_line_left = true;
        }

        media.payloads = new_pl;
    }

    DBG_SDP(sdp, "filter_arrange_SDP_out");

    if ((!media_line_left) && media_line_filtered_out) {
        DBG("all streams were marked as inactive");
        return FC_CODECS_NOT_MATCHED;
    }

    return 0;
}

int filterNoAudioStreams(AmSdp &sdp, bool filter)
{
    if (!filter)
        return 0;

    bool have_audio_stream = false;
    for (std::vector<SdpMedia>::iterator m_it = sdp.media.begin(); m_it != sdp.media.end(); m_it++) {
        SdpMedia &media = *m_it;
        if (media.type != MT_AUDIO) {
            media.port = 0;
            continue;
        }
        have_audio_stream = true;
    }

    if (!have_audio_stream) {
        DBG("no audio streams after non-audio streams filtering");
        return FC_NO_SUITABLE_MEDIA;
    }

    return 0;
}

int cutNoAudioStreams(AmSdp &sdp, bool cut)
{
    if (!cut)
        return 0;

    vector<SdpMedia> new_media;

    for (vector<SdpMedia>::iterator m_it = sdp.media.begin(); m_it != sdp.media.end(); m_it++) {
        SdpMedia &m = *m_it;
        if (m.type == MT_AUDIO) {
            new_media.push_back(m);
        }
    }

    if (!new_media.size()) {
        return FC_NO_SUITABLE_MEDIA;
    }

    sdp.media = new_media;
    return 0;
}

// add payload into payloads list with checking
inline void add_codec(std::vector<SdpPayload> &pl, const SdpPayload &p, bool single_codec)
{
    if (!single_codec ||                                      // single codec not enabled
        pl.empty() ||                                         // no payloads added yet
        (pl.size() == 1 && is_telephone_event(pl.front())) || // payloads no empty but contain telephone-event (for
                                                              // cases when telephone-event added first)
        is_telephone_event(p)) // telephone-event can be added even if we already have payload
    {
        DBG("add_codec: add payload: '%s', pl.size = %ld, ", p.encoding_name.c_str(), pl.size());
        pl.push_back(p);
    }
}

inline void reduce_codecs_to_single(std::vector<SdpMedia> &media)
{
    for (vector<SdpMedia>::iterator m_it = media.begin(); m_it != media.end(); ++m_it) {
        SdpMedia &m = *m_it;

        if (m.type != MT_AUDIO)
            continue;

        std::vector<SdpPayload> new_pl;
        for (std::vector<SdpPayload>::const_iterator p_it = m.payloads.begin(); p_it != m.payloads.end(); p_it++) {
            add_codec(new_pl, *p_it, true);
        }
        m.payloads = new_pl;
    }
}

void apply_sdp_to_body(AmMimeBody &body, AmMimeBody *sdp_body, AmSdp &sdp, bool reduce_to_singlepart_sdp = false)
{
    string n_body;
    sdp.print(n_body);

    if (reduce_to_singlepart_sdp) {
        body.clear();
        body.parse(SIP_APPLICATION_SDP, (const unsigned char *)n_body.c_str(), n_body.length());
    } else {
        sdp_body->setPayload((const unsigned char *)n_body.c_str(), n_body.length());
        sdp_body->normalizeContentType();
    }
}

bool is_media_transport_equal_ignoring_avpf(TransProt lhs_noavpf, TransProt rhs)
{
    switch (rhs) {
    case TP_RTPAVP:
    case TP_RTPAVPF:        return lhs_noavpf == TP_RTPAVP;
    case TP_RTPSAVP:
    case TP_RTPSAVPF:       return lhs_noavpf == TP_RTPSAVP;
    case TP_UDPTLSRTPSAVP:
    case TP_UDPTLSRTPSAVPF: return lhs_noavpf == TP_UDPTLSRTPSAVP;
    default:                return lhs_noavpf == rhs;
    }
}

int processSdpOffer(SBCCallLeg *call, SBCCallProfile &call_profile, AmMimeBody &body, string &method,
                    vector<SdpMedia> &negotiated_media, int static_codecs_id, bool local, bool single_codec)
{
    DBG("processSdpOffer() method = %s", method.c_str());

    AmMimeBody *sdp_body = body.hasContentType(SIP_APPLICATION_SDP);
    if (!sdp_body)
        return 0;

    if (!(method == SIP_METH_INVITE || method == SIP_METH_UPDATE || method == SIP_METH_PRACK || method == SIP_METH_ACK))
    {
        return 0;
    }

    AmSdp sdp;
    int   res = sdp.parse((const char *)sdp_body->getPayload());
    if (0 != res) {
        DBG("SDP parsing failed during body filtering!");
        return DC_REPLY_SDP_PARSING_FAILED;
    }

    if (local) {
        // check if sdp offer can be processed locally
        auto m_it = sdp.media.begin();
        for (const auto &m : negotiated_media) {
            if (m_it == sdp.media.end()) {
                DBG("in-dialog offer contains less streams(%zd) than in negotiated_media(%zd). not acceptable",
                    sdp.media.size(), negotiated_media.size());
                return DC_REPLY_SDP_STREAMS_COUNT;
            }
            if (m.type != m_it->type) {
                DBG("in-dialog offer changes media type for stream %zd from %d to %d. not acceptable",
                    std::distance(sdp.media.begin(), m_it), m.type, m_it->type);
                return DC_REPLY_SDP_STREAMS_TYPES;
            }
            ++m_it;
        }
        // disable all additional streams from offer
        while (m_it != sdp.media.end()) {
            m_it->port = 0;
            m_it++;
        }
    }

    CodecsGroupEntry codecs_group;
    CodecsGroups::instance()->get(static_codecs_id, codecs_group);
    auto               ptime                = codecs_group.get_ptime();
    vector<SdpPayload> static_codecs_filter = codecs_group.get_payloads();

    res = filter_arrange_SDP(sdp, static_codecs_filter, false, call_profile.rtprelay_enabled ? ptime : 0);
    if (0 != res) {
        return res;
    }
    filterSDPalines(sdp, call_profile.sdpalinesfilter);

    res = filterNoAudioStreams(sdp, call_profile.filter_noaudio_streams);
    if (0 != res) {
        return res;
    }

    if (local)
        fix_media_activity(sdp);

    if (single_codec)
        reduce_codecs_to_single(sdp.media);

    if (call_profile.rtprelay_enabled) {
        auto &first_media = *sdp.media.begin();
        if (first_media.type == MT_AUDIO) {
            const auto &media_transport =
                call->isALeg() ? call_profile.aleg_media_transport : call_profile.bleg_media_transport;
            if (!is_media_transport_equal_ignoring_avpf(media_transport, first_media.transport)) {
                DBG("got offer transport type %s while expected %s", transport_p_2_str(first_media.transport).data(),
                    transport_p_2_str(media_transport).data());
                return FC_INVALID_MEDIA_TRANSPORT;
            }
#ifdef WITH_ZRTP
            if (TP_RTPAVP == media_transport || TP_RTPAVPF == media_transport) {
                const auto &zrtp_enabled =
                    call->isALeg() ? call_profile.aleg_media_allow_zrtp : call_profile.bleg_media_allow_zrtp;
                if (zrtp_enabled && !first_media.zrtp_hash.is_use) {
                    DBG("got SDP offer without zrtp_hash while ZRTP is enabled for leg");
                    return FC_INVALID_MEDIA_TRANSPORT;
                }
            }
#endif
        }
    }

    // save negotiated result for the future usage
    negotiated_media = sdp.media;

    DBG_SDP_PAYLOAD(static_codecs_filter, "static_codecs_filter");
    DBG_SDP(sdp, "negotiateRequestSdp");

    apply_sdp_to_body(body, sdp_body, sdp, false);

    return res;
}

/* modifies dst_payloads payload_type
 * - to ensure that all payloads from dst_payloads which are exist in ref_payloads
 *   have the same payload_type as related payload in ref_payloads
 * - replaced all payloads_type < 0 with the related reference payload_type
 *   or with the first free dynamic one
 */
void replaceDynamicPayloads(std::vector<SdpPayload>       &dst_payloads,
                            const std::vector<SdpPayload> *ref_payloads = nullptr, int transport = 0)
{
    std::map<int, int> dst_used_dynamic_payloads;

    int dst_payload_idx = 0;
    for (const auto &p : dst_payloads) {
        if (p.payload_type >= DYNAMIC_PAYLOAD_TYPE_START)
            dst_used_dynamic_payloads.emplace(p.payload_type, dst_payload_idx);
        dst_payload_idx++;
    }

    dst_payload_idx = 0;
    for (auto &dst_pl : dst_payloads) {
        if (dst_pl.payload_type < 0) {
            // find first free dynamic payload_type
            int new_dynamic_pl_type = DYNAMIC_PAYLOAD_TYPE_START;
            while (dst_used_dynamic_payloads.contains(new_dynamic_pl_type))
                new_dynamic_pl_type++;

            DBG("assign dynamic payload id for %s/%d: %d -> %d", dst_pl.encoding_name.c_str(), dst_pl.clock_rate,
                dst_pl.payload_type, new_dynamic_pl_type);

            dst_pl.payload_type = new_dynamic_pl_type;
            dst_used_dynamic_payloads.emplace(dst_pl.payload_type, dst_payload_idx);

            // continue processing to check against reference payloads
        } else if (dst_pl.payload_type < DYNAMIC_PAYLOAD_TYPE_START) {
            // skip static payloads processing
            dst_payload_idx++;
            continue;
        }

        if (!ref_payloads) {
            // no lookup in reference payloads
            dst_payload_idx++;
            continue;
        }

        auto ref_pl = findPayload(*ref_payloads, dst_pl, transport);
        if (!ref_pl) {
            dst_payload_idx++;
            continue;
        }

        auto ref_payload_type = ref_pl->payload_type;
        if (ref_payload_type == dst_pl.payload_type) {
            dst_payload_idx++;
            continue;
        }

        /* dst payload type differs from the reference payload type
         * check for the conflicts over dst payloads before replacement */
        auto conflicting_dst_pl_it = dst_used_dynamic_payloads.find(ref_payload_type);
        if (conflicting_dst_pl_it != dst_used_dynamic_payloads.end()) {
            // move conflicting payload to the payload id to be replaced with reference one
            auto  conflicting_pl_idx = conflicting_dst_pl_it->second;
            auto &conflicting_pl     = dst_payloads.at(conflicting_pl_idx);
            DBG("replace dynamic payload id for %s/%d: %d -> %d "
                "to resolve payload_type conflict",
                conflicting_pl.encoding_name.c_str(), conflicting_pl.clock_rate, conflicting_pl.payload_type,
                dst_pl.payload_type);

            conflicting_pl.payload_type = dst_pl.payload_type;

            dst_used_dynamic_payloads.erase(ref_payload_type);
            dst_used_dynamic_payloads.at(conflicting_pl.payload_type) = conflicting_pl_idx;
        }

        // update current dst payload with the reference payload type
        DBG("replace dynamic payload id for %s/%d: %d -> %d "
            "to match the reference payload",
            dst_pl.encoding_name.c_str(), dst_pl.clock_rate, dst_pl.payload_type, ref_payload_type);

        dst_pl.payload_type = ref_payload_type;
        dst_used_dynamic_payloads.emplace(dst_pl.payload_type, dst_payload_idx);
    }
}

void fixDynamicPayloads(AmSdp &sdp, const vector<SdpMedia> *reference_media)
{
    auto audio_stream_predicate = [](const SdpMedia &m) -> bool { return m.type == MT_AUDIO; };

    vector<SdpMedia>::const_iterator ref_it;
    if (reference_media && reference_media->size()) {
        const auto &media = *reference_media;
        // get first audio stream from the negotiated_media
        ref_it = std::find_if(media.begin(), media.end(), audio_stream_predicate);
    }

    for (auto &media : sdp.media) {
        if (media.type != MT_AUDIO)
            continue;

        if (reference_media && ref_it != reference_media->end()) {
            replaceDynamicPayloads(media.payloads, &ref_it->payloads, media.transport);

            ++ref_it;
            // skip no-audio streams in the negotiated_media
            ref_it = std::find_if(ref_it, reference_media->end(), audio_stream_predicate);
        } else {
            replaceDynamicPayloads(media.payloads);
        }
    }
}

int filterSdpOffer(SBCCallLeg *call, _AmSipMsgInDlg &sip_msg, SBCCallProfile &call_profile, AmMimeBody &body,
                   string &method, int static_codecs_id, const std::vector<SdpMedia> *negotiated_media, AmSdp *out_sdp)
{
    bool a_leg = call->isALeg();
    DBG("filterSdpOffer() a_leg = %d method = %s", a_leg, method.c_str());
    if (body.empty())
        return 0;

    AmMimeBody *sdp_body = body.hasContentType(SIP_APPLICATION_SDP);
    if (!sdp_body)
        return 0;

    // filter body for given methods only
    if (!(method == SIP_METH_INVITE || method == SIP_METH_UPDATE || method == SIP_METH_PRACK || method == SIP_METH_ACK))
    {
        // DBG("filterRequestSdp() ignore method");
        return 0;
    }

    AmSdp sdp;
    int   res = sdp.parse((const char *)sdp_body->getPayload());
    if (0 != res) {
        ERROR("filterSdpOffer() SDP parsing failed during body filtering!");
        return DC_REPLY_SDP_PARSING_FAILED;
    }

    DBG_SDP(sdp, "filterSdpOffer_in");

    if (call_profile.rtprelay_enabled) {
        normalizeSDP(sdp);
        call->normalizeSdpVersion(sdp.origin.sessV, sip_msg.cseq, true);
    }

    CodecsGroupEntry codecs_group;
    CodecsGroups::instance()->get(static_codecs_id, codecs_group);
    auto                     ptime         = codecs_group.get_ptime();
    std::vector<SdpPayload> &static_codecs = codecs_group.get_payloads();

    res = filter_arrange_SDP(sdp, static_codecs,
                             call_profile.rtprelay_enabled /*  do not add new codecs if media proxifying is disabled */,
                             call_profile.rtprelay_enabled ? ptime : 0);
    if (0 != res)
        return res;

    if (call_profile.rtprelay_enabled) {
        fixDynamicPayloads(sdp, negotiated_media);

        filterSDPalines(sdp, a_leg ? call_profile.sdpalinesfilter : call_profile.bleg_sdpalinesfilter);
        clear_ice_params(sdp);
        clear_zrtp_params(sdp);

        res = cutNoAudioStreams(sdp, call_profile.filter_noaudio_streams);
        if (0 != res) {
            ERROR("filterSdpOffer() no streams after no audio streams filtering");
            return res;
        }

        // append missing streams from negotiated_media
        if (negotiated_media != nullptr) {
            auto m_it = sdp.media.begin();
            for (const auto &m : *negotiated_media) {
                if (m_it == sdp.media.end()) {
                    sdp.media.emplace_back(m);
                    m_it = sdp.media.end();
                    continue;
                }

                ++m_it;
            }
        }

        normalize_conn_location(sdp, a_leg ? call_profile.bleg_conn_location_id : call_profile.aleg_conn_location_id);
    }

    DBG_SDP(sdp, "filterSdpOffer_out");

    if (out_sdp)
        *out_sdp = sdp;

    apply_sdp_to_body(body, sdp_body, sdp, true /* TODO: get it from the callprofile */);

    return res;
}

static void filterSdpAnswerMedia(SBCCallLeg *call, vector<SdpMedia> &negotiated_media, std::vector<SdpMedia> &media,
                                 bool noaudio_streams_filtered, bool avoid_transcoding, bool single_codec, int ptime)
{
    int  override_id = 0;
    auto call_ctx    = call->getCallCtx();
    if (call_ctx) {
        override_id = call_ctx->getOverrideId();
    }

    if (negotiated_media.size()) {
        vector<SdpMedia> filtered_sdp_media;

        if (!media.size()) {
            ERROR("processSdpAnswer() [%s] empty answer sdp", call->getLocalTag().c_str());
            throw InternalException(DC_REPLY_SDP_EMPTY_ANSWER, override_id);
        }

        // check for streams count
        if (negotiated_media.size() != media.size()) {
            if (noaudio_streams_filtered) {

                // count audio streams for negotiated_media
                unsigned int nm_audio_streams = 0;
                for (vector<SdpMedia>::const_iterator it = negotiated_media.begin(); it != negotiated_media.end(); ++it)
                {
                    if (it->type == MT_AUDIO)
                        nm_audio_streams++;
                }

                // count audio streams for media
                unsigned int m_audio_streams = 0;
                for (vector<SdpMedia>::const_iterator it = media.begin(); it != media.end(); ++it) {
                    if (it->type == MT_AUDIO)
                        m_audio_streams++;
                }

                if (m_audio_streams != nm_audio_streams) {
                    ERROR("processSdpAnswer()[%s] audio streams count not equal reply: %lu, saved: %u)",
                          call->getLocalTag().c_str(), m_audio_streams, nm_audio_streams);
                    throw InternalException(DC_REPLY_SDP_STREAMS_COUNT, override_id);
                }
            } else {
                ERROR("processSdpAnswer()[%s] streams count not equal reply: %lu, saved: %lu)",
                      call->getLocalTag().c_str(), media.size(), negotiated_media.size());
                throw InternalException(DC_REPLY_SDP_STREAMS_COUNT, override_id);
            }
        }

        int                              stream_idx     = 0;
        vector<SdpMedia>::const_iterator other_media_it = negotiated_media.begin();
        vector<SdpMedia>::iterator       m_it           = media.begin();
        // while(m_it !=sdp.media.end())
        while (other_media_it != negotiated_media.end()) {
            if (noaudio_streams_filtered && other_media_it->type != MT_AUDIO) {
                /* skip non_audio streams in negotiated media (which were filtered in FilteRequestSdp)
                 * and add them to reply */
                DBG("add non-audio stream '%s' from netogitated media",
                    SdpMedia::type2str(other_media_it->type).c_str());
                filtered_sdp_media.push_back(*other_media_it);
                ++other_media_it;
                continue;
            }

            if (m_it == media.end()) {
                ERROR("unexpected reply sdp");
                break;
            }

            const SdpMedia &other_m = *other_media_it;
            SdpMedia       &m       = *m_it;

            /* check for streams types */
            if (m.type != other_m.type) {
                ERROR("processSdpAnswer() [%s] streams types not matched idx = %d", call->getLocalTag().c_str(),
                      stream_idx);
                DBG_SDP_PAYLOAD(other_m.payloads, "other_m payload " + int2str(stream_idx));
                throw InternalException(DC_REPLY_SDP_STREAMS_TYPES, override_id);
            }

            if (m.type != MT_AUDIO) {
                DBG("add non-audio stream '%s' from reply", SdpMedia::type2str(other_m.type).c_str());
                filtered_sdp_media.push_back(m); // add non-skipped noaudio streams as is
                ++m_it;
                ++other_media_it;
                continue;
            }

            if (m.transport != other_m.transport) {
                DBG("patch answer media transport: %s -> %s", transport_p_2_str(m.transport).data(),
                    transport_p_2_str(other_m.transport).data());
                m.transport = other_m.transport;
            }

            DBG_SDP_PAYLOAD(m.payloads, "m.payloads");
            DBG_SDP_PAYLOAD(other_m.payloads, "other_m.payloads");

            std::vector<SdpPayload> new_pl;
            if (!avoid_transcoding) {
                // clear all except of first codec and dtmf
                std::vector<SdpPayload>::const_iterator p_it = other_m.payloads.begin();
                for (; p_it != other_m.payloads.end(); p_it++) {
                    add_codec(new_pl, *p_it, single_codec);
                }
            } else {
                // arrange previously negotiated codecs according to received sdp

                /* fill with codecs from received sdp
                 * which exists in negotiated payload */
                std::vector<SdpPayload>::const_iterator f_it = m.payloads.begin();
                for (; f_it != m.payloads.end(); f_it++) {
                    const SdpPayload *p = findPayload(other_m.payloads, *f_it, m.transport);
                    if (p != NULL) {
                        add_codec(new_pl, *p, single_codec);
                    }
                }
                /* add codecs from negotiated payload
                 * which doesn't exists in recevied sdp
                 * to the tail */
                std::vector<SdpPayload>::const_iterator p_it = other_m.payloads.begin();
                for (; p_it != other_m.payloads.end(); p_it++) {
                    if (!containsPayload(m.payloads, *p_it, m.transport)) {
                        add_codec(new_pl, *p_it, single_codec);
                    }
                }
            }
            DBG_SDP_PAYLOAD(new_pl, "new_pl");
            m.payloads = new_pl;

            // check ptime
            if (ptime && m.frame_size != ptime) {
                DBG("override ptime from %d to %d", m.frame_size, ptime);
                m.frame_size = ptime;
            }

            DBG("add filtered audio stream %d from reply", stream_idx);
            filtered_sdp_media.push_back(m);

            ++m_it;
            ++other_media_it;
            stream_idx++;
        }

        media = filtered_sdp_media;
    } else {
        DBG("%s: no negotiated media. leave it as is", call->getLocalTag().data());
    }
}

int processSdpAnswer(SBCCallLeg *call, _AmSipMsgInDlg &sip_msg, AmMimeBody &body, const string &method,
                     vector<SdpMedia> &negotiated_media, bool single_codec, int static_codecs_id,
                     bool noaudio_streams_filtered, bool answer_is_mandatory)
{
    // filter body for given methods only
    if (!(method == SIP_METH_INVITE || method == SIP_METH_UPDATE || method == SIP_METH_PRACK || method == SIP_METH_ACK))
    {
        DBG("processSdpAnswer() ignore method");
        return 0;
    }

    bool            a_leg        = call->isALeg();
    SBCCallProfile &call_profile = call->getCallProfile();

    int  override_id = 0;
    auto call_ctx    = call->getCallCtx();
    if (call_ctx) {
        override_id = call_ctx->getOverrideId();
    }

    DBG("processSdpAnswer() method = %s, a_leg = %d, answer_is_mandatory = %d", method.c_str(), a_leg,
        answer_is_mandatory);

    if (body.empty()) {
        DBG("empty body");
        if (answer_is_mandatory)
            throw InternalException(DC_REPLY_SDP_EMPTY_ANSWER, override_id);
        return 0;
    }

    AmMimeBody *sdp_body = body.hasContentType(SIP_APPLICATION_SDP);
    if (!sdp_body) {
        DBG("no SDP in body");
        if (answer_is_mandatory)
            throw InternalException(DC_REPLY_SDP_EMPTY_ANSWER, override_id);
        return 0;
    }

    AmSdp sdp;
    int   res = sdp.parse((const char *)sdp_body->getPayload());
    if (0 != res) {
        ERROR("processSdpAnswer()[%s] SDP parsing failed during body filtering!", call->getLocalTag().c_str());
        throw InternalException(DC_REPLY_SDP_PARSING_FAILED, override_id);
    }

    DBG_SDP_MEDIA(negotiated_media, "processSdpAnswer_negotiated_media");
    DBG_SDP_MEDIA(sdp.media, "processSdpAnswer_in");

    if (call_profile.rtprelay_enabled) {
        normalizeSDP(sdp);
        call->normalizeSdpVersion(sdp.origin.sessV, sip_msg.cseq, false);

        int ptime = 0;
        if (call_profile.rtprelay_enabled) {
            CodecsGroupEntry codecs_group;
            CodecsGroups::instance()->get(static_codecs_id, codecs_group);
            ptime = codecs_group.get_ptime();
        }

        filterSdpAnswerMedia(call, negotiated_media, sdp.media, noaudio_streams_filtered,
                             call_profile.avoid_transcoding, single_codec, ptime);

        fixDynamicPayloads(sdp, &negotiated_media);

        filterSDPalines(sdp, a_leg ? call_profile.sdpalinesfilter : call_profile.bleg_sdpalinesfilter);

        normalize_conn_location(sdp, a_leg ? call_profile.bleg_conn_location_id : call_profile.aleg_conn_location_id);

        clear_ice_params(sdp);
        clear_zrtp_params(sdp);
    }

    DBG_SDP_MEDIA(sdp.media, "processSdpAnswer_out");

    negotiated_media = sdp.media;

    apply_sdp_to_body(body, sdp_body, sdp, true /* TODO: get it from the callprofile */);

    return 0;
}
