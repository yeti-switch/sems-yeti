"""
AMR/AMR-WB codecs negotiation with transcoding.

the caller offer reproduces the one from VoLTE UE (IMS) call: AMR-WB and AMR in bandwidth-efficient
and octet-aligned modes, PCMU, PCMA and telephone-event 16000/8000.
codecs groups (etc/db_map/load_codec_groups.json):
  2 - A-leg: AMR-WB, AMR, PCMA, PCMU, telephone-event/8000
  3 - B-leg: PCMA, PCMU, telephone-event/8000
so the call is transcoded: the termination gateway gets offer without AMR and answers with PCMA.

the caller must get valid SDP answers both in 183 and 200 OK: only payloads from the offer with
the same encoding and fmtp mode, AMR-WB first. before c4579b3 the 183 SDP was not processed
at all when the legacy profile flag suppress_early_media=false was present
(gateway SDP answer was relayed to the caller as is)
"""

import pytest

from checks import assert_call_cleaned_up
from profiles import NO_ROUTES, YETI, route_to
import sdp as sdplib
from sip_ua import EarlyReply

ALEG_AMR_CODECS_GROUP = 2
BLEG_NO_AMR_CODECS_GROUP = 3

AMR_PAYLOADS = ("amr-wb/16000", "amr/8000")


def volte_offer(ip, port):
    return "\r\n".join([
        "v=0",
        f"o=IMS-UE 1270200874888 0 IN IP4 {ip}",
        "s=SS VOIP",
        "t=0 0",
        f"m=audio {port} RTP/AVP 116 107 118 96 0 8 111 110",
        f"c=IN IP4 {ip}",
        "b=AS:42",
        "b=RR:2500",
        "b=RS:0",
        "a=rtpmap:116 AMR-WB/16000",
        "a=fmtp:116 mode-change-capability=2;max-red=220",
        "a=rtpmap:107 AMR-WB/16000",
        "a=fmtp:107 octet-align=1;mode-change-capability=2;max-red=220",
        "a=rtpmap:118 AMR/8000",
        "a=fmtp:118 mode-change-capability=2;max-red=220",
        "a=rtpmap:96 AMR/8000",
        "a=fmtp:96 octet-align=1;mode-change-capability=2;max-red=220",
        "a=rtpmap:0 PCMU/8000",
        "a=rtpmap:8 PCMA/8000",
        "a=rtpmap:111 telephone-event/16000",
        "a=fmtp:111 0-15",
        "a=rtpmap:110 telephone-event/8000",
        "a=fmtp:110 0-15",
        "a=curr:qos local none",
        "a=curr:qos remote none",
        "a=des:qos mandatory local sendrecv",
        "a=des:qos optional remote sendrecv",
        "a=sendrecv",
        f"a=rtcp:{port + 1}",
        "a=ptime:20",
        "a=maxptime:240",
    ]) + "\r\n"


def octet_aligned(fmtp):
    params = dict(p.strip().split("=", 1) for p in (fmtp or "").split(";") if "=" in p)
    return params.get("octet-align", "0").strip() == "1"


def assert_valid_answer(offer_body, msg, local_port):
    """SDP answer in msg corresponds to the caller offer"""
    assert msg.sdp is not None, f"no SDP:\n{msg.raw}"
    offer = sdplib.audio(sdplib.parse(offer_body))
    answer = sdplib.audio(msg.sdp)
    assert answer is not None, f"no audio in SDP:\n{msg.raw}"

    assert answer["port"] != local_port, f"SDP is not processed by yeti (termination side port):\n{msg.raw}"

    for pt in answer["fmts"]:
        assert pt in offer["fmts"], f"payload {pt} is not offered by caller:\n{msg.raw}"
        assert answer["rtpmap"].get(pt) == offer["rtpmap"][pt], f"payload {pt} encoding mismatch:\n{msg.raw}"
        if offer["rtpmap"][pt] in AMR_PAYLOADS:
            assert octet_aligned(answer["fmtp"].get(pt)) == octet_aligned(offer["fmtp"].get(pt)), \
                f"payload {pt} AMR mode mismatch with offer:\n{msg.raw}"

    assert answer["rtpmap"][answer["fmts"][0]] == "amr-wb/16000", f"AMR-WB is not preferred:\n{msg.raw}"
    assert "amr/8000" in answer["rtpmap"].values(), f"no AMR:\n{msg.raw}"
    for pt, enc in answer["rtpmap"].items():
        if enc.startswith("telephone-event"):
            assert enc == "telephone-event/8000", f"unexpected telephone-event rate:\n{msg.raw}"
    return answer


@pytest.mark.parametrize("profile_suppress_flag", [None, False], ids=["no_flag", "legacy_flag_false"])
def test_amr_negotiation(rpc, routing, cdrs, caller, term_gw, profile_suppress_flag):
    fields = {"aleg_codecs_group_id": ALEG_AMR_CODECS_GROUP, "bleg_codecs_group_id": BLEG_NO_AMR_CODECS_GROUP}
    if profile_suppress_flag is not None:
        fields["suppress_early_media"] = profile_suppress_flag
    routing.set_profiles([route_to(term_gw, **fields), NO_ROUTES])

    term_gw.codecs = ["pcma", "telephone-event"]
    term_gw.early_replies = [EarlyReply(183, "Session Progress")]

    offer = volte_offer(caller.ip, caller.rtp.port)
    reply = caller.invite(YETI, body=offer)
    assert reply is not None and reply.code == 200, reply and reply.raw

    # B-leg: offer from codecs group without AMR, answered with PCMA
    gw_offer = sdplib.audio(term_gw.invite_req.sdp)
    assert not set(gw_offer["rtpmap"].values()) & set(AMR_PAYLOADS), term_gw.invite_req.raw
    assert "pcma/8000" in gw_offer["rtpmap"].values(), term_gw.invite_req.raw

    # A-leg: AMR negotiated in both early and final answers
    r183 = [r for r in caller.provisional if r.code == 183]
    assert r183, f"no 183 for caller: {caller.provisional}"
    assert_valid_answer(offer, r183[0], term_gw.rtp.port)
    answer = assert_valid_answer(offer, reply, term_gw.rtp.port)

    # transcoding: PCMA from the gateway reaches the caller as AMR-WB
    term_gw.rtp.send(8, count=50)
    amr_wb_pt = int(answer["fmts"][0])
    assert caller.rtp.wait(amr_wb_pt, packets=10), f"caller got RTP: {dict(caller.rtp.received)}"

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
