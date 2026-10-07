"""
termination gateway sends one SDP in 183 and another one in 200 OK.
port of yeti-test test_early_media_sdp_change.py

  rel100 disabled (0): unreliable 183, 200 OK by timer
  rel100 supported (1): reliable 183 from the gateway (PRACKed by yeti), 200 OK after PRACK

the caller must get SDP both in 183 and 200 OK, and media must flow after the change
"""

import pytest

from checks import assert_call_cleaned_up
import sdp as sdplib
from profiles import NO_ROUTES, YETI, route_to
from sip_ua import EarlyReply


@pytest.mark.parametrize("answer_change", [
    {"codecs": ["pcma", "telephone-event"]},
    {"ptime": 30},
], ids=["codecs", "ptime"])
@pytest.mark.parametrize("rel100_mode", [0, 1], ids=["unreliable-183", "reliable-183"])
def test_early_media_sdp_change(rpc, routing, cdrs, caller, term_gw, rel100_mode, answer_change):
    routing.set_profiles([
        route_to(term_gw, aleg_rel100_mode_id=rel100_mode, bleg_rel100_mode_id=rel100_mode),
        NO_ROUTES,
    ])
    if rel100_mode:
        caller.supported = ["100rel"]
    term_gw.early_replies = [EarlyReply(183, "Session Progress", reliable=bool(rel100_mode))]
    term_gw.answer_delay = 1 if not rel100_mode else 0.2
    term_gw.answer_codecs = answer_change.get("codecs")
    term_gw.answer_ptime = answer_change.get("ptime")

    reply = caller.invite(YETI)
    assert reply is not None and reply.code == 200, reply and reply.raw

    # caller gets SDP in 183
    r183 = [r for r in caller.provisional if r.code == 183]
    assert r183, f"no 183 for caller: {caller.provisional}"
    assert r183[0].sdp is not None and sdplib.audio(r183[0].sdp), f"no audio SDP in 183:\n{r183[0].raw}"

    if rel100_mode:
        assert term_gw.wait_request("PRACK", call_id=term_gw.call_id) is not None, "no PRACK on termination side"

    # caller gets SDP in 200 OK
    answer = sdplib.audio(reply.sdp) if reply.sdp else None
    assert answer is not None, f"no audio SDP in 200 OK:\n{reply.raw}"

    # media flows after the SDP change in both directions
    # (the gateway sends media as well, like sems-tester callee in yeti-test)
    gw_pt = sdplib.payload_type(term_gw.codecs[0])
    term_gw.rtp.send(gw_pt, count=25)
    assert caller.rtp.wait(packets=10), f"caller got RTP: {dict(caller.rtp.received)}"

    # yeti lists telephone-event first (codecs group order), send audio codec
    pt = sdplib.first_audio_codec_pt(answer)
    caller.rtp.send(pt, count=25)
    assert term_gw.rtp.wait(packets=10), f"gateway got RTP: {dict(term_gw.rtp.received)}"

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
