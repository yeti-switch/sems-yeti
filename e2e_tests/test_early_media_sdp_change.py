"""
termination gateway sends one SDP in 183 and another one in 200 OK.
port of yeti-test test_early_media_sdp_change.py

  rel100 disabled (0): unreliable 183, 200 OK by timer
  rel100 supported (1): reliable 183 from the gateway (PRACKed by yeti), 200 OK after PRACK

RFC 3261 13.2.1: UAC MUST treat the first session description it receives as the answer and
MUST ignore session descriptions in subsequent responses to the initial INVITE.
SEMS follows it (AmOfferAnswer::isSubsequentSDP), so the SDP changed in 200 OK is ignored:
  * B-leg media keeps parameters of the 183 SDP (codec, ptime, RTP address)
  * the caller gets the same SDP in 200 OK as in 183 (the same o= version)
"""

import pytest

from checks import assert_call_cleaned_up
import sdp as sdplib
from profiles import NO_ROUTES, YETI, route_to
from rtp import RtpEndpoint
from sip_ua import EarlyReply

PTIME_20MS_STEP = 160  # RTP timestamp increment of 20ms frame at 8000 Hz


def early_media_call(routing, caller, term_gw, rel100_mode=0, **profile):
    routing.set_profiles([
        route_to(term_gw, aleg_rel100_mode_id=rel100_mode, bleg_rel100_mode_id=rel100_mode, **profile),
        NO_ROUTES,
    ])
    if rel100_mode:
        caller.supported = ["100rel"]
    term_gw.early_replies = [EarlyReply(183, "Session Progress", reliable=bool(rel100_mode))]
    term_gw.answer_delay = 1 if not rel100_mode else 0.2

    reply = caller.invite(YETI)
    assert reply is not None and reply.code == 200, reply and reply.raw
    r183 = [r for r in caller.provisional if r.code == 183]
    assert r183, f"no 183 for caller: {caller.provisional}"
    assert r183[0].sdp is not None and sdplib.audio(r183[0].sdp), f"no audio SDP in 183:\n{r183[0].raw}"
    if rel100_mode:
        assert term_gw.wait_request("PRACK", call_id=term_gw.call_id) is not None, "no PRACK on termination side"
    return reply, r183[0]


def assert_same_sdp(early, final):
    """caller gets in 200 OK the SDP it already got in 183"""
    e, f = early.sdp, final.sdp
    assert f is not None, f"no SDP in 200 OK:\n{final.raw}"
    assert f["version"] == e["version"], f"SDP version changed: 183 {e['version']}, 200 OK {f['version']}"
    ea, fa = sdplib.audio(e), sdplib.audio(f)
    assert (fa["port"], fa["fmts"], fa["ptime"]) == (ea["port"], ea["fmts"], ea["ptime"]), \
        f"SDP changed between 183 and 200 OK:\n{early.body}\n{final.body}"


def send_media(caller, term_gw, reply):
    """both sides send RTP, returns payload types received by the gateway (excluding DTMF and CN)"""
    term_gw.rtp.send(sdplib.payload_type(term_gw.codecs[0]), count=25)
    assert caller.rtp.wait(packets=10), f"caller got RTP: {dict(caller.rtp.received)}"
    # yeti lists telephone-event first (codecs group order), send audio codec
    caller.rtp.send(sdplib.first_audio_codec_pt(sdplib.audio(reply.sdp)), count=25)
    assert term_gw.rtp.wait(packets=10), f"gateway got RTP: {dict(term_gw.rtp.received)}"
    return {pt for pt in term_gw.rtp.received if pt not in (13, 101)}


@pytest.mark.parametrize("rel100_mode", [0, 1], ids=["unreliable-183", "reliable-183"])
def test_codec_change_ignored(rpc, routing, cdrs, caller, term_gw, rel100_mode):
    """gateway answers with PCMA only in 200 OK: yeti keeps the codec negotiated by 183.
    the caller sends first: SEMS switches the sending payload to the one received from the gateway,
    so RTP from the gateway would mask the negotiated codec"""
    term_gw.answer_codecs = ["pcma", "telephone-event"]
    reply, r183 = early_media_call(routing, caller, term_gw, rel100_mode)
    assert_same_sdp(r183, reply)

    early_codec = sdplib.first_audio_codec_pt(sdplib.audio(sdplib.parse(term_gw.early_sdp)))
    assert early_codec == 0, term_gw.early_sdp  # PCMU first in 183
    caller.rtp.send(sdplib.first_audio_codec_pt(sdplib.audio(reply.sdp)), count=25)
    assert term_gw.rtp.wait(packets=10), f"gateway got RTP: {dict(term_gw.rtp.received)}"
    pts = {pt for pt in term_gw.rtp.received if pt not in (13, 101)}
    assert pts == {early_codec}, f"gateway got RTP: {dict(term_gw.rtp.received)}"

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


@pytest.mark.parametrize("rel100_mode", [0, 1], ids=["unreliable-183", "reliable-183"])
def test_ptime_change_ignored(rpc, routing, cdrs, caller, term_gw, rel100_mode):
    """gateway answers with ptime 30 in 200 OK: yeti keeps 20ms frames of 183 SDP (no ptime)"""
    term_gw.answer_ptime = 30
    reply, r183 = early_media_call(routing, caller, term_gw, rel100_mode)
    assert_same_sdp(r183, reply)

    pts = send_media(caller, term_gw, reply)
    for pt in pts:
        steps = term_gw.rtp.timestamp_steps(pt)
        assert steps and max(set(steps), key=steps.count) == PTIME_20MS_STEP, \
            f"payload {pt} timestamp steps: {steps}"

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


@pytest.mark.parametrize("symmetric_rtp", [False, True], ids=["no-symmetric-rtp", "symmetric-rtp"])
def test_rtp_address_change_ignored(rpc, routing, cdrs, caller, term_gw, symmetric_rtp):
    """
    gateway answers with another RTP port in 200 OK: yeti keeps sending to the port from 183.
    with bleg_force_symmetric_rtp yeti switches to the address the gateway sends RTP from
    """
    new_rtp = RtpEndpoint()
    try:
        term_gw.answer_rtp = new_rtp
        reply, r183 = early_media_call(routing, caller, term_gw, bleg_force_symmetric_rtp=symmetric_rtp)
        assert_same_sdp(r183, reply)

        # the gateway sends RTP from the new port (to yeti address from the INVITE SDP)
        new_rtp.remote = term_gw.rtp.remote
        new_rtp.send(sdplib.payload_type(term_gw.codecs[0]), count=25)
        caller.rtp.send(sdplib.first_audio_codec_pt(sdplib.audio(reply.sdp)), count=25)

        if symmetric_rtp:
            assert new_rtp.wait(packets=10), f"no RTP to the symmetric address: {dict(new_rtp.received)}"
        else:
            assert term_gw.rtp.wait(packets=10), f"no RTP to the 183 address: {dict(term_gw.rtp.received)}"
            assert new_rtp.count() == 0, f"RTP to the address from 200 OK: {dict(new_rtp.received)}"
    finally:
        new_rtp.stop()

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
