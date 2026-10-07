"""
UPDATE requests (RFC 3311) handling by yeti (SBCCallLeg::onInDialogRequest):
  * relayed to the other leg if aleg_relay_update/bleg_relay_update of the leg it came from is enabled,
    otherwise processed locally: 200 OK with SDP answer (or without SDP for UPDATE without offer),
    unparsable SDP is rejected by SEMS core with 400 before yeti processing. SEMS also terminates
    the established call after that (onFailure, BYE to both legs) while failed UPDATE must not affect
    the dialog (RFC 3311 5.2): test_update_bad_sdp fails until fixed
  * never relayed in early dialog (processed locally)
  * hold via UPDATE follows UPDATE relay flags (aleg_relay_hold/bleg_relay_hold are for re-INVITE)
  * glare: offer while own offer is pending is rejected with 491 (agents do it too, RFC 3311 5.2)
basic relay/local processing of UPDATE with SDP is in test_reoffer_relay.py, session refresh in test_sst.py
"""

import threading
import time

import pytest

from checks import assert_call_cleaned_up
from profiles import NO_ROUTES, YETI, connect_call, route_to
import sdp as sdplib
from sip_ua import EarlyReply

NOT_RELAYED_WAIT = 0.5
REL100_SUPPORTED = 1
REL100_REQUIRE = 3


def in_dialog_after(t):
    return lambda r: r.tag("to") is not None and r.time >= t


def test_update_in_early_dialog(rpc, routing, cdrs, caller, term_gw):
    """UPDATE from the caller after reliable 183 is answered by yeti and not relayed"""
    routing.set_profiles([
        route_to(term_gw, aleg_rel100_mode_id=REL100_REQUIRE, bleg_rel100_mode_id=REL100_SUPPORTED),
        NO_ROUTES,
    ])
    caller.supported = ["100rel"]
    term_gw.early_replies = [EarlyReply(183, "Session Progress", reliable=True)]
    term_gw.answer_delay = 3

    result = []
    invite = threading.Thread(target=lambda: result.append(caller.invite(YETI)), daemon=True)
    invite.start()

    deadline = time.monotonic() + 5
    while not caller.prack_replies and time.monotonic() < deadline:
        time.sleep(0.05)
    assert caller.prack_replies, "early dialog is not established (no PRACK reply)"

    t = time.monotonic()
    reply = caller.update()
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert reply.sdp is not None, f"no SDP answer for early UPDATE:\n{reply.raw}"
    assert term_gw.wait_request("UPDATE", pred=in_dialog_after(t), timeout=NOT_RELAYED_WAIT) is None, \
        "UPDATE is relayed in early dialog"

    invite.join(10)
    assert result and result[0] is not None and result[0].code == 200, result
    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


@pytest.mark.parametrize("relay", [True, False], ids=["relay", "local"])
def test_update_without_sdp(rpc, routing, cdrs, caller, term_gw, relay):
    connect_call(routing, caller, term_gw, aleg_relay_update=relay)

    t = time.monotonic()
    reply = caller.in_dialog("UPDATE")
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert reply.sdp is None, f"SDP in reply to UPDATE without offer:\n{reply.raw}"

    req = term_gw.wait_request("UPDATE", pred=in_dialog_after(t), timeout=2 if relay else NOT_RELAYED_WAIT)
    if relay:
        assert req is not None and req.sdp is None, req and req.raw
    else:
        assert req is None, f"UPDATE is relayed:\n{req.raw}"

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


def test_update_bad_sdp(rpc, routing, cdrs, caller, term_gw):
    connect_call(routing, caller, term_gw, aleg_relay_update=False)

    reply = caller.in_dialog("UPDATE", body="v=0\r\nthis is not SDP\r\n")
    assert reply is not None and reply.code == 400, reply and reply.raw

    # the call is not affected
    assert caller.update().code == 200
    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


@pytest.mark.parametrize("relay_update", [True, False], ids=["relay_update", "local_update"])
def test_hold_via_update(rpc, routing, cdrs, caller, term_gw, relay_update):
    """aleg_relay_hold does not matter for UPDATE: relaying is defined by aleg_relay_update"""
    connect_call(routing, caller, term_gw, aleg_relay_update=relay_update, aleg_relay_hold=True)

    for direction, answer_direction in (("sendonly", "recvonly"), ("sendrecv", "sendrecv")):
        t = time.monotonic()
        reply = caller.update(direction)
        assert reply is not None and reply.code == 200, reply and reply.raw
        assert sdplib.audio(reply.sdp)["direction"] == answer_direction, reply.raw
        req = term_gw.wait_request("UPDATE", pred=in_dialog_after(t),
                                   timeout=2 if relay_update else NOT_RELAYED_WAIT)
        if relay_update:
            assert req is not None and sdplib.audio(req.sdp)["direction"] == direction, req and req.raw
        else:
            assert req is None, f"UPDATE is relayed:\n{req.raw}"

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


@pytest.mark.parametrize("relay", [True, False], ids=["relay", "local"])
def test_codec_change_via_update(rpc, routing, cdrs, caller, term_gw, relay):
    """UPDATE offering PCMA only: the caller gets RTP in PCMA afterwards"""
    caller.codecs = ["pcmu", "pcma", "telephone-event"]
    connect_call(routing, caller, term_gw, aleg_relay_update=relay)

    reply = caller.update(body=caller.offer(media=[sdplib.Media("audio", caller.rtp.port,
                                                                codecs=["pcma", "telephone-event"])]))
    assert reply is not None and reply.code == 200, reply and reply.raw
    answer = sdplib.audio(reply.sdp)
    assert sdplib.first_audio_codec_pt(answer) == 8, reply.raw

    # the gateway codec: PCMA if it answered the relayed UPDATE, PCMU from the initial call otherwise
    caller.rtp.received.clear()
    term_gw.rtp.send(8 if relay else 0, count=25)
    assert caller.rtp.wait(packets=10), f"caller got RTP: {dict(caller.rtp.received)}"
    audio_pts = {pt for pt in caller.rtp.received if pt not in (13, 101)}
    assert audio_pts == {8}, f"caller got RTP: {dict(caller.rtp.received)}"

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


def test_update_glare(rpc, routing, cdrs, caller, term_gw):
    """simultaneous UPDATEs from both sides: at least one is rejected with 491, the call survives
    and the retried UPDATE succeeds"""
    connect_call(routing, caller, term_gw, aleg_relay_update=True, bleg_relay_update=True)

    replies = {}
    start = threading.Barrier(2)

    def send(name, agent):
        start.wait()
        replies[name] = agent.update()

    threads = [threading.Thread(target=send, args=(n, a), daemon=True)
               for n, a in (("caller", caller), ("gw", term_gw))]
    for th in threads:
        th.start()
    for th in threads:
        th.join(10)

    codes = {n: r.code if r is not None else None for n, r in replies.items()}
    assert set(codes.values()) <= {200, 491}, codes
    assert 491 in codes.values(), f"no glare detected: {codes}"

    time.sleep(1)
    assert caller.update().code == 200, "UPDATE after glare failed"
    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
