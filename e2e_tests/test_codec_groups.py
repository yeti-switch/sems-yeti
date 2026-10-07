"""
codec negotiation according to codecs groups (src/CodecsGroup.cpp, src/sdp_filter.cpp).
routing profile: aleg_codecs_group_id, bleg_codecs_group_id, aleg_single_codec_in_200ok,
bleg_single_codec_in_200ok, try_avoid_transcoding

  * offer from the caller (processSdpOffer, A-leg group): only codecs of the group are left, ordered as
    in the group, caller payload types and fmtp are kept. no codecs left (or telephone-event/CN only):
    internal code 141 'Codecs not matched' -> 488
  * offer to the gateway (filterSdpOffer, B-leg group): exactly codecs of the group in the group order
    (missing ones are added for transcoding). dynamic_payload_type and format_parameters of the group
    override the offered ones, missing dynamic payload types are assigned from 96.
    no codecs: 488 Not Acceptable Here
  * answer to the caller (processSdpAnswer): codecs negotiated with the caller in the A-leg group order.
    try_avoid_transcoding: codecs answered by the gateway first. single codec in 200 OK: the first codec
    and telephone-event only
  * group ptime overrides a=ptime of the offer to and the answer from the leg of the group
  * codecs without loaded SEMS plugin (G729, G723, ...) are ignored when the group is loaded.
    codecs of the e2e SEMS: PCMU, PCMA (wav), AMR, AMR-WB (amr), telephone-event, CN (core)

codecs groups (etc/db_map/load_codec_groups.json):
  1 - telephone-event, CN, G723, G729, PCMU, PCMA, ... (common profile)
  2 - AMR-WB, AMR, PCMA, PCMU, telephone-event
  3 - PCMA, PCMU, telephone-event
  4 - AMR (dynamic_payload_type 97, octet-align=1), PCMA, telephone-event (dynamic_payload_type 100, 0-16)
  5 - PCMA, PCMU, telephone-event, ptime 30
  6 - G729 (no plugin), telephone-event
  7 - opus, speex (8000, 16000, 32000), GSM, PCMA, telephone-event: transcoding codecs for
      test_undecodable_media.py (SEMS variant "codecs" loads their plugins, the main SEMS ignores them)
"""

import time

import pytest

from checks import assert_call_cleaned_up, is_unhandled, no_active_calls
from profiles import NO_ROUTES, YETI, route_to
import sdp as sdplib

GROUP_DEFAULT = 1
GROUP_AMR = 2
GROUP_PCMA_PCMU = 3
GROUP_DYNAMIC = 4
GROUP_PTIME_30 = 5
GROUP_NO_PLUGIN = 6

PT_PCMU = 0
PT_PCMA = 8
PT_TE = 101  # telephone-event payload type of test agents

CODECS_NOT_MATCHED = (488, "Codecs not matched")

PCMU, PCMA, TE, CN = "pcmu/8000", "pcma/8000", "telephone-event/8000", "cn/8000"


def groups(aleg, bleg, **fields):
    return {"aleg_codecs_group_id": aleg, "bleg_codecs_group_id": bleg, **fields}


def call(routing, caller, term_gw, code=200, **fields):
    routing.set_profiles([route_to(term_gw, **fields), NO_ROUTES])
    reply = caller.invite(YETI)
    assert reply is not None and reply.code == code, reply and reply.raw
    if code == 200:
        assert term_gw.wait_request("ACK", call_id=term_gw.call_id) is not None, "no ACK on termination side"
    return reply


def audio(msg):
    m = sdplib.audio(msg.sdp)
    assert m is not None, f"no audio in SDP:\n{msg.raw}"
    return m


def codecs(msg):
    """'encoding/rate' of the audio stream in m= line order"""
    m = audio(msg)
    return [m["rtpmap"].get(pt) for pt in m["fmts"]]


def payload_types(msg):
    """'encoding/rate' -> payload type"""
    return {enc: int(pt) for pt, enc in audio(msg)["rtpmap"].items()}


def assert_media(src, dst, pt, received_pt):
    """RTP sent by src with pt reaches dst as received_pt"""
    dst.rtp.received.clear()
    src.rtp.send(pt, count=25)
    assert dst.rtp.wait(received_pt, packets=10), f"got RTP: {dict(dst.rtp.received)}"


def hangup(rpc, cdrs, caller, term_gw):
    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


# initial offer/answer

def test_filter_and_arrange(rpc, routing, cdrs, caller, term_gw):
    """caller offer is reduced to the A-leg group codecs in the group order,
    gateway gets the B-leg group codecs"""
    caller.codecs = ["g729", "pcmu", "pcma", "cn", "telephone-event"]
    reply = call(routing, caller, term_gw, **groups(GROUP_PCMA_PCMU, GROUP_PCMA_PCMU))

    assert codecs(reply) == [PCMA, PCMU, TE], reply.raw
    assert payload_types(reply)[TE] == PT_TE, reply.raw
    assert codecs(term_gw.invite_req) == [PCMA, PCMU, TE], term_gw.invite_req.raw
    hangup(rpc, cdrs, caller, term_gw)


def test_codecs_without_plugin_ignored(rpc, routing, cdrs, caller, term_gw):
    """G729 (no SEMS plugin) of the group 1 is neither negotiated with the caller nor offered to the gateway"""
    caller.codecs = ["g729", "pcmu", "telephone-event"]
    reply = call(routing, caller, term_gw, **groups(GROUP_DEFAULT, GROUP_DEFAULT))

    assert codecs(reply) == [TE, PCMU], reply.raw
    assert codecs(term_gw.invite_req) == [TE, CN, PCMU, PCMA], term_gw.invite_req.raw
    hangup(rpc, cdrs, caller, term_gw)


def test_transcoding_codecs_added(rpc, routing, cdrs, caller, term_gw):
    """B-leg group codecs not offered by the caller are added to the gateway offer,
    missing dynamic payload types are assigned from 96 skipping used ones"""
    caller.codecs = ["pcmu", "telephone-event"]
    term_gw.codecs = ["pcma", "telephone-event"]
    reply = call(routing, caller, term_gw, **groups(GROUP_PCMA_PCMU, GROUP_AMR))

    gw_offer = term_gw.invite_req
    assert codecs(gw_offer) == ["amr-wb/16000", "amr/8000", PCMA, PCMU, TE], gw_offer.raw
    pts = payload_types(gw_offer)
    assert (pts["amr-wb/16000"], pts["amr/8000"], pts[TE]) == (96, 97, PT_TE), gw_offer.raw

    assert codecs(reply) == [PCMU, TE], reply.raw
    assert_media(term_gw, caller, PT_PCMA, PT_PCMU)
    assert_media(caller, term_gw, PT_PCMU, PT_PCMA)
    hangup(rpc, cdrs, caller, term_gw)


def test_dynamic_payload_type_and_fmtp_from_group(rpc, routing, cdrs, caller, term_gw):
    """gateway offer has dynamic payload types and fmtp of the B-leg group,
    the caller keeps own payload types"""
    caller.codecs = ["pcmu", "pcma", "telephone-event"]
    term_gw.codecs = ["pcma", "telephone-event"]
    reply = call(routing, caller, term_gw, **groups(GROUP_PCMA_PCMU, GROUP_DYNAMIC))

    gw_offer = term_gw.invite_req
    m = audio(gw_offer)
    assert m["fmts"] == ["97", "8", "100"], gw_offer.raw
    assert (m["rtpmap"]["97"], m["rtpmap"]["100"]) == ("amr/8000", TE), gw_offer.raw
    assert m["fmtp"].get("97") == "octet-align=1", gw_offer.raw
    assert m["fmtp"].get("100") == "0-16", gw_offer.raw

    # the gateway answers telephone-event with 100
    assert payload_types(reply)[TE] == PT_TE, reply.raw
    assert codecs(reply) == [PCMA, PCMU, TE], reply.raw
    hangup(rpc, cdrs, caller, term_gw)


@pytest.mark.parametrize("offer", [["g729"], ["g729", "telephone-event"]], ids=["no-common", "telephone-event-only"])
def test_no_common_codecs_aleg(rpc, routing, cdrs, caller, term_gw, offer):
    """nothing (or telephone-event only) is left from the caller offer: 488, no B-leg"""
    caller.codecs = offer
    reply = call(routing, caller, term_gw, code=488, **groups(GROUP_PCMA_PCMU, GROUP_PCMA_PCMU))
    assert reply.reason == "Not Acceptable Here", reply.raw
    assert term_gw.invite_req is None, "call is routed"
    assert_call_cleaned_up(rpc, cdrs, caller, code=0, reason="", internal=CODECS_NOT_MATCHED)


def test_no_codecs_bleg(rpc, routing, cdrs, caller, term_gw):
    """B-leg group has no usable codecs (G729 without plugin and telephone-event): 488, no B-leg"""
    reply = call(routing, caller, term_gw, code=488, **groups(GROUP_PCMA_PCMU, GROUP_NO_PLUGIN))
    assert term_gw.invite_req is None, "call is routed"
    assert no_active_calls(rpc, caller.remote_tag), "yeti still has sessions"
    found = cdrs.wait(caller.call_id)
    assert found, f"no CDR for call {caller.call_id}"
    assert not any(is_unhandled(c) for c in found), found


# ptime

@pytest.mark.parametrize("leg", ["aleg", "bleg"])
def test_group_ptime(rpc, routing, cdrs, caller, term_gw, leg):
    """group ptime overrides a=ptime in SDP sent to the leg of the group"""
    caller.ptime = 20
    term_gw.ptime = 20
    fields = groups(GROUP_PTIME_30, GROUP_PCMA_PCMU) if leg == "aleg" else groups(GROUP_PCMA_PCMU, GROUP_PTIME_30)
    reply = call(routing, caller, term_gw, **fields)

    caller_ptime, gw_ptime = (30, 20) if leg == "aleg" else (20, 30)
    assert audio(reply)["ptime"] == caller_ptime, reply.raw
    assert audio(term_gw.invite_req)["ptime"] == gw_ptime, term_gw.invite_req.raw
    hangup(rpc, cdrs, caller, term_gw)


# answer codecs

@pytest.mark.parametrize("single_codec", [False, True], ids=["all-codecs", "single-codec"])
def test_aleg_single_codec_in_200ok(rpc, routing, cdrs, caller, term_gw, single_codec):
    caller.codecs = ["pcmu", "pcma", "telephone-event"]
    reply = call(routing, caller, term_gw, **groups(GROUP_PCMA_PCMU, GROUP_PCMA_PCMU,
                                                     aleg_single_codec_in_200ok=single_codec))
    assert codecs(reply) == ([PCMA, TE] if single_codec else [PCMA, PCMU, TE]), reply.raw
    hangup(rpc, cdrs, caller, term_gw)


@pytest.mark.parametrize("single_codec", [False, True], ids=["all-codecs", "single-codec"])
def test_bleg_single_codec_in_200ok(rpc, routing, cdrs, caller, term_gw, single_codec):
    """answer to the relayed re-INVITE from the gateway"""
    call(routing, caller, term_gw, **groups(GROUP_PCMA_PCMU, GROUP_PCMA_PCMU, bleg_relay_reinvite=True,
                                            bleg_single_codec_in_200ok=single_codec))
    reply = term_gw.reinvite()
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert codecs(reply) == ([PCMA, TE] if single_codec else [PCMA, PCMU, TE]), reply.raw
    hangup(rpc, cdrs, caller, term_gw)


@pytest.mark.parametrize("avoid", [False, True], ids=["group-order", "avoid-transcoding"])
def test_try_avoid_transcoding(rpc, routing, cdrs, caller, term_gw, avoid):
    """gateway answers PCMU while PCMA is preferred by the A-leg group.
    try_avoid_transcoding puts PCMU first in the caller answer, so media goes without transcoding"""
    caller.codecs = ["pcmu", "pcma", "telephone-event"]
    term_gw.codecs = ["pcmu", "telephone-event"]
    reply = call(routing, caller, term_gw, **groups(GROUP_PCMA_PCMU, GROUP_PCMA_PCMU, try_avoid_transcoding=avoid))

    expected = PT_PCMU if avoid else PT_PCMA
    assert sdplib.first_audio_codec_pt(audio(reply)) == expected, reply.raw
    assert set(codecs(reply)) == {PCMA, PCMU, TE}, reply.raw
    assert_media(term_gw, caller, PT_PCMU, expected)
    hangup(rpc, cdrs, caller, term_gw)


# re-INVITE

def test_reinvite(rpc, routing, cdrs, caller, term_gw):
    """caller re-INVITE is filtered by the A-leg group (488 if nothing left, the call survives),
    relayed re-INVITE has codecs of the B-leg group"""
    call(routing, caller, term_gw, **groups(GROUP_PCMA_PCMU, GROUP_PCMA_PCMU, aleg_relay_reinvite=True))

    reply = caller.reinvite(body=caller.offer(media=[sdplib.Media("audio", caller.rtp.port, codecs=["g729"])]))
    assert reply is not None and reply.code == 488, reply and reply.raw

    t = time.monotonic()
    reply = caller.reinvite(body=caller.offer(media=[sdplib.Media("audio", caller.rtp.port,
                                                                  codecs=["pcmu", "telephone-event"])]))
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert codecs(reply) == [PCMU, TE], reply.raw
    req = term_gw.wait_request("INVITE", pred=lambda r: r.tag("to") is not None and r.time >= t)
    assert req is not None, "re-INVITE is not relayed"
    assert codecs(req) == [PCMA, PCMU, TE], req.raw
    hangup(rpc, cdrs, caller, term_gw)
