"""
call routing: yeti gets routing profiles from postgresql_proxy ('getprofile' mapping)
and sends the call to the termination gateway from the profile 'ruri'.

the routing result is a list of profiles tried in order. the last one is the refusing
profile (disconnect_code_id 113 -> '404 No routes') used when no more routes left.
profiles are merged with the common profile from etc/db_map/load_callprofiles.lua
(codecs group, rtp relay, gateways cache ids)
"""

from checks import assert_call_cleaned_up
from profiles import NO_ROUTES, YETI, connect_call, route_to
from sip_ua import sdp_audio, uri_hostport, uri_user


def test_call_routed_to_termination_gw(rpc, routing, cdrs, caller, term_gw):
    routing.set_profiles([route_to(term_gw), NO_ROUTES])

    reply = caller.invite(YETI, user="12345")
    assert reply is not None, "no final reply for INVITE"
    assert reply.code == 200, reply.raw

    # call is sent to the gateway from routing profile
    inv = term_gw.wait_request("INVITE")
    assert inv is not None, "termination gateway did not receive INVITE"
    assert uri_user(inv.ruri) == "term-user"
    assert uri_hostport(inv.ruri) == (term_gw.ip, term_gw.port)

    # B2BUA: separate dialog on the termination side
    assert inv.call_id != caller.call_id

    # media is relayed by yeti (rtp relay enabled by common call profile)
    bleg_ip, bleg_port = sdp_audio(inv.body)
    assert bleg_ip == "127.0.0.1"
    assert bleg_port and bleg_port != caller.rtp_port, inv.body
    _, aleg_port = sdp_audio(reply.body)
    assert aleg_port and aleg_port != term_gw.rtp_port, reply.body

    assert term_gw.wait_request("ACK", call_id=inv.call_id) is not None, "no ACK on termination side"

    # caller hangs up, BYE is passed to the termination gateway
    bye_reply = caller.bye()
    assert bye_reply is not None and bye_reply.code == 200
    assert term_gw.wait_request("BYE", call_id=inv.call_id) is not None, "no BYE on termination side"

    cdr = assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
    assert cdr["legb_ruri"] == f"sip:term-user@{term_gw.ip}:{term_gw.port}", cdr


def test_media_relayed(rpc, routing, cdrs, caller, term_gw):
    """RTP goes through yeti in both directions"""
    connect_call(routing, caller, term_gw)

    caller.rtp.send(0, count=20)
    assert term_gw.rtp.wait(0, packets=10), f"gateway got RTP: {dict(term_gw.rtp.received)}"
    term_gw.rtp.send(0, count=20)
    assert caller.rtp.wait(0, packets=10), f"caller got RTP: {dict(caller.rtp.received)}"

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


def test_termination_gw_hangs_up(rpc, routing, cdrs, caller, term_gw):
    connect_call(routing, caller, term_gw)

    bye_reply = term_gw.bye()
    assert bye_reply is not None and bye_reply.code == 200

    # BYE is passed to the caller (answered with 200 by Caller)
    assert caller.wait_request("BYE", call_id=caller.call_id) is not None, "no BYE on originating side"
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


def test_no_routes(rpc, routing, cdrs, caller, term_gw):
    """routing result with refusing profile only: call is rejected, nothing sent to gateway"""
    routing.set_profiles([NO_ROUTES])

    reply = caller.invite(YETI)
    assert reply is not None, "no final reply for INVITE"
    assert reply.code == 404, reply.raw
    assert term_gw.wait_request("INVITE", timeout=1) is None
    # no B-leg: SIP disconnect is empty, routing refuse is the internal disconnect
    assert_call_cleaned_up(rpc, cdrs, caller, code=0, reason="", internal=(404, "No routes"))
