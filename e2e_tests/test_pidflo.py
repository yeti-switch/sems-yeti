"""
PIDF-LO (RFC 6442 location conveyance, application/pidf+xml body part) relay.

routing profile pidflo_mode_id (SBCCallProfile::PidfloModeId, sdp_filter.cpp filterSdpOffer):
  0 disabled (default): SDP offers are reduced to the single application/sdp body
  1 relay: SDP offer from A-leg to B-leg keeps multipart/mixed with the (processed) SDP and
           the application/pidf+xml part, other parts are dropped. without PIDF-LO part the body
           is reduced to the single SDP. offers from B-leg to A-leg are always reduced to SDP
SEMS (AmMimeBody) does not unquote boundary parameter, so multipart body with quoted boundary
(RFC 2046 5.1.1) is not parsed and the INVITE is relayed without body: test_quoted_boundary fails until fixed
Geolocation header referencing the PIDF-LO part by Content-ID passes headers filter only
if whitelisted in transit_headers_a2b
"""

import time

import pytest

from checks import assert_call_cleaned_up
from profiles import NO_ROUTES, YETI, connect_call, route_to
import sdp as sdplib

PIDFLO_MODE_DISABLED = 0
PIDFLO_MODE_RELAY = 1

LOCATION_CID = "target123@e2e.invalid"

PIDF = """<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf"
          xmlns:gp="urn:ietf:params:xml:ns:pidf:geopriv10"
          xmlns:gml="http://www.opengis.net/gml"
          entity="pres:caller@e2e.invalid">
  <tuple id="e2e">
    <status>
      <gp:geopriv>
        <gp:location-info>
          <gml:Point srsName="urn:ogc:def:crs:EPSG::4326">
            <gml:pos>50.4501 30.5234</gml:pos>
          </gml:Point>
        </gp:location-info>
        <gp:usage-rules/>
      </gp:geopriv>
    </status>
  </tuple>
</presence>"""

GEOLOCATION = [f"Geolocation: <cid:{LOCATION_CID}>", "Geolocation-Routing: yes"]


def offer_with_location(agent, extra_parts=(("text/plain", "e2e extra part"),), quoted_boundary=False):
    """multipart/mixed: SDP offer, PIDF-LO with Content-ID and extra parts. returns (content type, body)"""
    return sdplib.multipart(
        ("application/sdp", agent.offer()),
        ("application/pidf+xml", PIDF, [f"Content-ID: <{LOCATION_CID}>"]),
        *extra_parts,
        quoted_boundary=quoted_boundary,
    )


def assert_location_relayed(req, sender):
    assert req.content_type == "multipart/mixed", req.raw
    parts = req.parts()
    assert [p["content_type"] for p in parts] == ["application/sdp", "application/pidf+xml"], req.raw
    pidf = parts[1]
    assert pidf["body"] == PIDF, f"PIDF-LO is changed:\n{pidf['body']}"
    assert pidf["headers"].get("content-id") == f"<{LOCATION_CID}>", pidf["headers"]
    # SDP part is processed by yeti
    _, port = sdplib.connection(req.sdp_body)
    assert port and port != sender.rtp_port, req.sdp_body


def assert_sdp_only(req):
    assert req.content_type == "application/sdp", req.raw
    assert req.sdp_body is not None and "pidf" not in req.body, req.raw


def location_call(routing, caller, term_gw, mode, extra_parts=(("text/plain", "e2e extra part"),),
                  quoted_boundary=False, **profile):
    routing.set_profiles([route_to(term_gw, pidflo_mode_id=mode, transit_headers_a2b="geolocation,geolocation-routing",
                                   **profile), NO_ROUTES])
    content_type, body = offer_with_location(caller, extra_parts, quoted_boundary)
    reply = caller.invite(YETI, body=body, content_type=content_type, headers=GEOLOCATION)
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert term_gw.wait_request("ACK", call_id=term_gw.call_id) is not None
    return term_gw.invite_req


def hangup(rpc, cdrs, caller, term_gw):
    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


def test_relay(rpc, routing, cdrs, caller, term_gw):
    """PIDF-LO part and Geolocation header reach the gateway, other parts are dropped"""
    inv = location_call(routing, caller, term_gw, PIDFLO_MODE_RELAY)
    assert_location_relayed(inv, caller)
    assert inv.header("geolocation") == f"<cid:{LOCATION_CID}>", inv.raw
    hangup(rpc, cdrs, caller, term_gw)


def test_quoted_boundary(rpc, routing, cdrs, caller, term_gw):
    """boundary="..." is the same as unquoted one (RFC 2046 5.1.1)"""
    inv = location_call(routing, caller, term_gw, PIDFLO_MODE_RELAY, quoted_boundary=True)
    assert_location_relayed(inv, caller)
    hangup(rpc, cdrs, caller, term_gw)


@pytest.mark.parametrize("mode", [None, PIDFLO_MODE_DISABLED], ids=["default", "disabled"])
def test_disabled(rpc, routing, cdrs, caller, term_gw, mode):
    profile = {} if mode is None else {"pidflo_mode_id": mode}
    routing.set_profiles([route_to(term_gw, **profile), NO_ROUTES])
    content_type, body = offer_with_location(caller)
    reply = caller.invite(YETI, body=body, content_type=content_type, headers=GEOLOCATION)
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert_sdp_only(term_gw.invite_req)
    hangup(rpc, cdrs, caller, term_gw)


def test_relay_without_pidflo_part(rpc, routing, cdrs, caller, term_gw):
    """multipart offer without PIDF-LO is reduced to the single SDP"""
    routing.set_profiles([route_to(term_gw, pidflo_mode_id=PIDFLO_MODE_RELAY), NO_ROUTES])
    content_type, body = sdplib.multipart(("application/sdp", caller.offer()), ("text/plain", "e2e extra part"))
    reply = caller.invite(YETI, body=body, content_type=content_type)
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert_sdp_only(term_gw.invite_req)
    hangup(rpc, cdrs, caller, term_gw)


def test_relay_sdp_only(rpc, routing, cdrs, caller, term_gw):
    connect_call(routing, caller, term_gw, pidflo_mode_id=PIDFLO_MODE_RELAY)
    assert_sdp_only(term_gw.invite_req)
    hangup(rpc, cdrs, caller, term_gw)


def test_relay_caller_reinvite(rpc, routing, cdrs, caller, term_gw):
    """relayed re-INVITE from the caller keeps PIDF-LO too"""
    connect_call(routing, caller, term_gw, pidflo_mode_id=PIDFLO_MODE_RELAY, aleg_relay_reinvite=True)

    t = time.monotonic()
    content_type, body = offer_with_location(caller)
    reply = caller.reinvite(body=body, content_type=content_type)
    assert reply is not None and reply.code == 200, reply and reply.raw
    req = term_gw.wait_request("INVITE", pred=lambda r: r.tag("to") is not None and r.time >= t)
    assert req is not None, "re-INVITE is not relayed"
    assert_location_relayed(req, caller)
    hangup(rpc, cdrs, caller, term_gw)


def test_not_relayed_to_caller(rpc, routing, cdrs, caller, term_gw):
    """offer from the gateway to the caller is reduced to SDP regardless of the mode"""
    connect_call(routing, caller, term_gw, pidflo_mode_id=PIDFLO_MODE_RELAY, bleg_relay_reinvite=True)

    t = time.monotonic()
    content_type, body = offer_with_location(term_gw)
    reply = term_gw.reinvite(body=body, content_type=content_type)
    assert reply is not None and reply.code == 200, reply and reply.raw
    req = caller.wait_request("INVITE", pred=lambda r: r.tag("to") is not None and r.time >= t)
    assert req is not None, "re-INVITE is not relayed"
    assert_sdp_only(req)
    hangup(rpc, cdrs, caller, term_gw)
