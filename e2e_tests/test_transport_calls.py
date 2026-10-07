"""
calls over stream transports (TCP, TLS, WS, WSS). SEMS listeners (etc/sems.conf, interface 'input'):
udp/tcp 5060, tls 5061, ws 8080, wss 8443 (static-client-port, connection-reuse)

A-leg: the caller connects to yeti. all requests from yeti to the caller must reach it:
  WS/WSS clients use '<random>.invalid' host in Via/Contact (RFC 7118), so they are reachable
  only over the connection opened by the client. SEMS resolves the Contact host for in-dialog requests,
  so the profile needs dlg_nat_handling (next hop: source address and transport of the INVITE).
  test_ws_caller_without_nat_handling fails until SEMS sends to WS clients over their connection (RFC 7118 5)
B-leg: yeti connects to the termination gateway listening on the transport.
  SEMS WS client rejects 101 reply without Sec-WebSocket-Version (not required by RFC 6455 4.2.2),
  test gateways send it, test_gw_ws_minimal_handshake fails until fixed.
  yeti Contact must point to the listener of the transport: for WSS SEMS advertises the WS port
  (<sip:127.0.0.1:8080;transport=wss>), so gateway requests fail. WSS gateway tests fail until fixed:
  * bleg_transport_protocol_id patches RURI ';transport=' param (TCP=2, TLS=3, WS=5, WSS=6)
  * or RURI has ';transport=' param already
CDR legA/legB_transport_protocol_id and local/remote ports
"""

import pytest

from checks import assert_call_cleaned_up
from profiles import NO_ROUTES, route_to
from sip_ua import Caller, TerminationGateway, uri_hostport, uri_of
from transport import TRANSPORT_IDS

YETI_PORTS = {"udp": 5060, "tcp": 5060, "tls": 5061, "ws": 8080, "wss": 8443}
STREAM_TRANSPORTS = ["tcp", "tls", "ws", "wss"]


def yeti_addr(transport):
    return ("127.0.0.1", YETI_PORTS[transport])


@pytest.fixture
def make_caller(sems):
    created = []

    def make(transport):
        c = Caller(transport=transport, invalid_host=transport in ("ws", "wss"))
        created.append(c)
        return c
    yield make
    for c in created:
        c.stop()


@pytest.fixture
def make_gw(sems):
    created = []

    def make(transport, **transport_kw):
        g = TerminationGateway(transport=transport, **transport_kw)
        created.append(g)
        return g
    yield make
    for g in created:
        g.stop()


def caller_profile(transport):
    """profile fields to reach the caller over its connection"""
    return {"dlg_nat_handling": True} if transport in ("ws", "wss") else {}


# A-leg

@pytest.mark.parametrize("transport", ["udp"] + STREAM_TRANSPORTS)
def test_caller_transport(rpc, routing, cdrs, make_caller, term_gw, transport):
    caller = make_caller(transport)
    routing.set_profiles([route_to(term_gw, **caller_profile(transport)), NO_ROUTES])

    reply = caller.invite(yeti_addr(transport))
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert term_gw.wait_request("ACK", call_id=term_gw.call_id) is not None

    # re-INVITE from the caller over its connection
    assert caller.reinvite().code == 200

    # BYE from the gateway is passed to the caller
    assert term_gw.bye().code == 200
    bye = caller.wait_request("BYE", call_id=caller.call_id)
    assert bye is not None, "BYE is not delivered to the caller"

    cdr = assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
    assert cdr["legA_transport_protocol_id"] == TRANSPORT_IDS[transport.upper()], cdr
    assert cdr["legA_local_port"] == YETI_PORTS[transport], cdr

    if transport != "udp":
        conn = caller.trsp.connections[0]
        assert cdr["legA_remote_port"] == conn.local[1], cdr
        if transport in ("ws", "wss"):
            # caller is reachable only over its connection
            assert bye.conn is conn, f"BYE over {bye.conn}, expected {conn}"
            assert len(caller.trsp.connections) == 1, caller.trsp.connections


@pytest.mark.parametrize("transport", STREAM_TRANSPORTS)
def test_caller_hangs_up(rpc, routing, cdrs, make_caller, term_gw, transport):
    caller = make_caller(transport)
    routing.set_profiles([route_to(term_gw, **caller_profile(transport)), NO_ROUTES])
    assert caller.invite(yeti_addr(transport)).code == 200
    bye_reply = caller.bye()
    assert bye_reply is not None and bye_reply.code == 200, bye_reply and bye_reply.raw
    assert bye_reply.conn is caller.trsp.connections[0]
    assert term_gw.wait_request("BYE", call_id=term_gw.call_id) is not None
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


@pytest.mark.parametrize("transport", ["ws", "wss"])
def test_ws_caller_receives_reinvite(rpc, routing, cdrs, make_caller, term_gw, transport):
    """re-INVITE from yeti (relayed hold from the gateway) reaches WS client over its connection"""
    caller = make_caller(transport)
    routing.set_profiles([route_to(term_gw, **caller_profile(transport)), NO_ROUTES])
    assert caller.invite(yeti_addr(transport)).code == 200
    assert term_gw.wait_request("ACK", call_id=term_gw.call_id) is not None

    assert term_gw.hold().code == 200
    req = caller.wait_request("INVITE", pred=lambda r: r.tag("to") is not None)
    assert req is not None and req.conn is caller.trsp.connections[0]

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


@pytest.mark.parametrize("transport", ["ws", "wss"])
def test_ws_caller_without_nat_handling(rpc, routing, cdrs, make_caller, term_gw, transport):
    """BYE reaches WS client over its connection without dlg_nat_handling (RFC 7118 5)"""
    caller = make_caller(transport)
    routing.set_profiles([route_to(term_gw), NO_ROUTES])
    assert caller.invite(yeti_addr(transport)).code == 200
    assert term_gw.wait_request("ACK", call_id=term_gw.call_id) is not None

    assert term_gw.bye().code == 200
    bye = caller.wait_request("BYE", call_id=caller.call_id)
    assert bye is not None, "BYE is not delivered to the caller"
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


# B-leg

def gw_call(rpc, routing, cdrs, caller, gw, transport, **profile):
    routing.set_profiles([route_to(gw, **profile), NO_ROUTES])
    reply = caller.invite(("127.0.0.1", 5060))
    assert reply is not None and reply.code == 200, reply and reply.raw
    inv = gw.invite_req
    assert inv.header("via").upper().startswith(f"SIP/2.0/{transport.upper()} "), inv.raw
    assert gw.wait_request("ACK", call_id=gw.call_id) is not None, "no ACK"
    conn = inv.conn
    assert conn is not None and conn.direction == "in", conn
    contact = uri_of(inv.header("contact"))
    assert uri_hostport(contact)[1] == YETI_PORTS[transport], f"Contact is not the {transport} listener: {contact}"

    # BYE from the gateway over the connection opened by yeti
    assert gw.bye().code == 200
    assert caller.wait_request("BYE", call_id=caller.call_id) is not None
    assert len(gw.trsp.connections) == 1, f"new connection for BYE: {gw.trsp.connections}"

    cdr = assert_call_cleaned_up(rpc, cdrs, caller, gw)
    assert cdr["legB_transport_protocol_id"] == TRANSPORT_IDS[transport.upper()], cdr
    assert cdr["legB_remote_port"] == gw.port, cdr
    return inv, conn, cdr


@pytest.mark.parametrize("transport", ["tcp", "tls"])
def test_gw_transport_protocol_id(rpc, routing, cdrs, caller, make_gw, transport):
    gw = make_gw(transport)
    inv, conn, cdr = gw_call(rpc, routing, cdrs, caller, gw, transport,
                             bleg_transport_protocol_id=TRANSPORT_IDS[transport.upper()])
    assert f";transport={transport}" in inv.ruri.lower(), inv.raw
    # static-client-port: connection from the listening port of the transport
    assert conn.peer[1] == YETI_PORTS[transport], conn
    assert cdr["legB_local_port"] == YETI_PORTS[transport], cdr


@pytest.mark.parametrize("transport", STREAM_TRANSPORTS)
def test_gw_ruri_transport_param(rpc, routing, cdrs, caller, make_gw, transport):
    gw = make_gw(transport)
    inv, conn, cdr = gw_call(rpc, routing, cdrs, caller, gw, transport,
                             ruri=f"sip:term-user@{gw.ip}:{gw.port};transport={transport}")
    assert conn.peer[1] == YETI_PORTS[transport], conn


@pytest.mark.parametrize("transport", ["ws", "wss"])
def test_gw_transport_protocol_id_ws(rpc, routing, cdrs, caller, make_gw, transport):
    """bleg_transport_protocol_id WS/WSS: yeti does not patch RURI for them yet
    (SBCCallProfile _patch_uri_transport: 'not supported yet'). the test fails until supported"""
    gw = make_gw(transport)
    gw_call(rpc, routing, cdrs, caller, gw, transport, bleg_transport_protocol_id=TRANSPORT_IDS[transport.upper()])


@pytest.mark.parametrize("transport", ["ws", "wss"])
def test_gw_ws_minimal_handshake(rpc, routing, cdrs, caller, make_gw, transport):
    """gateway answers WS handshake with 101 without Sec-WebSocket-Version (RFC 6455 4.2.2)"""
    gw = make_gw(transport, ws_reply_version=False)
    gw_call(rpc, routing, cdrs, caller, gw, transport,
            ruri=f"sip:term-user@{gw.ip}:{gw.port};transport={transport}")


@pytest.mark.parametrize("transport", ["tcp", "tls", "wss"])
def test_gw_transport_with_ws_caller(rpc, routing, cdrs, make_caller, make_gw, transport):
    """WS client calls the gateway on another stream transport"""
    caller = make_caller("ws")
    gw = make_gw(transport)
    routing.set_profiles([route_to(gw, ruri=f"sip:term-user@{gw.ip}:{gw.port};transport={transport}",
                                   **caller_profile("ws")), NO_ROUTES])

    assert caller.invite(yeti_addr("ws")).code == 200
    assert gw.wait_request("ACK", call_id=gw.call_id) is not None
    contact = uri_of(gw.invite_req.header("contact"))
    assert uri_hostport(contact)[1] == YETI_PORTS[transport], f"Contact is not the {transport} listener: {contact}"
    assert gw.bye().code == 200
    bye = caller.wait_request("BYE", call_id=caller.call_id)
    assert bye is not None and bye.conn is caller.trsp.connections[0]

    cdr = assert_call_cleaned_up(rpc, cdrs, caller, gw)
    assert cdr["legA_transport_protocol_id"] == TRANSPORT_IDS["WS"], cdr
    assert cdr["legB_transport_protocol_id"] == TRANSPORT_IDS[transport.upper()], cdr
