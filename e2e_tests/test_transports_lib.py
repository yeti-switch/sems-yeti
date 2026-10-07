"""
self-tests of the test agents transports (lib/transport.py) without SEMS:
agents call each other directly over every transport
"""

import threading
import time

import pytest

from sip_ua import Caller, TerminationGateway
from transport import TcpTransport, WsTransport, ws_frame

TRANSPORTS = ["udp", "tcp", "tls", "ws", "wss"]


@pytest.fixture
def agents():
    created = []

    def make(cls, transport, **kw):
        a = cls(transport=transport, **kw)
        created.append(a)
        return a
    yield make
    for a in created:
        a.stop()


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_call(agents, transport):
    gw = agents(TerminationGateway, transport)
    caller = agents(Caller, transport)

    reply = caller.invite((gw.ip, gw.port))
    assert reply is not None and reply.code == 200, reply and reply.raw
    inv = gw.invite_req
    assert inv.header("via").startswith(f"SIP/2.0/{transport.upper()} "), inv.raw
    assert gw.wait_request("ACK") is not None
    assert caller.bye().code == 200
    bye = gw.wait_request("BYE")
    assert bye is not None

    if transport != "udp":
        # all requests and replies of the dialog over the single connection
        assert len(caller.trsp.connections) == 1, caller.trsp.connections
        assert len(gw.trsp.connections) == 1, gw.trsp.connections
        assert inv.conn is bye.conn


@pytest.mark.parametrize("transport", ["tcp", "tls", "ws", "wss"])
def test_reverse_request_over_accepted_connection(agents, transport):
    """gateway BYE goes to the caller over the connection opened by the caller"""
    gw = agents(TerminationGateway, transport)
    caller = agents(Caller, transport)
    assert caller.invite((gw.ip, gw.port)).code == 200
    assert gw.wait_request("ACK") is not None

    gw.remote_target = f"sip:caller@{caller.ip}:{caller.trsp.connections[0].local[1]}"
    gw.trsp.connections[0].peer = caller.trsp.connections[0].local
    assert gw.bye().code == 200
    assert len(gw.trsp.connections) == 1, gw.trsp.connections


@pytest.mark.parametrize("transport", ["tls", "wss"])
def test_tls(agents, transport):
    gw = agents(TerminationGateway, transport)
    caller = agents(Caller, transport, client_cert=True)
    assert caller.invite((gw.ip, gw.port)).code == 200
    conn = gw.trsp.connections[0]
    assert conn.tls_version in ("TLSv1.2", "TLSv1.3")
    assert conn.peer_cert and ("commonName", "client.e2e.invalid") in conn.peer_cert["subject"][0]
    assert caller.bye().code == 200


def test_tcp_framing(agents):
    """several messages and keep-alive CRLFs in a single read"""
    gw = agents(TerminationGateway, "tcp")
    t = TcpTransport()
    try:
        msgs = []
        t.on_message = lambda data, peer, conn: msgs.append(data)
        opt = (f"OPTIONS sip:gw@{gw.ip}:{gw.port} SIP/2.0\r\nVia: SIP/2.0/TCP {t.local[0]}:{t.local[1]};branch=z9hG4bK{{}}\r\n"
               f"From: <sip:a@x>;tag=1\r\nTo: <sip:gw@x>\r\nCall-ID: framing\r\nCSeq: {{}} OPTIONS\r\n"
               "Content-Length: 0\r\n\r\n")
        conn = t.connect((gw.ip, gw.port))
        conn.sock.sendall(("\r\n\r\n" + opt.format(1, 1) + "\r\n" + opt.format(2, 2)).encode())
        deadline = time.monotonic() + 3
        while len(msgs) < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert len(msgs) == 2, msgs
        assert len(gw.requests_of("OPTIONS")) == 2
    finally:
        t.close()


def test_ws_fragmented_frames_and_ping(agents):
    gw = agents(TerminationGateway, "ws")
    t = WsTransport()
    try:
        msgs = []
        t.on_message = lambda data, peer, conn: msgs.append(data)
        conn = t.connect((gw.ip, gw.port))
        assert conn.ws_protocol == "sip"
        opt = (f"OPTIONS sip:gw@{gw.ip}:{gw.port} SIP/2.0\r\nVia: SIP/2.0/WS x.invalid;branch=z9hG4bKfrag\r\n"
               "From: <sip:a@x>;tag=1\r\nTo: <sip:gw@x>\r\nCall-ID: frag\r\nCSeq: 1 OPTIONS\r\n"
               "Content-Length: 0\r\n\r\n").encode()
        first = bytearray(ws_frame(opt[:20], 0x1))
        first[0] &= 0x7F  # not FIN
        rest = bytearray(ws_frame(opt[20:], 0x0))
        conn.sock.sendall(bytes(first) + bytes(rest))
        assert gw.wait_request("OPTIONS", timeout=3) is not None
        deadline = time.monotonic() + 3
        while not msgs and time.monotonic() < deadline:
            time.sleep(0.05)
        assert msgs and msgs[0].startswith(b"SIP/2.0 200"), msgs
        t.ping((gw.ip, gw.port))
    finally:
        t.close()


def test_ws_handshake_without_sip_protocol(agents):
    gw = agents(TerminationGateway, "ws")
    t = WsTransport(ws_protocols=None)
    try:
        conn = t.connect((gw.ip, gw.port))
        assert conn.ws_protocol is None
        assert t.handshake_replies == ["HTTP/1.1 101 Switching Protocols"]
    finally:
        t.close()


@pytest.mark.parametrize("transport", ["tcp", "ws"])
def test_close_connection(agents, transport):
    gw = agents(TerminationGateway, transport)
    caller = agents(Caller, transport)
    assert caller.invite((gw.ip, gw.port)).code == 200
    caller.trsp.close_connection((gw.ip, gw.port))
    deadline = time.monotonic() + 3
    while gw.trsp.connections[0].closed is None and time.monotonic() < deadline:
        time.sleep(0.05)
    assert gw.trsp.connections[0].closed_by_peer, gw.trsp.connections


def test_glare(agents):
    """crossing UPDATE offers are rejected with 491 (RFC 3311 5.2).
    both offers are marked as pending before sending: otherwise on loopback the first UPDATE is often
    answered before the other side starts its own one and the offers do not cross"""
    gw = agents(TerminationGateway, "udp")
    caller = agents(Caller, "udp")
    assert caller.invite((gw.ip, gw.port)).code == 200
    assert gw.wait_request("ACK") is not None

    caller.offer_pending = gw.offer_pending = True
    replies = {}
    barrier = threading.Barrier(2)

    def send(name, agent):
        barrier.wait()
        replies[name] = agent.update()
    threads = [threading.Thread(target=send, args=(n, a)) for n, a in (("caller", caller), ("gw", gw))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert 491 in {r.code for r in replies.values()}, replies
