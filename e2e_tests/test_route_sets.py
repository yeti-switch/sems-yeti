"""
predefined route sets and outbound proxies from routing profile.

B-leg (SBCCallProfile::apply_b_routing):
  bleg_route_set              - predefined route set, has priority over outbound_proxy
  outbound_proxy              - '<outbound_proxy;lr>' route for the initial INVITE,
  force_outbound_proxy          for in-dialog requests too if forced (AmBasicSipDialog::getRoute)
A-leg (SBCCallProfile::apply_a_routing), requests from yeti to the caller (BYE):
  aleg_route_set, aleg_outbound_proxy/aleg_force_outbound_proxy
  (A-leg dialog is established, so outbound proxy is used only when forced)

loose routing (first route with ';lr'): RURI is the remote target, the request goes to the first route
strict routing (first route without ';lr', RFC 3261 12.2.1.1, trans_layer prepare_strict_routing):
  RURI is the first route URI, it is removed from Route set and the remote target is appended
  as the last Route

CDR legb_outbound_proxy: B-leg predefined route set (bleg_route_set or '<outbound_proxy;lr>')
"""

import pytest

from checks import assert_call_cleaned_up
from profiles import NO_ROUTES, YETI, connect_call, route_to
from sip_ua import uri_hostport


def gw_ruri(gw):
    return f"sip:term-user@{gw.ip}:{gw.port}"


def hop(agent, lr=True):
    return f"<sip:{agent.ip}:{agent.port}{';lr' if lr else ''}>"


def call_via(rpc, routing, cdrs, caller, first_hop, **fields):
    """call answered by the first hop agent. returns INVITE received by it and CDR"""
    reply = connect_call(routing, caller, first_hop, **fields)
    assert reply.code == 200
    inv = first_hop.invite_req
    assert caller.bye().code == 200
    cdr = assert_call_cleaned_up(rpc, cdrs, caller, first_hop)
    return inv, cdr


# B-leg initial INVITE

def test_loose_route(rpc, routing, cdrs, caller, term_gw, make_agent):
    proxy = make_agent()
    route_set = hop(proxy)

    inv, cdr = call_via(rpc, routing, cdrs, caller, proxy, ruri=gw_ruri(term_gw), bleg_route_set=route_set)
    assert inv.ruri == gw_ruri(term_gw), inv.raw
    assert inv.route_set == [route_set], inv.raw
    assert term_gw.wait_request("INVITE", timeout=0.5) is None
    assert cdr["legb_outbound_proxy"] == route_set, cdr


def test_loose_route_multiple_hops(rpc, routing, cdrs, caller, term_gw, make_agent):
    proxy1, proxy2 = make_agent(), make_agent()
    hops = [hop(proxy1), hop(proxy2)]
    route_set = ",".join(hops)

    inv, cdr = call_via(rpc, routing, cdrs, caller, proxy1, ruri=gw_ruri(term_gw), bleg_route_set=route_set)
    assert inv.ruri == gw_ruri(term_gw), inv.raw
    assert inv.route_set == hops, inv.raw
    assert proxy2.wait_request("INVITE", timeout=0.5) is None
    assert cdr["legb_outbound_proxy"] == route_set, cdr


def test_strict_route(rpc, routing, cdrs, caller, term_gw, make_agent):
    """RURI is replaced with the strict route, the remote target becomes the last Route"""
    proxy = make_agent()
    route_set = hop(proxy, lr=False)

    inv, cdr = call_via(rpc, routing, cdrs, caller, proxy, ruri=gw_ruri(term_gw), bleg_route_set=route_set)
    assert inv.ruri == f"sip:{proxy.ip}:{proxy.port}", inv.raw
    assert inv.route_set == [f"<{gw_ruri(term_gw)}>"], inv.raw
    assert term_gw.wait_request("INVITE", timeout=0.5) is None
    assert cdr["legb_outbound_proxy"] == route_set, cdr


def test_strict_route_multiple_hops(rpc, routing, cdrs, caller, term_gw, make_agent):
    proxy1, proxy2 = make_agent(), make_agent()
    route_set = ",".join([hop(proxy1, lr=False), hop(proxy2)])

    inv, cdr = call_via(rpc, routing, cdrs, caller, proxy1, ruri=gw_ruri(term_gw), bleg_route_set=route_set)
    assert inv.ruri == f"sip:{proxy1.ip}:{proxy1.port}", inv.raw
    assert inv.route_set == [hop(proxy2), f"<{gw_ruri(term_gw)}>"], inv.raw
    assert cdr["legb_outbound_proxy"] == route_set, cdr


def test_route_set_overrides_outbound_proxy(rpc, routing, cdrs, caller, term_gw, make_agent):
    proxy, outbound = make_agent(), make_agent()
    route_set = hop(proxy)

    inv, cdr = call_via(rpc, routing, cdrs, caller, proxy, ruri=gw_ruri(term_gw), bleg_route_set=route_set,
                        outbound_proxy=f"sip:{outbound.ip}:{outbound.port}")
    assert inv.route_set == [route_set], inv.raw
    assert outbound.wait_request("INVITE", timeout=0.5) is None
    assert cdr["legb_outbound_proxy"] == route_set, cdr


def test_outbound_proxy_strict(rpc, routing, cdrs, caller, term_gw, make_agent):
    """outbound proxy is always loose route ('<outbound_proxy;lr>')"""
    proxy = make_agent()
    outbound_proxy = f"sip:{proxy.ip}:{proxy.port}"

    inv, cdr = call_via(rpc, routing, cdrs, caller, proxy, ruri=gw_ruri(term_gw), outbound_proxy=outbound_proxy)
    assert inv.ruri == gw_ruri(term_gw), inv.raw
    assert inv.route_set == [f"<{outbound_proxy};lr>"], inv.raw
    assert cdr["legb_outbound_proxy"] == f"<{outbound_proxy};lr>", cdr


# B-leg in-dialog requests

@pytest.mark.parametrize("force", [True, False], ids=["forced", "not_forced"])
def test_outbound_proxy_in_dialog(rpc, routing, cdrs, caller, term_gw, make_agent, force):
    """the call is answered through the proxy with the gateway Contact. in-dialog requests go
    to the Contact directly or through the proxy if force_outbound_proxy is set"""
    proxy = make_agent()
    outbound_proxy = f"sip:{proxy.ip}:{proxy.port}"
    proxy.contact_override = f"<{term_gw.contact_uri}>"

    routing.set_profiles([
        route_to(term_gw, outbound_proxy=outbound_proxy, force_outbound_proxy=force),
        NO_ROUTES,
    ])
    reply = caller.invite(YETI)
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert proxy.invite_req.route_set == [f"<{outbound_proxy};lr>"], proxy.invite_req.raw

    # ACK for 2xx is in-dialog request as well
    ack_receiver, other = (proxy, term_gw) if force else (term_gw, proxy)
    assert ack_receiver.wait_request("ACK", call_id=proxy.call_id) is not None, "ACK is not received"
    assert other.wait_request("ACK", timeout=0.5) is None

    assert caller.bye().code == 200
    if force:
        bye = proxy.wait_request("BYE", call_id=proxy.call_id)
        assert bye is not None, "BYE is not sent through the forced outbound proxy"
        assert bye.ruri == term_gw.contact_uri, bye.raw
        assert bye.route_set == [f"<{outbound_proxy};lr>"], bye.raw
        assert term_gw.wait_request("BYE", timeout=0.5) is None
    else:
        bye = term_gw.wait_request("BYE", call_id=proxy.call_id)
        assert bye is not None, "BYE is not sent to the remote target"
        assert bye.route_set == [], bye.raw
        assert proxy.wait_request("BYE", timeout=0.5) is None

    cdr = assert_call_cleaned_up(rpc, cdrs, caller, proxy)
    assert cdr["legb_outbound_proxy"] == f"<{outbound_proxy};lr>", cdr


# A-leg

def hangup_by_gw(term_gw):
    reply = term_gw.bye()
    assert reply is not None and reply.code == 200, reply and reply.raw


@pytest.mark.parametrize("force", [True, False], ids=["forced", "not_forced"])
def test_aleg_outbound_proxy(rpc, routing, cdrs, caller, term_gw, make_agent, force):
    proxy = make_agent()
    aleg_outbound_proxy = f"sip:{proxy.ip}:{proxy.port}"
    connect_call(routing, caller, term_gw,
                 aleg_outbound_proxy=aleg_outbound_proxy, aleg_force_outbound_proxy=force)

    hangup_by_gw(term_gw)
    if force:
        bye = proxy.wait_request("BYE", call_id=caller.call_id)
        assert bye is not None, "BYE to caller is not sent through the forced outbound proxy"
        assert bye.ruri == caller.contact_uri, bye.raw
        assert bye.route_set == [f"<{aleg_outbound_proxy};lr>"], bye.raw
        assert caller.wait_request("BYE", timeout=0.5) is None
    else:
        bye = caller.wait_request("BYE", call_id=caller.call_id)
        assert bye is not None, "BYE is not sent to the caller"
        assert bye.route_set == [], bye.raw
        assert proxy.wait_request("BYE", timeout=0.5) is None

    cdr = assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
    assert cdr["legb_outbound_proxy"] == "", "A-leg routing must not affect legb_outbound_proxy"


@pytest.mark.parametrize("lr", [True, False], ids=["loose", "strict"])
def test_aleg_route_set(rpc, routing, cdrs, caller, term_gw, make_agent, lr):
    proxy = make_agent()
    aleg_route_set = hop(proxy, lr)
    connect_call(routing, caller, term_gw, aleg_route_set=aleg_route_set)

    hangup_by_gw(term_gw)
    bye = proxy.wait_request("BYE", call_id=caller.call_id)
    assert bye is not None, "BYE to caller is not sent through aleg_route_set"
    if lr:
        assert bye.ruri == caller.contact_uri, bye.raw
        assert bye.route_set == [aleg_route_set], bye.raw
    else:
        assert bye.ruri == f"sip:{proxy.ip}:{proxy.port}", bye.raw
        assert bye.route_set == [f"<{caller.contact_uri}>"], bye.raw
    assert caller.wait_request("BYE", timeout=0.5) is None

    cdr = assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
    assert cdr["legb_outbound_proxy"] == "", "A-leg routing must not affect legb_outbound_proxy"


def test_no_route_set(rpc, routing, cdrs, caller, term_gw):
    routing.set_profiles([route_to(term_gw), NO_ROUTES])
    reply = caller.invite(YETI)
    assert reply is not None and reply.code == 200, reply and reply.raw
    inv = term_gw.invite_req
    assert inv.route_set == [] and uri_hostport(inv.ruri) == (term_gw.ip, term_gw.port), inv.raw

    assert caller.bye().code == 200
    cdr = assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
    assert cdr["legb_outbound_proxy"] == "", cdr
