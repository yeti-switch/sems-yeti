"""
calls to registered AoRs (routing profile registered_aor_id/registered_aor_mode_id).

REGISTER is processed by yeti (digest auth by incoming auth credentials, credentials id is the AoR id)
and SEMS registrar (bindings in redis). on routing yeti resolves AoR bindings and for each binding
(SBCCallLeg::onSipRegistrarResolveResponse/replace_profile_fields):
  * mode AS_IS: RURI = registered Contact
  * mode REPLACE_RURI_TRANSPORT_INFO: RURI = Contact with user from profile RURI and merged
    profile RURI params; To host 'unknown.invalid' is replaced by Contact host
  * Path from REGISTER becomes route set for B-leg (Route headers, INVITE sent to the first hop)
  * no bindings: profile is skipped with DC_NOT_REGISTERED (131 -> 480 Gateway not registered)
mode DISABLED: AoR is not resolved, profile RURI is used as is

CDR legb_outbound_proxy is B-leg predefined route set: '<outbound_proxy;lr>' (if set) and Path
"""

from checks import assert_call_cleaned_up
from profiles import (
    AOR1,
    AOR_NEVER_REGISTERED_ID,
    NO_ROUTES,
    NOT_REGISTERED,
    REGISTERED_AOR_MODE_AS_IS,
    REGISTERED_AOR_MODE_DISABLED,
    REGISTERED_AOR_MODE_REPLACE_RURI_TRANSPORT_INFO,
    YETI,
    aor_profile,
    route_to,
)
from sip_ua import uri_hostport, uri_of, uri_user


def register(make_registrant, device, contact_params="", path=None):
    """registers device for AOR1, returns registered contact URI"""
    registrant = make_registrant(AOR1["user"], AOR1["password"])
    contact = f"sip:device@{device.ip}:{device.port}{contact_params}"
    reply = registrant.register(YETI, f"<{contact}>", path=path)
    assert reply is not None and reply.code == 200, reply and reply.raw
    return contact


def answered_call(caller, term):
    reply = caller.invite(YETI)
    assert reply is not None and reply.code == 200, reply and reply.raw
    inv = term.invite_req
    assert inv is not None, "INVITE is not received"
    assert term.wait_request("ACK", call_id=inv.call_id) is not None, "no ACK"
    return inv


def hangup(rpc, cdrs, caller, term):
    assert caller.bye().code == 200
    return assert_call_cleaned_up(rpc, cdrs, caller, term)


def test_register(make_registrant, term_gw):
    """REGISTER is challenged and accepted with digest credentials"""
    registrant = make_registrant(AOR1["user"], AOR1["password"])
    contact = f"<sip:device@{term_gw.ip}:{term_gw.port}>"
    reply = registrant.register(YETI, contact)
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert any("401" in r.start_line for r in registrant.replies), "REGISTER was not challenged"
    assert f"device@{term_gw.ip}:{term_gw.port}" in (reply.header("contact") or ""), reply.raw


def test_wrong_password(make_registrant, term_gw):
    registrant = make_registrant(AOR1["user"], "wrong-password")
    reply = registrant.register(YETI, f"<sip:device@{term_gw.ip}:{term_gw.port}>")
    assert reply is not None and reply.code in (401, 403), reply and reply.raw


def test_as_is_without_path(rpc, routing, cdrs, caller, term_gw, make_registrant):
    contact = register(make_registrant, term_gw, ";ob")
    routing.set_profiles([aor_profile(AOR1["id"], REGISTERED_AOR_MODE_AS_IS), NO_ROUTES])

    inv = answered_call(caller, term_gw)
    assert inv.ruri == contact, inv.raw
    assert inv.route_set == [], inv.raw

    cdr = hangup(rpc, cdrs, caller, term_gw)
    assert cdr["legb_ruri"] == contact, cdr
    assert cdr["legb_outbound_proxy"] == "", cdr


def test_as_is_with_path(rpc, routing, cdrs, caller, term_gw, make_registrant, make_agent):
    """INVITE goes to the edge proxy from Path with Route header, RURI is the registered contact"""
    edge = make_agent()
    path = f"<sip:{edge.ip}:{edge.port};lr>"
    contact = register(make_registrant, term_gw, ";ob", path=path)
    routing.set_profiles([aor_profile(AOR1["id"], REGISTERED_AOR_MODE_AS_IS), NO_ROUTES])

    inv = answered_call(caller, edge)
    assert inv.ruri == contact, inv.raw
    assert inv.route_set == [path], inv.raw
    assert term_gw.wait_request("INVITE", timeout=0.5) is None, "INVITE is sent to the contact bypassing Path"

    cdr = hangup(rpc, cdrs, caller, edge)
    assert cdr["legb_ruri"] == contact, cdr
    assert cdr["legb_outbound_proxy"] == path, cdr


def test_path_with_outbound_proxy(rpc, routing, cdrs, caller, term_gw, make_registrant, make_agent):
    """outbound proxy from profile is the first hop, Path is the next one"""
    edge = make_agent()
    proxy = make_agent()
    path = f"<sip:{edge.ip}:{edge.port};lr>"
    outbound_proxy = f"sip:{proxy.ip}:{proxy.port}"
    contact = register(make_registrant, term_gw, path=path)
    routing.set_profiles([
        aor_profile(AOR1["id"], REGISTERED_AOR_MODE_AS_IS, outbound_proxy=outbound_proxy),
        NO_ROUTES,
    ])

    inv = answered_call(caller, proxy)
    assert inv.ruri == contact, inv.raw
    assert inv.route_set == [f"<{outbound_proxy};lr>", path], inv.raw
    assert edge.wait_request("INVITE", timeout=0.5) is None

    cdr = hangup(rpc, cdrs, caller, proxy)
    assert cdr["legb_outbound_proxy"] == f"<{outbound_proxy};lr>,{path}", cdr


def test_replace_ruri_transport_info(rpc, routing, cdrs, caller, term_gw, make_registrant):
    """RURI user and params are taken from the profile, host/port/params from the contact"""
    register(make_registrant, term_gw, ";transport=udp;ob")
    routing.set_profiles([
        aor_profile(AOR1["id"], REGISTERED_AOR_MODE_REPLACE_RURI_TRANSPORT_INFO,
                    ruri="sip:dialed-user@unknown.invalid;user=phone",
                    to="<sip:dialed-user@unknown.invalid>"),
        NO_ROUTES,
    ])

    inv = answered_call(caller, term_gw)
    assert uri_user(inv.ruri) == "dialed-user", inv.raw
    assert uri_hostport(inv.ruri) == (term_gw.ip, term_gw.port), inv.raw
    params = set(inv.ruri.split(";")[1:])
    assert {"transport=udp", "ob", "user=phone"} <= params, inv.raw

    to_uri = uri_of(inv.header("to"))
    assert uri_user(to_uri) == "dialed-user", inv.raw
    assert uri_hostport(to_uri)[0] == term_gw.ip, f"To host is not replaced by contact host:\n{inv.raw}"

    hangup(rpc, cdrs, caller, term_gw)


def test_mode_disabled(rpc, routing, cdrs, caller, term_gw, make_registrant, make_agent):
    """AoR is not resolved, call goes to the profile RURI"""
    device = make_agent()
    register(make_registrant, device)
    routing.set_profiles([
        aor_profile(AOR1["id"], REGISTERED_AOR_MODE_DISABLED, ruri=f"sip:term-user@{term_gw.ip}:{term_gw.port}"),
        NO_ROUTES,
    ])

    inv = answered_call(caller, term_gw)
    assert uri_hostport(inv.ruri) == (term_gw.ip, term_gw.port), inv.raw
    assert device.wait_request("INVITE", timeout=0.5) is None

    hangup(rpc, cdrs, caller, term_gw)


def test_not_registered(rpc, routing, cdrs, caller):
    routing.set_profiles([aor_profile(AOR_NEVER_REGISTERED_ID), NO_ROUTES])

    reply = caller.invite(YETI)
    assert reply is not None, "no final reply for INVITE"
    assert (reply.code, reply.reason) == NOT_REGISTERED, reply.raw
    assert_call_cleaned_up(rpc, cdrs, caller, code=0, reason="", internal=NOT_REGISTERED)


def test_not_registered_fallback(rpc, routing, cdrs, caller, term_gw):
    """not registered AoR profile is skipped (with CDR), the next profile is used"""
    routing.set_profiles([aor_profile(AOR_NEVER_REGISTERED_ID), route_to(term_gw), NO_ROUTES])

    answered_call(caller, term_gw)
    hangup(rpc, cdrs, caller, term_gw)

    attempts = cdrs.wait(caller.call_id)
    assert len(attempts) == 2, attempts
    skipped = attempts[0]
    assert (skipped["disconnect_intermediate_code"], skipped["disconnect_intermediate_reason"]) == NOT_REGISTERED, \
        skipped
