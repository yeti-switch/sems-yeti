"""
push notifications for calls to not registered AoRs.

when the AoR has no bindings and there is no other profile without registered_aor_id,
yeti takes push_token ('<type>:<value>') of the profile B-leg gateway from the gateways cache,
sends the notification to the http_client destination and waits (push.timeout = 3000 ms
in etc/sems.conf) for the AoR registration:
  * registered within timeout: the call goes to the new binding
  * timeout or non-2xx reply from the push destination: the profile is skipped as not registered
token types (destinations): 0 FCM (fcm), 1 APNs (apns), 2 APNs sandbox (apns_sandbox), 3 webhook
PushServer (lib/push.py) emulates both the push provider and the device which registers on push
"""

import threading
import time

import pytest

from checks import assert_call_cleaned_up
from profiles import (
    AOR2,
    GW_PUSH_APNS,
    GW_PUSH_APNS_SANDBOX,
    GW_PUSH_FCM,
    GW_PUSH_WEBHOOK,
    NO_ROUTES,
    NOT_REGISTERED,
    YETI,
    aor_profile,
    route_to,
)

PUSH_TIMEOUT = 3.0


def check_webhook(push, caller):
    body = push.json
    assert push.path == "/webhook", push
    assert body["type"] == "call_start", body
    assert body["token"] == "webhook-token", body
    assert body["aor_id"] == str(AOR2["id"]), body
    assert body["call_id"] == caller.call_id, body
    assert body["from_user"] == "caller", body
    assert body["timeout"] == int(PUSH_TIMEOUT * 1000), body
    # From of the caller INVITE (like 'to' and 'ruri')
    assert f"sip:caller@{caller.ip}" in body["from"], body


def check_fcm(push, caller):
    msg = push.json["message"]
    assert push.path == "/fcm", push
    assert msg["token"] == "fcm-token", msg
    assert msg["android"]["priority"] == "high", msg
    assert msg["data"]["type"] == "call_start", msg
    assert msg["data"]["call_id"] == caller.call_id, msg
    assert msg["data"]["from_user"] == "caller", msg


def check_apns(path):
    def check(push, caller):
        body = push.json
        assert push.path == path, push
        assert body["type"] == "call_start", body
        assert body["call_id"] == caller.call_id, body
        assert body["from_user"] == "caller", body
    return check


PUSH_TYPES = [
    pytest.param(GW_PUSH_WEBHOOK, check_webhook, id="webhook"),
    pytest.param(GW_PUSH_FCM, check_fcm, id="fcm"),
    pytest.param(GW_PUSH_APNS, check_apns("/apns/apns-token"), id="apns"),
    pytest.param(GW_PUSH_APNS_SANDBOX, check_apns("/apns_sandbox/apns-sandbox-token"), id="apns_sandbox"),
]


def device_registrant(make_registrant, device):
    registrant = make_registrant(AOR2["user"], AOR2["password"])
    contact = f"sip:device@{device.ip}:{device.port}"
    return registrant, contact


@pytest.mark.parametrize("push_gw, check_push", PUSH_TYPES)
def test_push_and_register(rpc, routing, cdrs, caller, term_gw, make_registrant, push_server, push_gw, check_push):
    """device registers on push, the call goes to it"""
    registrant, contact = device_registrant(make_registrant, term_gw)
    registered = threading.Event()

    def on_push(_):
        time.sleep(0.3)
        reply = registrant.register(YETI, f"<{contact}>")
        if reply is not None and reply.code == 200:
            registered.set()
    push_server.on_push = on_push

    routing.set_profiles([aor_profile(AOR2["id"], legb_gw_cache_id=push_gw), NO_ROUTES])

    reply = caller.invite(YETI)
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert registered.is_set(), "device was not registered on push"

    assert len(push_server.requests) == 1, push_server.requests
    check_push(push_server.requests[0], caller)

    inv = term_gw.invite_req
    assert inv is not None and inv.ruri == contact, inv and inv.raw

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


def test_push_without_registration(rpc, routing, cdrs, caller, push_server):
    """push is accepted but the device does not register: not registered after push timeout"""
    routing.set_profiles([aor_profile(AOR2["id"], legb_gw_cache_id=GW_PUSH_WEBHOOK), NO_ROUTES])

    start = time.monotonic()
    reply = caller.invite(YETI, timeout=PUSH_TIMEOUT + 5)
    elapsed = time.monotonic() - start
    assert reply is not None, "no final reply for INVITE"
    assert (reply.code, reply.reason) == NOT_REGISTERED, reply.raw
    assert len(push_server.requests) == 1, push_server.requests
    assert PUSH_TIMEOUT - 0.5 <= elapsed <= PUSH_TIMEOUT + 2, f"rejected after {elapsed:.2f}s"

    assert_call_cleaned_up(rpc, cdrs, caller, code=0, reason="", internal=NOT_REGISTERED)


def test_push_rejected(rpc, routing, cdrs, caller, push_server):
    """non-2xx reply from the push destination stops waiting at once"""
    push_server.reply_code = 500
    routing.set_profiles([aor_profile(AOR2["id"], legb_gw_cache_id=GW_PUSH_WEBHOOK), NO_ROUTES])

    start = time.monotonic()
    reply = caller.invite(YETI, timeout=PUSH_TIMEOUT + 5)
    elapsed = time.monotonic() - start
    assert reply is not None, "no final reply for INVITE"
    assert (reply.code, reply.reason) == NOT_REGISTERED, reply.raw
    assert len(push_server.requests) == 1, push_server.requests
    assert elapsed < PUSH_TIMEOUT - 1, f"rejected after {elapsed:.2f}s, push timeout was not interrupted"

    assert_call_cleaned_up(rpc, cdrs, caller, code=0, reason="", internal=NOT_REGISTERED)


def test_no_push_when_registered(rpc, routing, cdrs, caller, term_gw, make_registrant, push_server):
    registrant, contact = device_registrant(make_registrant, term_gw)
    assert registrant.register(YETI, f"<{contact}>").code == 200
    routing.set_profiles([aor_profile(AOR2["id"], legb_gw_cache_id=GW_PUSH_WEBHOOK), NO_ROUTES])

    reply = caller.invite(YETI)
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert term_gw.invite_req.ruri == contact
    assert push_server.requests == [], push_server.requests

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


def test_no_push_with_alternative_route(rpc, routing, cdrs, caller, term_gw, push_server):
    """push is not sent when there is a profile not requiring registration"""
    routing.set_profiles([
        aor_profile(AOR2["id"], legb_gw_cache_id=GW_PUSH_WEBHOOK),
        route_to(term_gw),
        NO_ROUTES,
    ])

    reply = caller.invite(YETI)
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert term_gw.invite_req is not None
    assert push_server.requests == [], push_server.requests

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)


def test_no_push_token(rpc, routing, cdrs, caller, push_server):
    """B-leg gateway without push_token: not registered at once"""
    routing.set_profiles([aor_profile(AOR2["id"]), NO_ROUTES])

    reply = caller.invite(YETI)
    assert reply is not None and (reply.code, reply.reason) == NOT_REGISTERED, reply and reply.raw
    assert push_server.requests == [], push_server.requests
