"""
auth feedback (yeti 'enable_auth_feedback', disabled by default).

with the option enabled auth challenges and errors contain 'X-Yeti-Auth-Error: <code>'
with the reason of the authentication failure (Auth::error_type):
   0 no Authorization header (challenge)
   2 no username in Authorization header
   3 no credentials for username
  10 + uac_auth UACAuthErrorCodes for digest check errors:
       13 realm mismatch, 15 incorrect nonce, 18 response not matched (wrong password)
the same code is written to the auth log (writeauth statement, auth_error_id field) regardless
of the option. successful authentication has no header and auth_error_id is NULL.

the option is read on start only, so every case runs against the main SEMS (feedback disabled:
no header) and against separate SEMS started with enable_auth_feedback = true
(conftest SEMS_VARIANTS "auth_feedback", ports shifted by 100)
"""

import re

import pytest

from checks import assert_call_cleaned_up
from profiles import AOR1, NO_ROUTES, YETI, YETI_AUTH_FEEDBACK, Routing, route_to
from sip_ua import digest_authorization

HDR = "x-yeti-auth-error"

NO_AUTH = 0
NO_USERNAME = 2
NO_CREDENTIALS = 3
REALM_MISMATCH = 13
NONCE_INCORRECT = 15
RESPONSE_NOT_MATCHED = 18

CONTACT = "<sip:device@127.0.0.1:40100>"


class Target:
    def __init__(self, addr, rpc, feedback):
        self.addr = addr
        self.rpc = rpc
        self.feedback = feedback


@pytest.fixture(params=["feedback_disabled", "feedback_enabled"])
def target(request, rpc):
    if request.param == "feedback_disabled":
        return Target(YETI, rpc, False)
    return Target(YETI_AUTH_FEEDBACK, request.getfixturevalue("rpc_auth_feedback"), True)


def challenge(target, registrant):
    """REGISTER without Authorization, returns 401 reply"""
    reply = registrant.register(target.addr, CONTACT, retry_auth=False)
    assert reply is not None and reply.code == 401, reply and reply.raw
    assert reply.header("www-authenticate"), reply.raw
    return reply


def register_with(target, registrant, authorization):
    reply = registrant.register(target.addr, CONTACT, extra=[f"Authorization: {authorization}"], retry_auth=False)
    assert reply is not None, "no reply"
    return reply


def patched_authorization(target, chlg_reply, user, password, method="REGISTER", uri=None, **replace):
    """digest Authorization for the challenge with replaced challenge params (realm, nonce)"""
    chlg = chlg_reply.header("www-authenticate")
    for k, v in replace.items():
        chlg = re.sub(rf'{k}="[^"]*"', f'{k}="{v}"', chlg)
    return digest_authorization(chlg, method, uri or f"sip:{target.addr[0]}:{target.addr[1]}", user, password)


def assert_feedback(target, reply, code):
    if target.feedback:
        assert reply.header(HDR) == str(code), f"expected {HDR}: {code}\n{reply.raw}"
    else:
        assert reply.header(HDR) is None, f"{HDR} with disabled auth feedback\n{reply.raw}"


def assert_logged(auth_log, call_id, error_id, count):
    """auth log has the error code regardless of auth feedback option"""
    records = auth_log.wait(call_id, count=count)
    assert len(records) >= count, records
    last = records[count - 1]
    assert last["auth_error_id"] == error_id, last
    assert last["success"] is (error_id is None), last
    return last


def test_no_authorization(target, auth_log, make_registrant):
    r = make_registrant(AOR1["user"], AOR1["password"])
    reply = challenge(target, r)
    assert_feedback(target, reply, NO_AUTH)
    rec = assert_logged(auth_log, r.call_id, NO_AUTH, 1)
    assert rec["code"] == 401 and rec["internal_reason"] == "no Authorization header", rec


def test_no_username(target, auth_log, make_registrant):
    r = make_registrant(AOR1["user"], AOR1["password"])
    reply = register_with(target, r, 'Digest realm="e2e", nonce="e2e", uri="sip:127.0.0.1", response="e2e"')
    assert reply.code == 401, reply.raw
    assert reply.header("www-authenticate"), "no challenge"
    assert_feedback(target, reply, NO_USERNAME)
    assert_logged(auth_log, r.call_id, NO_USERNAME, 1)


def test_unknown_username(target, auth_log, make_registrant):
    r = make_registrant("unknown-user", "password")
    chlg = challenge(target, r)
    reply = register_with(target, r, patched_authorization(target, chlg, "unknown-user", "password"))
    assert reply.code == 401, reply.raw
    assert_feedback(target, reply, NO_CREDENTIALS)
    rec = assert_logged(auth_log, r.call_id, NO_CREDENTIALS, 2)
    assert rec["username"] == "unknown-user", rec


def test_wrong_password(target, auth_log, make_registrant):
    r = make_registrant(AOR1["user"], "wrong-password")
    reply = r.register(target.addr, CONTACT)
    assert reply.code == 401, reply.raw
    assert_feedback(target, reply, RESPONSE_NOT_MATCHED)
    rec = assert_logged(auth_log, r.call_id, RESPONSE_NOT_MATCHED, 2)
    assert rec["username"] == AOR1["user"], rec


def test_realm_mismatch(target, auth_log, make_registrant):
    r = make_registrant(AOR1["user"], AOR1["password"])
    chlg = challenge(target, r)
    reply = register_with(target, r, patched_authorization(target, chlg, AOR1["user"], AOR1["password"],
                                                           realm="wrong.realm"))
    assert reply.code == 401, reply.raw
    assert_feedback(target, reply, REALM_MISMATCH)
    assert_logged(auth_log, r.call_id, REALM_MISMATCH, 2)


def test_incorrect_nonce(target, auth_log, make_registrant):
    r = make_registrant(AOR1["user"], AOR1["password"])
    chlg = challenge(target, r)
    reply = register_with(target, r, patched_authorization(target, chlg, AOR1["user"], AOR1["password"],
                                                           nonce="deadbeef"))
    assert reply.code == 401, reply.raw
    assert_feedback(target, reply, NONCE_INCORRECT)
    assert_logged(auth_log, r.call_id, NONCE_INCORRECT, 2)


def test_success(target, auth_log, make_registrant):
    r = make_registrant(AOR1["user"], AOR1["password"])
    reply = r.register(target.addr, CONTACT)
    assert reply.code == 200, reply.raw
    assert reply.header(HDR) is None, reply.raw
    rec = assert_logged(auth_log, r.call_id, None, 2)
    assert rec["auth_id"] == AOR1["id"] and rec["username"] == AOR1["user"], rec


def invite_authorization(target, make_registrant, password):
    chlg = challenge(target, make_registrant(AOR1["user"], AOR1["password"]))
    ruri = f"sip:1234@{target.addr[0]}:{target.addr[1]}"
    return patched_authorization(target, chlg, AOR1["user"], password, method="INVITE", uri=ruri)


def test_invite_wrong_password(target, auth_log, make_registrant, caller):
    """INVITE with failed digest check is rejected"""
    authorization = invite_authorization(target, make_registrant, "wrong-password")

    reply = caller.invite(target.addr, headers=[f"Authorization: {authorization}"])
    assert reply is not None and reply.code == 401, reply and reply.raw
    assert_feedback(target, reply, RESPONSE_NOT_MATCHED)
    rec = assert_logged(auth_log, caller.call_id, RESPONSE_NOT_MATCHED, 1)
    assert rec["method"] == "INVITE", rec


def test_invite_authorized(target, cdrs, auth_log, make_registrant, caller, term_gw):
    """INVITE with correct digest is authorized (auth_id in auth log) and routed"""
    authorization = invite_authorization(target, make_registrant, AOR1["password"])
    routing = Routing(target.rpc)
    routing.set_profiles([route_to(term_gw), NO_ROUTES])
    try:
        reply = caller.invite(target.addr, headers=[f"Authorization: {authorization}"])
        assert reply is not None and reply.code == 200, reply and reply.raw
        assert reply.header(HDR) is None, reply.raw
        rec = assert_logged(auth_log, caller.call_id, None, 1)
        assert rec["auth_id"] == AOR1["id"] and rec["method"] == "INVITE", rec
        assert caller.bye().code == 200
        assert_call_cleaned_up(target.rpc, cdrs, caller, term_gw)
    finally:
        routing.reset()
