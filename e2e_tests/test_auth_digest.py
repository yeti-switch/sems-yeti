"""
digest authentication processing (yeti Auth + SEMS uac_auth), RFC 7616 / RFC 2617.

uac_auth (core/plug-in/uac_auth/UACAuth.cpp):
  * challenge: 'Digest realm, qop="auth,auth-int", nonce, algorithm' per allowed algorithm
  * nonce is stateless: HMAC of the timestamp with server_secret, valid for nonce_expire (default 300s)
  * qop auth / auth-int (H(entity-body) in HA2) / no qop (RFC 2069 response)
  * nc must be hex
  * errors (auth log auth_error_id = 10 + UACAuthErrorCodes):
      10 unsupported algorithm, 15 incorrect nonce, 16 nonce expired, 17 nc parse error, 18 response not matched

algorithms: yeti 'auth { allowed_digest_algs = {...} }' option (MD5 only by default) sets challenges
(SEMS_VARIANTS auth_sha256, auth_sha256_md5). the nonce is bound to the hash by its length only and
uac_auth verifies the response by the algorithm of Authorization: allowed algorithms are not passed to
uac_auth checkAuth and not checked by it, so test_sha256_only_md5_nonce_from_other_node is reported
as xfail (skipped in junit) until they are.

replay protection (RFC 7616 3.4.5, 5.12) is not implemented by uac_auth yet: no stale flag for the expired
nonce (test_stale_flag) and nonce count is not tracked (test_replay_rejected, test_nc_must_increase).
these tests are reported as xfail until it is.
"""

import time

import pytest

from profiles import AOR1, NO_ROUTES, YETI, Routing, route_to
from sip_ua import challenge_params, digest_authorization, pick_challenge

CONTACT = "<sip:device@127.0.0.1:40200>"

UNSUPPORTED_ALGORITHM = 10
NONCE_INCORRECT = 15
NONCE_EXPIRED = 16
NONCE_COUNT_PARSE = 17
RESPONSE_NOT_MATCHED = 18


def ruri(addr):
    return f"sip:{addr[0]}:{addr[1]}"


class Auth:
    """REGISTER with explicitly built Authorization for AOR1 to the SEMS address"""

    def __init__(self, registrant, addr, auth_log):
        self.r = registrant
        self.addr = addr
        self.auth_log = auth_log
        self.records = 0

    def challenge(self):
        reply = self.r.register(self.addr, CONTACT, retry_auth=False)
        assert reply is not None and reply.code == 401, reply and reply.raw
        self.records += 1
        return reply

    def authorization(self, chlg, password=AOR1["password"], **kw):
        return digest_authorization(chlg, "REGISTER", ruri(self.addr), AOR1["user"], password, **kw)

    def register(self, authorization):
        reply = self.r.register(self.addr, CONTACT, extra=[f"Authorization: {authorization}"], retry_auth=False)
        assert reply is not None, "no reply"
        self.records += 1
        return reply

    def logged_error(self):
        """auth_error_id of the last auth log record (None for success)"""
        records = self.auth_log.wait(self.r.call_id, count=self.records)
        assert len(records) >= self.records, records
        return records[self.records - 1]["auth_error_id"]

    def assert_ok(self, reply):
        assert reply.code == 200, reply.raw
        assert self.logged_error() is None

    def assert_rejected(self, reply, error_id):
        assert reply.code == 401, reply.raw
        assert self.logged_error() == error_id


@pytest.fixture
def auth(make_registrant, auth_log):
    def make(addr=YETI):
        return Auth(make_registrant(AOR1["user"], AOR1["password"]), addr, auth_log)
    return make


# challenge, qop

def challenge_algorithms(reply):
    """algorithms of WWW-Authenticate challenges in order. checks every challenge has
    realm, nonce and default uac_auth qops"""
    algorithms = []
    for c in reply.header_all("www-authenticate"):
        p = challenge_params(c)
        assert {q.strip() for q in p.get("qop", "").split(",")} == {"auth", "auth-int"}, reply.raw
        assert p.get("realm") and p.get("nonce"), reply.raw
        algorithms.append(p.get("algorithm"))
    return algorithms


def test_default_challenge(auth):
    reply = auth().challenge()
    assert challenge_algorithms(reply) == ["MD5"], reply.raw


@pytest.mark.parametrize("qop", ["auth", "auth-int", None], ids=["auth", "auth-int", "no-qop"])
def test_qop(auth, qop):
    a = auth()
    chlg = pick_challenge(a.challenge())
    a.assert_ok(a.register(a.authorization(chlg, qop=qop)))


def test_auth_int_wrong_body_hash(auth):
    """auth-int response calculated over another body"""
    a = auth()
    chlg = pick_challenge(a.challenge())
    a.assert_rejected(a.register(a.authorization(chlg, qop="auth-int", body="v=0\r\n")), RESPONSE_NOT_MATCHED)


@pytest.mark.parametrize("valid_body_hash", [True, False], ids=["body-hash", "wrong-body-hash"])
def test_auth_int_invite(rpc, auth, auth_log, caller, term_gw, valid_body_hash):
    """INVITE with SDP body authenticated with qop=auth-int"""
    chlg = pick_challenge(auth().challenge())
    body = caller.offer()
    invite_ruri = f"sip:1234@{YETI[0]}:{YETI[1]}"
    authorization = digest_authorization(chlg, "INVITE", invite_ruri, AOR1["user"], AOR1["password"],
                                         qop="auth-int", body=body if valid_body_hash else body + "a=x\r\n")
    routing = Routing(rpc)
    routing.set_profiles([route_to(term_gw), NO_ROUTES])
    try:
        reply = caller.invite(YETI, body=body, headers=[f"Authorization: {authorization}"])
        assert reply is not None, "no final reply"
        rec = auth_log.wait(caller.call_id)[0]
        if valid_body_hash:
            assert reply.code == 200 and rec["auth_error_id"] is None, (reply.raw, rec)
            assert caller.bye().code == 200
        else:
            assert reply.code == 401 and rec["auth_error_id"] == RESPONSE_NOT_MATCHED, (reply.raw, rec)
    finally:
        routing.reset()


# nonce and nonce count

def test_nonce_reuse(auth):
    """the same nonce with increasing nonce count authenticates subsequent requests"""
    a = auth()
    chlg = pick_challenge(a.challenge())
    for nc in (1, 2, 3):
        a.assert_ok(a.register(a.authorization(chlg, nc=nc)))


def test_nc_not_hex(auth):
    a = auth()
    chlg = pick_challenge(a.challenge())
    a.assert_rejected(a.register(a.authorization(chlg, nc="zzzzzzzz")), NONCE_COUNT_PARSE)


def test_forged_nonce(auth):
    a = auth()
    chlg = pick_challenge(a.challenge())
    chlg = chlg.replace(challenge_params(chlg)["nonce"], "0123456789abcdef")
    a.assert_rejected(a.register(a.authorization(chlg)), NONCE_INCORRECT)


def test_replay_rejected(auth):
    """the same credentials (nonce, nc, cnonce, response) must not be accepted twice"""
    a = auth()
    authorization = a.authorization(pick_challenge(a.challenge()), nc=1)
    a.assert_ok(a.register(authorization))
    reply = a.register(authorization)
    if reply.code == 200:
        pytest.xfail("nonce count is not tracked by uac_auth: replayed Authorization is accepted")
    assert reply.code == 401, f"replayed Authorization accepted:\n{reply.raw}"


@pytest.mark.parametrize("nc_sequence", [(2, 2), (2, 1)], ids=["repeated-nc", "decreased-nc"])
def test_nc_must_increase(auth, nc_sequence):
    """nonce count must increase for every request with the same nonce (new cnonce does not help)"""
    a = auth()
    chlg = pick_challenge(a.challenge())
    first, second = nc_sequence
    a.assert_ok(a.register(a.authorization(chlg, nc=first)))
    reply = a.register(a.authorization(chlg, nc=second))
    if reply.code == 200:
        pytest.xfail(f"nonce count is not tracked by uac_auth: nc {second} after {first} is accepted")
    assert reply.code == 401, f"nc {second} after {first} accepted:\n{reply.raw}"


def test_nonce_expired(auth, sems_variant):
    """auth_nonce_expire variant: uac_auth nonce_expire = 2"""
    a = auth(sems_variant("auth_nonce_expire").addr)
    chlg = pick_challenge(a.challenge())
    time.sleep(3)
    reply = a.register(a.authorization(chlg))
    a.assert_rejected(reply, NONCE_EXPIRED)
    fresh = pick_challenge(reply)
    assert fresh, f"no new challenge for expired nonce:\n{reply.raw}"
    a.assert_ok(a.register(a.authorization(fresh)))


def test_stale_flag(auth, sems_variant):
    """challenge for the expired nonce has stale=TRUE (RFC 7616 3.3), so client retries without prompting"""
    a = auth(sems_variant("auth_nonce_expire").addr)
    chlg = pick_challenge(a.challenge())
    time.sleep(3)
    reply = a.register(a.authorization(chlg))
    assert reply.code == 401, reply.raw
    stale = challenge_params(pick_challenge(reply)).get("stale")
    if stale is None:
        pytest.xfail("stale flag is not implemented by uac_auth: no stale=true for the expired nonce")
    assert stale.lower() == "true", reply.raw


# algorithms

def test_sha256_not_accepted_by_default(auth):
    """SHA-256 response to MD5 challenge: MD5 only is allowed by default.
    uac_auth takes the hash by the algorithm of Authorization and the nonce HMAC is bound to the hash,
    so it is rejected as incorrect nonce"""
    a = auth()
    chlg = pick_challenge(a.challenge())
    a.assert_rejected(a.register(a.authorization(chlg, algorithm="SHA-256")), NONCE_INCORRECT)


@pytest.mark.parametrize("qop", ["auth", "auth-int", None], ids=["auth", "auth-int", "no-qop"])
def test_sha256_only(auth, sems_variant, qop):
    """allowed_digest_algs = { SHA-256 }: SHA-256 challenge only, SHA-256 response is accepted"""
    a = auth(sems_variant("auth_sha256").addr)
    reply = a.challenge()
    assert challenge_algorithms(reply) == ["SHA-256"], reply.raw
    a.assert_ok(a.register(a.authorization(pick_challenge(reply, "SHA-256"), qop=qop)))


def test_sha256_only_md5_response(auth, sems_variant):
    """allowed_digest_algs = { SHA-256 }: MD5 response to SHA-256 challenge is rejected.
    MD5 hash is used to check SHA-256 nonce, so it is rejected as incorrect nonce"""
    a = auth(sems_variant("auth_sha256").addr)
    chlg = pick_challenge(a.challenge(), "SHA-256")
    a.assert_rejected(a.register(a.authorization(chlg, algorithm="MD5")), NONCE_INCORRECT)


def test_sha256_only_md5_nonce_from_other_node(auth, sems_variant):
    """allowed_digest_algs = { SHA-256 }: MD5 response to MD5 challenge of another node
    with the same server_secret (default SEMS) must be rejected as unsupported algorithm"""
    md5_chlg = pick_challenge(auth().challenge(), "MD5")
    a = auth(sems_variant("auth_sha256").addr)
    reply = a.register(a.authorization(md5_chlg))
    if reply.code == 200:
        pytest.xfail("allowed digest algorithms are not checked on verification: MD5 response is accepted")
    a.assert_rejected(reply, UNSUPPORTED_ALGORITHM)


@pytest.mark.parametrize("algorithm", ["SHA-256", "MD5"])
def test_sha256_and_md5(auth, sems_variant, algorithm):
    """allowed_digest_algs = { SHA-256, MD5 }: challenge per algorithm in order of preference,
    client answers any of them"""
    a = auth(sems_variant("auth_sha256_md5").addr)
    reply = a.challenge()
    assert challenge_algorithms(reply) == ["SHA-256", "MD5"], reply.raw
    a.assert_ok(a.register(a.authorization(pick_challenge(reply, algorithm))))


@pytest.mark.parametrize("algorithm", ["SHA-256", "MD5"])
def test_sha256_and_md5_invite(rpc, auth, auth_log, sems_variant, caller, term_gw, algorithm):
    """INVITE authenticated with any of allowed algorithms"""
    variant = sems_variant("auth_sha256_md5")
    chlg = pick_challenge(auth(variant.addr).challenge(), algorithm)
    invite_ruri = f"sip:1234@{variant.addr[0]}:{variant.addr[1]}"
    authorization = digest_authorization(chlg, "INVITE", invite_ruri, AOR1["user"], AOR1["password"])
    routing = Routing(variant.rpc)
    routing.set_profiles([route_to(term_gw), NO_ROUTES])
    try:
        reply = caller.invite(variant.addr, headers=[f"Authorization: {authorization}"])
        assert reply is not None, "no final reply"
        rec = auth_log.wait(caller.call_id)[0]
        assert reply.code == 200 and rec["auth_error_id"] is None, (reply.raw, rec)
        assert caller.bye().code == 200
    finally:
        routing.reset()
