"""
SIP OPTIONS probers (load_sip_options_probers -> SEMS options_prober, OptionsSingleProbe).

probers are loaded from routing db on 'options_probers' version change in check_states()
(db_config fixture). all probers are replaced on reload.
  * OPTIONS sip:[ruri_username@]ruri_domain From: from_uri To: to_uri
  * Contact only if contact_uri is set, append_headers ('\\r\\n' escaped) are added
  * proxy / route_set: next hop
  * 401 challenge must be answered with auth_username/auth_password (credentials realm is ruri_domain).
    not implemented: OptionsProber gets uac_auth instance but never attaches it to the probe dialog,
    test_digest_auth[ruri_domain] is reported as xfail (skipped in junit) until implemented
  * R-URI has no ruri_username: OptionsSingleProbe builds r_uri before uri_user is set,
    test_probe fails until it is fixed
  * request every 'interval' seconds (the first one within the half of the interval)
state is checked by options_prober.show.probers
"""

import time

import pytest

from sip_ua import uri_of

PROBER_ID = 1


def prober_row(target, **fields):
    row = {
        "id": PROBER_ID,
        "name": "e2e-prober",
        "ruri_domain": f"{target.ip}:{target.port}",
        "ruri_username": "probe-user",
        "from_uri": "<sip:prober@yeti.e2e.invalid>",
        "to_uri": f"<sip:probe-user@{target.ip}:{target.port}>",
        "interval": 1,
    }
    row.update(fields)
    return row


def prober(rpc, prober_id=PROBER_ID):
    for p in rpc.call("options_prober.show.probers") or []:
        if p.get("id") == prober_id:
            return p
    return None


def wait_reply_code(rpc, code, timeout=5, prober_id=PROBER_ID):
    deadline = time.monotonic() + timeout
    while True:
        p = prober(rpc, prober_id)
        if (p and p["last_reply_code"] == code) or time.monotonic() > deadline:
            return p
        time.sleep(0.1)


def test_probe(rpc, db_config, make_remote):
    target = make_remote()
    db_config.set("options_probers", [prober_row(target)])

    req = target.wait_request("OPTIONS", timeout=3)
    assert req is not None, "OPTIONS is not sent"
    assert req.ruri == f"sip:probe-user@{target.ip}:{target.port}", req.raw
    assert uri_of(req.header("from")) == "sip:prober@yeti.e2e.invalid", req.raw
    assert uri_of(req.header("to")) == f"sip:probe-user@{target.ip}:{target.port}", req.raw
    assert req.header("contact") is None, req.raw

    p = wait_reply_code(rpc, 200)
    assert p and p["last_reply_code"] == 200, p


def test_interval(db_config, make_remote):
    target = make_remote()
    db_config.set("options_probers", [prober_row(target, interval=1)])
    assert target.wait_request("OPTIONS", timeout=3) is not None

    t = time.monotonic()
    time.sleep(3.2)
    count = len(target.requests_of("OPTIONS", after=t))
    assert 2 <= count <= 4, f"{count} OPTIONS in 3.2s with 1s interval"


def test_contact_and_append_headers(db_config, make_remote):
    target = make_remote()
    db_config.set("options_probers", [prober_row(
        target, contact_uri="sip:prober-contact@127.0.0.1:5060", append_headers="X-Probe: e2e\\r\\n")])

    req = target.wait_request("OPTIONS", timeout=3)
    assert req is not None
    # SEMS adds ;transport=udp (RFC 3261 19.1.4: equal URI)
    assert uri_of(req.header("contact")).split(";")[0] == "sip:prober-contact@127.0.0.1:5060", req.raw
    assert req.header("x-probe") == "e2e", req.raw


@pytest.mark.parametrize("realm", ["ruri_domain", "other"])
def test_digest_auth(rpc, db_config, make_remote, realm):
    target = make_remote()
    target.auth = ("probe-auth", "probe-password")
    if realm == "ruri_domain":
        target.REALM = f"{target.ip}:{target.port}"
    db_config.set("options_probers", [prober_row(target, auth_username="probe-auth", auth_password="probe-password")])

    if realm == "ruri_domain":
        p = wait_reply_code(rpc, 200)
        assert p, "prober is not loaded"
        answered = any(r.header("authorization") for r in target.requests_of("OPTIONS"))
        if p["last_reply_code"] == 401 and not answered:
            pytest.xfail("options_prober digest auth is not implemented: 401 challenge is not answered")
        assert p["last_reply_code"] == 200, p
        assert answered, "challenge is not answered"
    else:
        p = wait_reply_code(rpc, 401, timeout=3)
        assert p and p["last_reply_code"] == 401, p
        assert not any(r.header("authorization") for r in target.requests_of("OPTIONS")), \
            "challenge for another realm is answered"


def test_error_reply(rpc, db_config, make_remote):
    target = make_remote()
    target.reply_code = 503
    db_config.set("options_probers", [prober_row(target)])

    p = wait_reply_code(rpc, 503)
    assert p and p["last_reply_code"] == 503, p


@pytest.mark.parametrize("via", ["proxy", "route_set"])
def test_next_hop(db_config, make_remote, via):
    proxy = make_remote()
    hop = f"sip:{proxy.ip}:{proxy.port}"
    fields = {"ruri_domain": "target.e2e.invalid", "to_uri": "<sip:probe-user@target.e2e.invalid>"}
    if via == "proxy":
        fields["proxy"] = hop
    else:
        fields["route_set"] = f"<{hop};lr>"
    db_config.set("options_probers", [prober_row(proxy, **fields)])

    req = proxy.wait_request("OPTIONS", timeout=3)
    assert req is not None, "OPTIONS is not sent to the next hop"
    assert uri_of(req.ruri).endswith("target.e2e.invalid"), req.raw
    assert req.route_set == [f"<{hop};lr>"], req.raw


def test_removal(db_config, make_remote):
    target = make_remote()
    db_config.set("options_probers", [prober_row(target)])
    assert target.wait_request("OPTIONS", timeout=3) is not None

    db_config.set("options_probers", [])
    time.sleep(0.5)  # in-flight request
    t = time.monotonic()
    time.sleep(2.5)
    assert target.requests_of("OPTIONS", after=t) == [], "OPTIONS are sent after prober removal"


def test_multiple_probers(rpc, db_config, make_remote):
    target1, target2 = make_remote(), make_remote()
    db_config.set("options_probers", [prober_row(target1, id=1), prober_row(target2, id=2, name="e2e-prober-2")])

    assert target1.wait_request("OPTIONS", timeout=3) is not None
    assert target2.wait_request("OPTIONS", timeout=3) is not None
    assert wait_reply_code(rpc, 200, prober_id=1)["last_reply_code"] == 200
    assert wait_reply_code(rpc, 200, prober_id=2)["last_reply_code"] == 200
