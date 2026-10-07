"""
outgoing registrations (load_registrations_out -> SEMS registrar_client, core AmSIPRegistration).

registrations are loaded from routing db on 'registrations' version change in check_states()
(db_config fixture), removed ones are unregistered, new ones are registered.
  * REGISTER sip:<o_domain> From/To: "<o_display_name>" <sip:o_user@o_domain>, Expires: <o_expire>,
    Contact: o_contact or <sip:o_user@local interface>
  * 401 challenge is answered with o_auth_user/o_auth_password
  * expires: matched Contact 'expires' param, Expires header, or o_expire if both missed
    or o_force_expire is set. re-REGISTER at the half of the expires
  * 200 OK without our Contact: error 'no matching Contact in positive reply'
  * error replies: retry after o_retry_delay, up to o_max_attempts (0: unlimited)
  * o_proxy / o_route_set: next hop for REGISTER
state is checked by yeti.show.registrations
"""

import time

import pytest

from sip_ua import uri_hostport, uri_of, uri_user

REG_ID = "1"
REG_USER = "reg-user"


def reg_row(server, **fields):
    row = {
        "o_id": REG_ID,
        "o_domain": f"{server.ip}:{server.port}",
        "o_user": REG_USER,
        "o_display_name": "Yeti Registration",
        "o_auth_user": "auth-user",
        "o_auth_password": "auth-password",
        "o_expire": 60,
        "o_retry_delay": 1,
    }
    row.update(fields)
    return row


def registration(rpc, reg_id=REG_ID):
    for r in rpc.call("yeti.show.registrations") or []:
        if str(r.get("id")) == reg_id:
            return r
    return None


def wait_state(rpc, state, timeout=5, reg_id=REG_ID):
    deadline = time.monotonic() + timeout
    while True:
        r = registration(rpc, reg_id)
        if r and r["state"] == state:
            return r
        if time.monotonic() > deadline:
            return r
        time.sleep(0.1)


def registers(server, after=None):
    return server.requests_of("REGISTER", after=after)


def wait_registers(server, count, timeout, after=None):
    deadline = time.monotonic() + timeout
    while len(registers(server, after)) < count and time.monotonic() < deadline:
        time.sleep(0.05)
    return registers(server, after)


def test_register(rpc, db_config, make_remote):
    server = make_remote()
    db_config.set("registrations", [reg_row(server)])

    req = server.wait_request("REGISTER")
    assert req is not None, "REGISTER is not sent"
    assert req.ruri == f"sip:{server.ip}:{server.port}", req.raw
    for hdr in ("from", "to"):
        assert uri_of(req.header(hdr)) == f"sip:{REG_USER}@{server.ip}:{server.port}", req.raw
        assert '"Yeti Registration"' in req.header(hdr), req.raw
    assert req.header("expires") == "60", req.raw
    contact = uri_of(req.header("contact"))
    assert uri_user(contact) == REG_USER and uri_hostport(contact)[0] == "127.0.0.1", req.raw

    r = wait_state(rpc, "RegisterActive")
    assert r and r["state"] == "RegisterActive", r
    assert r["expires"] == 60, r


def test_custom_contact(rpc, db_config, make_remote):
    server = make_remote()
    db_config.set("registrations", [reg_row(server, o_contact="sip:custom-contact@127.0.0.1:5060")])

    req = server.wait_request("REGISTER")
    assert req is not None
    # SEMS adds ;transport=udp (RFC 3261 19.1.4: equal URI)
    assert uri_of(req.header("contact")).split(";")[0] == "sip:custom-contact@127.0.0.1:5060", req.raw
    assert wait_state(rpc, "RegisterActive")["state"] == "RegisterActive"


def test_digest_auth(rpc, db_config, make_remote):
    server = make_remote()
    server.auth = ("auth-user", "auth-password")
    db_config.set("registrations", [reg_row(server)])

    r = wait_state(rpc, "RegisterActive")
    assert r and r["state"] == "RegisterActive", r
    regs = registers(server)
    assert regs[0].header("authorization") is None
    assert regs[1].header("authorization"), "challenge is not answered"


def test_digest_auth_wrong_password(rpc, db_config, make_remote):
    server = make_remote()
    server.auth = ("auth-user", "other-password")
    db_config.set("registrations", [reg_row(server)])

    r = wait_state(rpc, "RegisterError")
    assert r and r["state"] == "RegisterError", r
    assert r["last_error_code"] in (401, 403), r


def test_reregister_at_half_expires(rpc, db_config, make_remote):
    """registrar grants 4s in Contact param: re-REGISTER in ~2s"""
    server = make_remote()
    server.granted_expires = 4
    db_config.set("registrations", [reg_row(server)])

    regs = wait_registers(server, 2, timeout=6)
    assert len(regs) >= 2, regs
    interval = regs[1].time - regs[0].time
    assert 1.5 <= interval <= 3.5, f"re-REGISTER after {interval:.1f}s, expected ~2s"
    assert registration(rpc)["expires"] == 4


def test_expires_from_header(rpc, db_config, make_remote):
    """no 'expires' param in Contact: Expires header is used"""
    server = make_remote()
    server.granted_expires = 4
    server.expires_in = "header"
    db_config.set("registrations", [reg_row(server)])

    regs = wait_registers(server, 2, timeout=6)
    assert len(regs) >= 2, regs
    assert 1.5 <= regs[1].time - regs[0].time <= 3.5
    assert registration(rpc)["expires"] == 4


def test_expires_missed(rpc, db_config, make_remote):
    """neither Contact param nor Expires header: own o_expire is used"""
    server = make_remote()
    server.granted_expires = 4
    server.expires_in = "none"
    db_config.set("registrations", [reg_row(server)])

    r = wait_state(rpc, "RegisterActive")
    assert r and r["expires"] == 60, r


def test_force_expires(rpc, db_config, make_remote):
    """o_force_expire: own interval is used regardless of the granted one"""
    server = make_remote()
    server.granted_expires = 4
    db_config.set("registrations", [reg_row(server, o_force_expire=True)])

    r = wait_state(rpc, "RegisterActive")
    assert r and r["expires"] == 60, r
    assert len(wait_registers(server, 2, timeout=4)) == 1, "re-REGISTER by granted expires"


def test_no_matching_contact(rpc, db_config, make_remote):
    server = make_remote()
    server.contact_mode = "other"
    db_config.set("registrations", [reg_row(server)])

    r = wait_state(rpc, "RegisterError")
    assert r and r["state"] == "RegisterError", r
    assert r["last_error_reason"] == "no matching Contact in positive reply", r


def test_retry_after_error(rpc, db_config, make_remote):
    server = make_remote()
    server.reply_code = 503
    db_config.set("registrations", [reg_row(server, o_retry_delay=1)])

    regs = wait_registers(server, 2, timeout=5)
    assert len(regs) >= 2, "REGISTER is not retried"
    assert 0.5 <= regs[1].time - regs[0].time <= 3.5
    r = registration(rpc)
    assert r["last_error_code"] == 503, r


def test_max_attempts(rpc, db_config, make_remote):
    """AmSIPRegistration checks max_attempts only for REGISTER send timeouts (onRegisterSendTimeout),
    error replies are retried endlessly (SIPRegistrarClient::onTimer): fails until fixed"""
    server = make_remote()
    server.reply_code = 503
    db_config.set("registrations", [reg_row(server, o_retry_delay=1, o_max_attempts=2)])

    time.sleep(5)
    assert len(registers(server)) == 2, registers(server)


@pytest.mark.parametrize("via", ["proxy", "route_set"])
def test_next_hop(rpc, db_config, make_remote, via):
    """REGISTER for the domain is sent to the proxy (loose route)"""
    proxy = make_remote()
    hop = f"sip:{proxy.ip}:{proxy.port}"
    fields = {"o_domain": "registrar.e2e.invalid"}
    if via == "proxy":
        fields["o_proxy"] = hop
    else:
        fields["o_route_set"] = f"<{hop};lr>"
    db_config.set("registrations", [reg_row(proxy, **fields)])

    req = proxy.wait_request("REGISTER")
    assert req is not None, "REGISTER is not sent to the next hop"
    assert req.ruri == "sip:registrar.e2e.invalid", req.raw
    assert req.route_set == [f"<{hop};lr>"], req.raw
    assert wait_state(rpc, "RegisterActive")["state"] == "RegisterActive"


def test_unregister_on_removal(rpc, db_config, make_remote):
    server = make_remote()
    db_config.set("registrations", [reg_row(server)])
    register = server.wait_request("REGISTER")
    assert wait_state(rpc, "RegisterActive")["state"] == "RegisterActive"

    t = time.monotonic()
    db_config.set("registrations", [])
    unregister = server.wait_request("REGISTER", after=t)
    assert unregister is not None, "no unregistration on removal"
    assert unregister.header("expires") == "0", unregister.raw
    assert uri_of(unregister.header("contact")) == uri_of(register.header("contact")), unregister.raw

    deadline = time.monotonic() + 3
    while registration(rpc) is not None and time.monotonic() < deadline:
        time.sleep(0.1)
    assert registration(rpc) is None, "registration is not removed"


def test_update(rpc, db_config, make_remote):
    """changed registration is re-created with the new parameters"""
    server = make_remote()
    db_config.set("registrations", [reg_row(server)])
    assert wait_state(rpc, "RegisterActive")["state"] == "RegisterActive"

    t = time.monotonic()
    db_config.set("registrations", [reg_row(server, o_expire=120)])
    req = server.wait_request("REGISTER", after=t, pred=lambda r: r.header("expires") == "120")
    assert req is not None, "no REGISTER with updated expires"
    deadline = time.monotonic() + 3
    while (registration(rpc) or {}).get("expires") != 120 and time.monotonic() < deadline:
        time.sleep(0.1)
    assert registration(rpc)["expires"] == 120


def test_multiple_registrations(rpc, db_config, make_remote):
    server1, server2 = make_remote(), make_remote()
    db_config.set("registrations", [reg_row(server1, o_id="1"), reg_row(server2, o_id="2", o_user="other-user")])

    assert server1.wait_request("REGISTER") is not None
    req = server2.wait_request("REGISTER")
    assert req is not None and uri_user(uri_of(req.header("from"))) == "other-user"
    assert wait_state(rpc, "RegisterActive", reg_id="1")["state"] == "RegisterActive"
    assert wait_state(rpc, "RegisterActive", reg_id="2")["state"] == "RegisterActive"
