"""
reliable provisional replies (RFC 3262, 100rel) on both legs. port of yeti-test test_prack.py

profile aleg_rel100_mode_id/bleg_rel100_mode_id (Am100rel::State):
  1 supported, 3 require

B-leg: yeti announces 100rel in INVITE to the gateway (Supported or Require)
       and PRACKs the reliable 183 from the gateway
A-leg: the mode is applied after routing, when the caller INVITE (with 'Supported: 100rel')
       is already processed, so:
         supported - 183 to the caller is not reliable, only 'Supported: 100rel' is added
         require   - 183 to the caller is reliable (Require: 100rel, RSeq) and must be PRACKed
"""

import time

import pytest

from checks import assert_call_cleaned_up
from profiles import NO_ROUTES, YETI, route_to
from sip_ua import EarlyReply

REL100_SUPPORTED = 1
REL100_REQUIRE = 3


@pytest.mark.parametrize("aleg_mode", [REL100_SUPPORTED, REL100_REQUIRE], ids=["aleg_supported", "aleg_require"])
@pytest.mark.parametrize("bleg_mode", [REL100_SUPPORTED, REL100_REQUIRE], ids=["bleg_supported", "bleg_require"])
def test_prack(rpc, routing, cdrs, caller, term_gw, aleg_mode, bleg_mode):
    routing.set_profiles([
        route_to(term_gw, aleg_rel100_mode_id=aleg_mode, bleg_rel100_mode_id=bleg_mode),
        NO_ROUTES,
    ])
    caller.supported = ["100rel"]
    term_gw.early_replies = [EarlyReply(183, "Session Progress", reliable=True)]

    reply = caller.invite(YETI)
    assert reply is not None and reply.code == 200, reply and reply.raw

    # B-leg
    inv = term_gw.invite_req
    if bleg_mode == REL100_SUPPORTED:
        assert inv.has_option_tag("supported", "100rel"), inv.raw
    else:
        assert inv.has_option_tag("require", "100rel"), inv.raw

    prack = term_gw.wait_request("PRACK", call_id=term_gw.call_id)
    assert prack is not None, "reliable 183 from gateway is not PRACKed by yeti"
    assert prack.header("rack") == f"1 {inv.cseq[0]} INVITE", prack.raw

    # A-leg
    r183 = [r for r in caller.provisional if r.code == 183]
    assert r183, f"183 is not relayed to caller: {caller.provisional}"
    if aleg_mode == REL100_SUPPORTED:
        assert r183[0].has_option_tag("supported", "100rel"), r183[0].raw
        assert r183[0].header("rseq") is None, r183[0].raw
    else:
        assert r183[0].has_option_tag("require", "100rel"), r183[0].raw
        assert r183[0].header("rseq") is not None, r183[0].raw
        deadline = time.monotonic() + 2
        while not caller.prack_replies and time.monotonic() < deadline:
            time.sleep(0.05)
        assert [r.code for r in caller.prack_replies] == [200], "PRACK from caller is not answered"

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
