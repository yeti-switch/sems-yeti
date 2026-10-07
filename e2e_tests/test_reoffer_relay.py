"""
relaying of in-dialog SDP offers (re-INVITE, UPDATE). port of yeti-test test_relay.py

profile flags of the leg the request came from:
  aleg_relay_reinvite/bleg_relay_reinvite - re-INVITE is relayed to the other leg,
                                            otherwise answered by yeti locally
  aleg_relay_update/bleg_relay_update     - the same for UPDATE (in confirmed dialog)
the flags of the other leg are set to the opposite values to check they do not matter
"""

import time

import pytest

from checks import assert_call_cleaned_up
from profiles import connect_call

NOT_RELAYED_WAIT = 0.5


@pytest.mark.parametrize("relay", [True, False], ids=["relay", "local"])
@pytest.mark.parametrize("method", ["INVITE", "UPDATE"])
@pytest.mark.parametrize("from_leg", ["aleg", "bleg"])
def test_reoffer_relay(rpc, routing, cdrs, caller, term_gw, from_leg, method, relay):
    other_leg = "bleg" if from_leg == "aleg" else "aleg"
    connect_call(routing, caller, term_gw, **{
        f"{from_leg}_relay_reinvite": relay,
        f"{from_leg}_relay_update": relay,
        f"{other_leg}_relay_reinvite": not relay,
        f"{other_leg}_relay_update": not relay,
    })
    sender, receiver = (caller, term_gw) if from_leg == "aleg" else (term_gw, caller)

    t = time.monotonic()
    reply = sender.reinvite() if method == "INVITE" else sender.update()
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert reply.sdp is not None, f"no SDP answer:\n{reply.raw}"

    req = receiver.wait_request(method, pred=lambda r: r.tag("to") is not None and r.time >= t,
                                timeout=2 if relay else NOT_RELAYED_WAIT)
    if relay:
        assert req is not None, f"{method} is not relayed"
        assert req.sdp is not None, req.raw
    else:
        assert req is None, f"{method} is relayed while relay is disabled:\n{req.raw}"

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
