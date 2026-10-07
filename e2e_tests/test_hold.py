"""
hold/unhold re-INVITEs. port of yeti-test test_hold_unhold.py

with aleg_relay_reinvite/bleg_relay_reinvite disabled, re-INVITEs are processed locally by yeti
except hold state changes: they are relayed to the other leg if aleg_relay_hold/bleg_relay_hold
of the leg the request came from is enabled. in both cases the sender gets SDP answer
with mirrored direction (sendonly -> recvonly)
"""

import time

import pytest

from checks import assert_call_cleaned_up
from profiles import connect_call
import sdp as sdplib

NOT_RELAYED_WAIT = 0.5


def reinvite_with_sdp_after(t):
    return lambda r: r.time >= t and r.tag("to") is not None and r.sdp is not None


def check_hold_cycle(sender, receiver, relay):
    for action, sent_direction, answer_direction in (("hold", "sendonly", "recvonly"),
                                                     ("unhold", "sendrecv", "sendrecv")):
        t = time.monotonic()
        reply = getattr(sender, action)()
        assert reply is not None and reply.code == 200, f"{action}: {reply and reply.raw}"
        assert sdplib.audio(reply.sdp)["direction"] == answer_direction, f"{action}: {reply.raw}"

        req = receiver.wait_request("INVITE", pred=reinvite_with_sdp_after(t),
                                    timeout=2 if relay else NOT_RELAYED_WAIT)
        if relay:
            assert req is not None, f"{action} is not relayed"
            assert sdplib.audio(req.sdp)["direction"] == sent_direction, f"{action}: {req.raw}"
            # next offer from the receiver is allowed only after ACK (yeti replies 491 otherwise)
            ack = receiver.wait_request("ACK", pred=lambda r: r.call_id == req.call_id and r.cseq[0] == req.cseq[0])
            assert ack is not None, f"ACK for relayed {action} is not relayed"
        else:
            assert req is None, f"{action} is relayed while relay_hold is disabled:\n{req.raw}"


@pytest.mark.parametrize("aleg_relay_hold", [True, False], ids=["aleg_relay", "aleg_local"])
@pytest.mark.parametrize("bleg_relay_hold", [True, False], ids=["bleg_relay", "bleg_local"])
def test_hold_unhold(rpc, routing, cdrs, caller, term_gw, aleg_relay_hold, bleg_relay_hold):
    connect_call(routing, caller, term_gw,
                 aleg_relay_hold=aleg_relay_hold, bleg_relay_hold=bleg_relay_hold,
                 aleg_relay_reinvite=False, bleg_relay_reinvite=False)

    check_hold_cycle(caller, term_gw, aleg_relay_hold)
    check_hold_cycle(term_gw, caller, bleg_relay_hold)

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
