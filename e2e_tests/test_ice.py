"""
ICE connectivity failure on the A-leg (SBCCallLeg::onIceConnectivityFailed)

the caller offers ICE (ice-ufrag/ice-pwd) without usable candidates, as WebRTC clients do with mDNS
'.local' host candidates only. ICE is enabled for the A-leg (gateway ice_mode_id 'enable when offered'
by default), there are no candidate pairs and SEMS fails the connectivity check after
ice_connectivity_check_timeout (default 5s) from the A-leg stream start (183 with SDP relayed to the caller).

the A-leg is terminated with 487 then. the B-leg must be cancelled immediately and the call must not be
rerouted: originally only the A-leg was stopped, the B-leg stayed in the early state and was cancelled
only by the next provisional reply (failed relay to the stopped A-leg) or by SIP timer C (3 min).
A local 408 on timer C was handled by the A-leg as the B-leg failure in Ringing state: the call was
rerouted to the next gateway, both CDRs had 'Unhandled sequence' internal disconnect reason.

B-leg SIP disconnect code/reason is not written to the CDR (the cancelled B-leg reply comes
after the A-leg is disconnected)
"""

from checks import assert_call_cleaned_up
from profiles import NO_ROUTES, YETI, route_to
from sip_ua import EarlyReply

ICE_FAILURE_WAIT = 10  # ice_connectivity_check_timeout with margin
CANCEL_WAIT = 2
# internal disconnect code 135 (etc/db_map/load_disconnect_code_refuse.json)
ICE_FAILED = (200, "ICE connectivity failed")


def ice_offer(caller):
    """SDP offer with ICE credentials and without candidates"""
    return caller.offer() + "a=ice-ufrag:e2eUfrag\r\na=ice-pwd:e2eIcePasswordWithoutCandidates\r\n"


def ringing_gw(gw):
    gw.early_replies = [EarlyReply()]
    gw.no_answer = True
    return gw


def test_early_ice_failure_cancels_bleg(rpc, routing, cdrs, caller, term_gw):
    routing.set_profiles([route_to(ringing_gw(term_gw)), NO_ROUTES])

    reply = caller.invite(YETI, body=ice_offer(caller), timeout=ICE_FAILURE_WAIT)
    assert reply is not None, "no final reply for INVITE"
    assert reply.code == 487, reply.raw
    assert [r.code for r in caller.provisional if r.code > 100] == [183]

    assert term_gw.wait_request("CANCEL", timeout=CANCEL_WAIT) is not None, "B-leg is not cancelled"

    cdr = assert_call_cleaned_up(rpc, cdrs, caller, term_gw, code=0, reason="", internal=ICE_FAILED)
    assert cdr["attempt_num"] == 1, cdr


def test_early_ice_failure_no_rerouting(rpc, routing, cdrs, caller, make_agent):
    """B-leg failure after the A-leg ICE failure must not start the next routing attempt"""
    gw1 = ringing_gw(make_agent())
    gw2 = make_agent()
    routing.set_profiles([route_to(gw1), route_to(gw2), NO_ROUTES])

    reply = caller.invite(YETI, body=ice_offer(caller), timeout=ICE_FAILURE_WAIT)
    assert reply is not None, "no final reply for INVITE"
    assert reply.code == 487, reply.raw

    # fails the B-leg like timer C does if it was not cancelled (no-op for already cancelled INVITE)
    gw1.reject(503, "Service Unavailable")

    assert gw2.wait_request("INVITE", timeout=CANCEL_WAIT) is None, "call is rerouted after the A-leg termination"

    assert_call_cleaned_up(rpc, cdrs, caller, gw1, code=0, reason="", internal=ICE_FAILED)
    attempts = cdrs.wait(caller.call_id)
    assert len(attempts) == 1, attempts
