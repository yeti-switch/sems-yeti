"""
SIP session timers (RFC 4028) on yeti legs. port of yeti-test test_sst.py

test agents do not support timers, so yeti is the refresher on the legs where
session timer is enabled by the routing profile:
  A-leg: enable_aleg_session_timer, aleg_session_expires, aleg_minimum_timer, ...
  B-leg: enable_session_timer, session_expires, minimum_timer, ...
refresh UPDATE is sent at session_expires/2
"""

import re

import pytest

from checks import assert_call_cleaned_up
from profiles import connect_call

SESSION_EXPIRES = 9
MIN_SE = 7
MAX_TIMER = 14
REFRESH_METHOD_UPDATE = 2
REFRESH_WAIT = SESSION_EXPIRES // 2 + 3

ALEG_SST = {
    "enable_aleg_session_timer": "yes",
    "aleg_session_expires": SESSION_EXPIRES,
    "aleg_minimum_timer": MIN_SE,
    "aleg_maximum_timer": MAX_TIMER,
    "aleg_session_refresh_method_id": REFRESH_METHOD_UPDATE,
}

BLEG_SST = {
    "enable_session_timer": "yes",
    "session_expires": SESSION_EXPIRES,
    "minimum_timer": MIN_SE,
    "maximum_timer": MAX_TIMER,
    "session_refresh_method_id": REFRESH_METHOD_UPDATE,
}

NO_RELAY = {
    "aleg_relay_update": False,
    "bleg_relay_update": False,
    "aleg_relay_reinvite": False,
    "bleg_relay_reinvite": False,
}


def session_expires(msg):
    """(delta seconds, refresher) from Session-Expires header"""
    value = msg.header("session-expires") or msg.header("x")
    assert value, f"no Session-Expires:\n{msg.raw}"
    m = re.match(r"\s*(\d+)\s*(?:;\s*refresher\s*=\s*(\w+))?", value)
    return int(m.group(1)), m.group(2)


def assert_refresh(update):
    assert update is not None, "no session refresh UPDATE"
    assert session_expires(update) == (SESSION_EXPIRES, "uac"), update.raw
    assert int(update.header("min-se")) == MIN_SE, update.raw


@pytest.mark.parametrize("aleg_sst, bleg_sst", [
    (True, False),
    (True, True),
    (False, False),
], ids=["yeti_aleg_only", "yeti_aleg_and_bleg", "yeti_no_sst"])
def test_sst(rpc, routing, cdrs, caller, term_gw, aleg_sst, bleg_sst):
    fields = dict(NO_RELAY)
    if aleg_sst:
        fields.update(ALEG_SST)
    if bleg_sst:
        fields.update(BLEG_SST)
    connect_call(routing, caller, term_gw, **fields)

    inv = term_gw.invite_req
    if bleg_sst:
        assert session_expires(inv)[0] == SESSION_EXPIRES, inv.raw
        assert int(inv.header("min-se")) == MIN_SE, inv.raw
    else:
        assert inv.header("session-expires") is None, inv.raw

    in_dialog = lambda r: r.tag("to") is not None  # noqa: E731
    caller_update = caller.wait_request("UPDATE", pred=in_dialog, timeout=REFRESH_WAIT)
    if aleg_sst:
        assert_refresh(caller_update)
    else:
        assert caller_update is None, f"unexpected UPDATE to caller:\n{caller_update.raw}"

    gw_update = term_gw.wait_request("UPDATE", pred=in_dialog, timeout=REFRESH_WAIT if bleg_sst else 1)
    if bleg_sst:
        assert_refresh(gw_update)
    else:
        assert gw_update is None, f"unexpected UPDATE to gateway:\n{gw_update.raw}"

    # call is still alive after refreshes
    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
