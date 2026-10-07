"""common checks for call tests: CDRs and yeti active sessions"""

import json
import time


# writecdr arguments order (src/cdr/CdrWriter.cpp cdr_static_fields)
CDR_FIELDS = [
    "is_master", "node_id", "pop_id", "attempt_num", "is_last",
    "legA_transport_protocol_id", "legA_local_ip", "legA_local_port", "legA_remote_ip", "legA_remote_port",
    "legB_transport_protocol_id", "legB_local_ip", "legB_local_port", "legB_remote_ip", "legB_remote_port",
    "legb_ruri", "legb_outbound_proxy", "time_data", "early_media_present",
    "disconnect_code", "disconnect_reason", "disconnect_initiator",
    "disconnect_intermediate_code", "disconnect_intermediate_reason",
    "disconnect_rewrited_code", "disconnect_rewrited_reason",
    "orig_call_id", "term_call_id", "local_tag", "bleg_local_tag",
]


# initial value of the CDR internal disconnect reason (src/cdr/Cdr.cpp).
# remains in the CDR when the call was finished by a sequence yeti does not handle
UNHANDLED_SEQUENCE = "Unhandled sequence"


def is_unhandled(cdr):
    return cdr["disconnect_intermediate_reason"] == UNHANDLED_SEQUENCE


class Cdrs:
    """CDRs written by yeti through postgresql_proxy (etc/db_map/writecdr.lua)"""

    def __init__(self, path):
        self.path = path

    def all(self):
        cdrs = []
        with open(self.path) as f:
            for line in f:
                if line.strip():
                    args = json.loads(line)
                    cdrs.append(dict(zip(CDR_FIELDS, args)))
        return cdrs

    def unhandled(self):
        """CDRs with 'Unhandled sequence' internal disconnect reason"""
        return [c for c in self.all() if is_unhandled(c)]

    def wait(self, orig_call_id, timeout=5):
        """wait for CDRs of the call (one per routing attempt)"""
        deadline = time.monotonic() + timeout
        while True:
            found = [c for c in self.all() if c["orig_call_id"] == orig_call_id]
            if found or time.monotonic() > deadline:
                return found
            time.sleep(0.1)


def no_active_calls(rpc, *tags, timeout=3):
    """True if none of the tags is in yeti active sessions"""
    deadline = time.monotonic() + timeout
    while True:
        sessions = json.dumps(rpc.call("yeti.show.sessions"))
        if not any(t and t in sessions for t in tags):
            return True
        if time.monotonic() > deadline:
            return False
        time.sleep(0.1)


def assert_call_cleaned_up(rpc, cdrs, caller, term_gw=None, code=200, reason="Bye", internal=None):
    """yeti has no sessions for the call and wrote the CDR with expected disconnect code/reason
    (SIP disconnect of the B-leg; empty for calls rejected before B-leg creation)
    and internal (intermediate) disconnect code/reason if given"""
    tags = [caller.remote_tag]
    if term_gw is not None and term_gw.invite_req is not None:
        tags.append(term_gw.invite_req.tag("from"))
    assert no_active_calls(rpc, *tags), f"yeti still has sessions for tags {tags}"

    found = cdrs.wait(caller.call_id)
    assert found, f"no CDR for call {caller.call_id}"
    for c in found:
        assert not is_unhandled(c), f"'{UNHANDLED_SEQUENCE}' in CDR: {c}"
    cdr = found[-1]
    assert (cdr["disconnect_code"], cdr["disconnect_reason"]) == (code, reason), cdr
    if internal is not None:
        assert (cdr["disconnect_intermediate_code"], cdr["disconnect_intermediate_reason"]) == internal, cdr
    assert cdr["local_tag"] == caller.remote_tag, cdr
    if term_gw is not None and term_gw.invite_req is not None:
        assert cdr["term_call_id"] == term_gw.call_id, cdr
    return cdr
