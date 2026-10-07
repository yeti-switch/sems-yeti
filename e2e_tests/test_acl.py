"""
SEMS signaling interfaces ACLs (origination-acl, options-acl, register-acl, message-acl).

ACLs are configured per transport section of a signaling interface and are checked
in the transaction layer for out-of-dialog INVITE/OPTIONS/REGISTER/MESSAGE only:
  * source address matches any whitelist network -> request is passed to the application
  * otherwise 'reject' method replies 403 statelessly, 'drop' method silently drops it
  * empty or absent ACL allows everything

interfaces used (see etc/sems.conf):
  5060 udp/tcp  no ACLs
  5070 udp      all ACLs, whitelist 127.0.0.2/32, method reject
  5070 tcp      no ACLs
  5071 udp      all ACLs, whitelist 127.0.0.2/32, method drop
  5071 tcp      origination-acl and options-acl, whitelist 127.0.0.2/32, method drop
  5072 udp      options-acl only, whitelist { 127.0.0.2/32, 127.0.1.0/24 }, method reject

"allowed" replies come from SEMS core/yeti (OPTIONS 200, REGISTER 401, MESSAGE 405,
INVITE routing error since there is no routing mapping), none of them is 403
"""

import pytest

from sip import SipClient

ALLOWED_IP = "127.0.0.2"
DENIED_IP = "127.0.0.3"
SUBNET_IP = "127.0.1.5"

NO_ACL_PORT = 5060
REJECT_PORT = 5070
DROP_PORT = 5071
OPTIONS_ONLY_PORT = 5072

ACL_METHODS = ["INVITE", "OPTIONS", "REGISTER", "MESSAGE"]

# enough to get final reply for allowed request, used as silence window for dropped ones
TIMEOUT = 3

REJECTED = "sip_acl_rejected"
DROPPED = "sip_acl_dropped"


def udp(ip):
    return SipClient("udp", ip)


def tcp(ip):
    return SipClient("tcp", ip)


def assert_passed(reply):
    """request was passed through ACL to the application"""
    assert reply is not None, "no reply for request which must pass ACL"
    assert reply.code != 403, f"unexpected 403 for request which must pass ACL: {reply.raw}"


@pytest.mark.parametrize("method", ACL_METHODS)
def test_reject_not_whitelisted(sems, metrics, method):
    before = metrics.get(REJECTED)
    reply = udp(DENIED_IP).request(method, REJECT_PORT, timeout=TIMEOUT)
    assert reply is not None, "no reply from 'reject' ACL"
    assert reply.code == 403, reply.raw
    assert metrics.get(REJECTED) == before + 1


@pytest.mark.parametrize("method", ACL_METHODS)
def test_reject_whitelisted(sems, metrics, method):
    before = metrics.get(REJECTED)
    assert_passed(udp(ALLOWED_IP).request(method, REJECT_PORT, timeout=TIMEOUT))
    assert metrics.get(REJECTED) == before


@pytest.mark.parametrize("method", ACL_METHODS)
def test_drop_not_whitelisted(sems, metrics, method):
    before = metrics.get(DROPPED)
    reply = udp(DENIED_IP).request(method, DROP_PORT, timeout=TIMEOUT)
    assert reply is None, f"reply for request which must be dropped: {reply.raw}"
    assert metrics.get(DROPPED) == before + 1


@pytest.mark.parametrize("method", ACL_METHODS)
def test_drop_whitelisted(sems, metrics, method):
    before = metrics.get(DROPPED)
    assert_passed(udp(ALLOWED_IP).request(method, DROP_PORT, timeout=TIMEOUT))
    assert metrics.get(DROPPED) == before


@pytest.mark.parametrize("method", ["INVITE", "OPTIONS"])
def test_drop_tcp(sems, metrics, method):
    before = metrics.get(DROPPED)
    assert tcp(DENIED_IP).request(method, DROP_PORT, timeout=TIMEOUT) is None
    assert metrics.get(DROPPED) == before + 1

    assert_passed(tcp(ALLOWED_IP).request(method, DROP_PORT, timeout=TIMEOUT))
    assert metrics.get(DROPPED) == before + 1


@pytest.mark.parametrize("method", ["REGISTER", "MESSAGE"])
def test_drop_tcp_method_without_acl(sems, metrics, method):
    """5071 tcp has no register-acl and message-acl"""
    before = metrics.get(DROPPED)
    assert_passed(tcp(DENIED_IP).request(method, DROP_PORT, timeout=TIMEOUT))
    assert metrics.get(DROPPED) == before


@pytest.mark.parametrize("method", ACL_METHODS)
def test_acl_is_per_transport(sems, metrics, method):
    """5070 udp has ACLs, 5070 tcp on the same interface has not"""
    before = metrics.get(REJECTED)
    assert_passed(tcp(DENIED_IP).request(method, REJECT_PORT, timeout=TIMEOUT))
    assert metrics.get(REJECTED) == before


@pytest.mark.parametrize("method", ACL_METHODS)
def test_no_acl(sems, metrics, method):
    before_rejected, before_dropped = metrics.get(REJECTED), metrics.get(DROPPED)
    assert_passed(udp(DENIED_IP).request(method, NO_ACL_PORT, timeout=TIMEOUT))
    assert metrics.get(REJECTED) == before_rejected
    assert metrics.get(DROPPED) == before_dropped


def test_in_dialog_request_not_checked(sems, metrics):
    """requests with To-tag bypass ACLs (expected 481 for unknown dialog)"""
    before = metrics.get(REJECTED)
    assert_passed(udp(DENIED_IP).request("OPTIONS", REJECT_PORT, to_tag="e2etotag", timeout=TIMEOUT))
    assert metrics.get(REJECTED) == before


def test_method_without_acl_kind(sems, metrics):
    """only INVITE/OPTIONS/REGISTER/MESSAGE are checked. INFO passes (yeti replies 405)"""
    before = metrics.get(REJECTED)
    assert_passed(udp(DENIED_IP).request("INFO", REJECT_PORT, timeout=TIMEOUT))
    assert metrics.get(REJECTED) == before


@pytest.mark.parametrize("ip", [ALLOWED_IP, SUBNET_IP])
def test_whitelist_networks(sems, ip):
    """any of whitelist networks matches: /32 host and /24 subnet"""
    reply = udp(ip).request("OPTIONS", OPTIONS_ONLY_PORT, timeout=TIMEOUT)
    assert reply is not None and reply.code == 200


def test_whitelist_networks_not_matched(sems, metrics):
    before = metrics.get(REJECTED)
    reply = udp(DENIED_IP).request("OPTIONS", OPTIONS_ONLY_PORT, timeout=TIMEOUT)
    assert reply is not None and reply.code == 403
    assert metrics.get(REJECTED) == before + 1


@pytest.mark.parametrize("method", ["INVITE", "REGISTER", "MESSAGE"])
def test_acl_kinds_are_independent(sems, metrics, method):
    """5072 has options-acl only. other methods from not whitelisted address pass"""
    before = metrics.get(REJECTED)
    assert_passed(udp(DENIED_IP).request(method, OPTIONS_ONLY_PORT, timeout=TIMEOUT))
    assert metrics.get(REJECTED) == before
