from sip import SipClient


def test_options(sems):
    reply = SipClient().request("OPTIONS", 5060)
    assert reply is not None and reply.code == 200
