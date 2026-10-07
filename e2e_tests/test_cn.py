"""
comfort noise relay with rtp_force_relay_cn. port of yeti-test test_cn.py

CN (payload type 13) packets sent by one side must reach the other side through yeti RTP relay.

CN is relayed only when RTP relay is possible for the call:
  * no inband DTMF detection on both legs: aleg_dtmf_recv_modes/bleg_dtmf_recv_modes
    default DTMF_RX_MODE_ALL includes inband (0x4) which forces transcoding (SBCCallProfile.cpp),
    so both are set to RFC2833 only (0x1)
  * AmRtpStream relays packets when the payload matches the last payload received from
    the opposite side, so both sides send PCMU first (like real endpoints and sems-tester in yeti-test)
otherwise yeti processes the media itself and CN is decoded and replaced with generated PCMU
"""

from checks import assert_call_cleaned_up
from profiles import connect_call

DTMF_RX_MODE_RFC2833 = 1

PT_PCMU = 0
PT_CN = 13


def test_cn_relay(rpc, routing, cdrs, caller, term_gw):
    caller.codecs = ["pcmu", "cn", "telephone-event"]
    term_gw.codecs = ["pcmu", "cn", "telephone-event"]
    reply = connect_call(routing, caller, term_gw, rtp_force_relay_cn=True,
                         aleg_dtmf_recv_modes=DTMF_RX_MODE_RFC2833, bleg_dtmf_recv_modes=DTMF_RX_MODE_RFC2833)
    assert "cn" in reply.sdp["media"][0]["codecs"], f"CN is not negotiated for caller:\n{reply.raw}"

    term_gw.rtp.send(PT_PCMU, count=10)
    caller.rtp.send(PT_PCMU, count=10)
    assert term_gw.rtp.wait(PT_PCMU, packets=5), f"gateway got RTP: {dict(term_gw.rtp.received)}"
    assert caller.rtp.wait(PT_PCMU, packets=5), f"caller got RTP: {dict(caller.rtp.received)}"

    caller.rtp.send(PT_CN, count=10)
    assert term_gw.rtp.wait(PT_CN, packets=5), f"gateway got RTP: {dict(term_gw.rtp.received)}"

    term_gw.rtp.send(PT_CN, count=10)
    assert caller.rtp.wait(PT_CN, packets=5), f"caller got RTP: {dict(caller.rtp.received)}"

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
