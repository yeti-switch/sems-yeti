"""
SDES SRTP gateway restarts RTP sequence numbers after re-INVITE with the same SSRC and the same key
(production case, see README.md and the pcaps in this directory).

the caller (plain RTP) sends re-INVITE right after the answer, yeti relays it to the gateway
(RTP/SAVP, bleg_media_encryption_mode_id 1) and the gateway answers with the same a=crypto key.
then the gateway continues the same SSRC from another sequence number. the jumps are taken from
the production calls:
  * back-29912: 32228 -> 2316, the failed call: all the following packets were rejected by
    the libsrtp replay check (replay_old: far behind the highest index), no audio to the caller
  * back-105:   32331 -> 32226, within the 128 packets replay window, the already used
    32322..32331 come again later
  * forward-3163: 29165 -> 32328

expected: the gateway audio reaches the caller after the restart and the only SRTP decrypt error
of the B-leg (CDR media_stats rx_srtp_decrypt_errors) is the latching packet. it fails for back-29912
until SEMS resets the SRTP receive context on the new SDP answer (AmSrtpConnection recreates it only
on SSRC change). the production issue is recognized by the lost packets counted as SRTP decrypt
errors, packets lost otherwise fail the test with another message.

the gateway also sends the plain RTP latching packet (SSRC 0xdeadbeef, seq 0, PCMU) before
the SRTP stream, as Mitel MBG does: it fails SRTP authentication (1 decrypt error in the
production calls too) and must not affect the call.

requires python3-cryptography (lib/srtp.py)
"""

import struct
import time

import pytest

pytest.importorskip("cryptography", reason="python3-cryptography is required for SRTP")

from checks import assert_call_cleaned_up, media_stats  # noqa: E402
from profiles import NO_ROUTES, Routing, route_to  # noqa: E402
import sdp as sdplib  # noqa: E402
from sip_ua import TerminationGateway  # noqa: E402
from srtp import SrtpContext, crypto_lines, new_inline  # noqa: E402

SRTP_SDES = 1  # bleg_media_encryption_mode_id: RTP/SAVP
SUPPORTED_SUITES = ("AES_256_CM_HMAC_SHA1_80", "AES_CM_128_HMAC_SHA1_80")
PT_PCMA = 8
PCMA_FRAME = bytes([0xd5]) * 160
GW_SSRC = 0x001e1b00
FRAME_INTERVAL = 0.02
PACKETS_AFTER_RESTART = 120  # back-105 reaches the already used sequence numbers after 96 packets
LATCHING_ERRORS = 1  # the plain RTP latching packet fails SRTP authentication

# production calls: (first seq, packets before the re-INVITE, first seq after it)
JUMPS = {
    "back-29912": (32220, 9, 2316),  # 9-72434DFC-6AC8FE41000C5DDA-62EF26C0_9.pcap (no audio)
    "back-105": (32322, 10, 32226),  # 8-220816C5-6AC8FE34000B42B8-9DEF46C0_8.pcap
    "forward-3163": (29159, 7, 32328),  # 9-1FCC123C-6AC8FE2900090FE8-62EF26C0_9.pcap
}


class SdesGateway(TerminationGateway):
    """answers RTP/SAVP offers with its own SDES key, the same one in all the answers of the dialog"""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.crypto = None  # (tag, suite, own inline key) of the last answer
        self.answered_keys = []

    def answer(self, offer_body, rtp=None):
        body = super().answer(offer_body, rtp)
        offered = [c for c in crypto_lines(offer_body) if c[1] in SUPPORTED_SUITES]
        assert offered, f"no supported a=crypto in the offer:\n{offer_body}"
        tag, suite, peer_key = offered[0]
        key = self.crypto[2] if self.crypto and self.crypto[1] == suite else new_inline(suite)
        self.crypto = (tag, suite, key)
        self.answered_keys.append(key)
        self.rtp.srtp_tx = SrtpContext(suite, key)
        self.rtp.srtp_rx = SrtpContext(suite, peer_key)
        return body + f"a=crypto:{tag} {suite} inline:{key}\r\n"


@pytest.fixture
def variant(sems_variant):
    return sems_variant("srtp")


@pytest.fixture
def routing(variant):
    r = Routing(variant.rpc)
    yield r
    r.reset()


@pytest.fixture
def sdes_gw(spool):
    gw = SdesGateway()
    yield gw
    gw.stop()


def send_frames(rtp, count):
    for _ in range(count):
        rtp.send_packet(PT_PCMA, PCMA_FRAME)
        time.sleep(FRAME_INTERVAL)


def latching_packet():
    """plain RTP packet sent by Mitel MBG before the SRTP stream"""
    return struct.pack("!BBHII", 0x80, 0, 0, 0, 0xdeadbeef) + bytes([0xff]) * 160


@pytest.mark.parametrize("jump", JUMPS)
def test_seq_restart_after_reinvite(variant, routing, cdrs, caller, sdes_gw, jump):
    first_seq, packets_before, restart_seq = JUMPS[jump]
    caller.codecs = sdes_gw.codecs = ["pcma", "telephone-event"]
    routing.set_profiles([route_to(sdes_gw, bleg_media_encryption_mode_id=SRTP_SDES), NO_ROUTES])

    reply = caller.invite(variant.addr)
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert sdplib.audio(sdes_gw.invite_req.sdp)["proto"] == "RTP/SAVP", sdes_gw.invite_req.raw
    assert sdes_gw.wait_request("ACK", call_id=sdes_gw.call_id) is not None, "no ACK on termination side"

    rtp = sdes_gw.rtp
    rtp.send_raw(latching_packet())
    rtp.ssrc, rtp.seq, rtp.ts = GW_SSRC, first_seq - 1, 0
    send_frames(rtp, packets_before)
    assert caller.rtp.wait(PT_PCMA, packets=packets_before - 2), \
        f"SRTP from the gateway does not reach the caller: {dict(caller.rtp.received)}"

    # caller re-INVITE relayed to the gateway, answered with the same key
    t = time.monotonic()
    reply = caller.reinvite()
    assert reply is not None and reply.code == 200, reply and reply.raw
    reinvite = sdes_gw.wait_request("INVITE", pred=lambda r: r.time >= t and r.tag("to") is not None)
    assert reinvite is not None, "re-INVITE is not relayed to the gateway"
    assert len(set(sdes_gw.answered_keys)) == 1 and len(sdes_gw.answered_keys) == 2, sdes_gw.answered_keys

    # the gateway continues the same SSRC from another sequence number
    time.sleep(0.05)
    caller.rtp.received.clear()
    rtp.seq = restart_seq - 1
    send_frames(rtp, PACKETS_AFTER_RESTART)
    caller.rtp.wait(PT_PCMA, packets=PACKETS_AFTER_RESTART, timeout=1)
    got = caller.rtp.count(PT_PCMA)

    assert caller.bye().code == 200
    cdr = assert_call_cleaned_up(variant.rpc, cdrs, caller, sdes_gw)
    bleg = media_stats(cdr, cdr["bleg_local_tag"])
    assert bleg is not None, f"no B-leg media stats in CDR: {cdr['media_stats']}"
    errors = bleg["rx_srtp_decrypt_errors"]
    lost = PACKETS_AFTER_RESTART - got
    stats = (f"caller got {got} of {PACKETS_AFTER_RESTART} gateway packets after the sequence restart, "
             f"B-leg rx_srtp_decrypt_errors={errors} ({LATCHING_ERRORS} expected for the latching packet), "
             f"B-leg rx: {[(hex(r['rx_ssrc']), r['rx_packets']) for r in bleg['rx']]}")

    # packets lost not by the SRTP rejection are another issue
    assert lost <= 2 or errors - LATCHING_ERRORS >= lost - 2, f"packets lost without SRTP decrypt errors: {stats}"
    # the production issue: gateway packets after the restart rejected by SRTP (replay check)
    assert lost <= 2 and errors == LATCHING_ERRORS, f"gateway SRTP packets rejected after the restart: {stats}"
