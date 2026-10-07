"""
undecodable audio packet on a transcoded call: the caller codec is decoded by SEMS and encoded to PCMA
for the gateway. runs on the SEMS variant "codecs" (opus, speex, gsm plugins loaded, codecs group 7).

production case: the caller (opus) sent every ~32.8s a duplicate of an already sent packet (the same
RTP header, other payload 10 bytes longer: not an opus packet, looks like SRTP-encrypted copy).
duplicates received right after the original were dropped, the one received 20ms late (after the
original was played) was decoded: 'codec 60 decode failed', AmAudio::get() < 0, the media processor
cleared the B2B media session and both legs were stopped by SEMS core (BYE to both legs) without yeti
processing: CDR with 'Unhandled sequence' internal disconnect reason, time_end = time_start,
negative duration.

the same happens for every codec plugin which reports decode errors (AmAudio::decode):
  * opus: invalid packet (opus_decode < 0)
  * speex (8000, 16000, 32000): corrupted stream (speex_decode -2, e.g. invalid mode)
  * GSM: payload size is not a multiple of 33 (gsm_2_pcm16)
and for any codec when the decoded packet does not fit AUDIO_BUFFER_SIZE (8192 bytes, 4096 samples),
even if the packet is valid: opus 120ms packet, GSM packet with 26 frames.
not affected: G.711, L16, G.722, G.726, AMR, codec2, iLBC (decode errors only for not initialized codec).
not built in the SEMS package: iSAC, SILK (would be affected), G.729.

expected: the undecodable packet is a lost frame, the call goes on.

frames (checked with libopus/libspeex):
  * opus (RFC 6716 3.1/3.2): TOC byte only is a valid packet with empty frame (packet loss concealment),
    code 1 packet (two equal frames) with odd frames length is invalid, code 3 packet with 6 empty
    20ms frames is valid 120ms packet
  * speex: encoded 20ms of silence, invalid mode 9 in the first frame header
  * GSM: 33 bytes frames with 0xD signature
"""

from collections import namedtuple
import time

import pytest

from checks import assert_call_cleaned_up
from profiles import NO_ROUTES, Routing, route_to
import sdp as sdplib

Codec = namedtuple("Codec", "pt rtpmap fmtp ts_step valid invalid")

SPEEX_INVALID = bytes([0x48]) + bytes(7)  # mode 9 ('Invalid mode encountered. The stream is corrupted')

CODECS = {
    "opus": Codec(107, "opus/48000/2", "useinbandfec=1", 960,
                  bytes([0x78]),  # config 15 (hybrid FB 20ms), mono, code 0, empty frame
                  bytes([0x31]) + bytes(63)),  # code 1 with odd frames length: OPUS_INVALID_PACKET
    "speex-nb": Codec(110, "speex/8000", None, 160, bytes.fromhex(
        "2e9d1b9a2000017fffffffffff8100bfffffffffffc0805fffffffffffe0402ffffffffffff7"), SPEEX_INVALID),
    "speex-wb": Codec(111, "speex/16000", None, 320, bytes.fromhex(
        "369d1b9a20000168e8e8e8e8e8e8e88400b47474747474747442005a3a3a3a3a3a3a3a21002d1d1d1d1d1d1d1d1b3b60"
        "ababababab0ababababab0ababababab0ababababab7"), SPEEX_INVALID),
    "speex-uwb": Codec(112, "speex/32000", None, 640, bytes.fromhex(
        "3e9d1b9a2000017fffffffffffdb6db6db6db68900bfffffffffffedb6db6db6db42005ffffffffffff6db6db6db6da1002"
        "ffffffffffffb6db6db6db6db3b60ababababab0ababababab0ababababab0ababababab93b600000"), SPEEX_INVALID),
    "gsm": Codec(3, "GSM/8000", None, 160,
                 bytes([0xd0]) + bytes(32),
                 bytes([0xd0]) + bytes(33)),  # 34 bytes: not a multiple of the 33 bytes frame
}

# valid packets decoded to more than AUDIO_BUFFER_SIZE
OVERSIZED = {
    "opus-120ms": ("opus", bytes([0x7b, 0x06])),  # code 3, CBR, 6 empty 20ms frames: 5760 samples
    "gsm-26-frames": ("gsm", (bytes([0xd0]) + bytes(32)) * 26),  # 4160 samples
}

FRAME_INTERVAL = 0.02
FRAMES = 50

# codecs groups (etc/db_map/load_codec_groups.json): 7 - transcoding codecs, PCMA; 3 - PCMA, PCMU
GROUP_TRANSCODING = 7
GROUP_PCMA_PCMU = 3
PT_PCMA = 8


@pytest.fixture
def variant(sems_variant):
    return sems_variant("codecs")


@pytest.fixture
def routing(variant):
    r = Routing(variant.rpc)
    yield r
    r.reset()


def transcoded_call(variant, routing, caller, term_gw, codec):
    """the caller offers the codec only, the gateway answers PCMA"""
    caller.codecs = [(codec.pt, codec.rtpmap, codec.fmtp), "telephone-event"]
    term_gw.codecs = ["pcma", "telephone-event"]
    routing.set_profiles([route_to(term_gw, aleg_codecs_group_id=GROUP_TRANSCODING,
                                   bleg_codecs_group_id=GROUP_PCMA_PCMU), NO_ROUTES])
    reply = caller.invite(variant.addr)
    assert reply is not None and reply.code == 200, reply and reply.raw
    assert term_gw.wait_request("ACK", call_id=term_gw.call_id) is not None, "no ACK on termination side"

    rtpmap = "/".join(codec.rtpmap.lower().split("/")[:2])
    answer = sdplib.audio(reply.sdp)
    assert answer["rtpmap"].get(str(codec.pt)) == rtpmap, f"{rtpmap} is not accepted:\n{reply.raw}"
    offer = sdplib.audio(term_gw.invite_req.sdp)
    assert rtpmap not in offer["rtpmap"].values(), f"no transcoding:\n{term_gw.invite_req.raw}"


def send_frames(caller, codec, count=FRAMES):
    """valid stream from the caller. returns (seq, ts) of the sent packets"""
    sent = []
    for _ in range(count):
        sent.append(caller.rtp.send_packet(codec.pt, codec.valid, ts_step=codec.ts_step))
        time.sleep(FRAME_INTERVAL)
    return sent


def check_call_goes_on(variant, cdrs, caller, term_gw, codec):
    """the call is not terminated and the gateway gets transcoded audio after the packet"""
    term_gw.rtp.received.clear()
    send_frames(caller, codec)

    assert caller.wait_request("BYE", call_id=caller.call_id, timeout=0.5) is None, \
        "call is terminated by yeti after the packet"
    assert term_gw.wait_request("BYE", call_id=term_gw.call_id, timeout=0.1) is None, \
        "call is terminated by yeti after the packet"
    assert term_gw.rtp.wait(PT_PCMA, packets=20), f"gateway got RTP: {dict(term_gw.rtp.received)}"

    assert caller.bye().code == 200
    assert_call_cleaned_up(variant.rpc, cdrs, caller, term_gw)


@pytest.mark.parametrize("codec_name", CODECS)
def test_invalid_packet(variant, routing, cdrs, caller, term_gw, codec_name):
    """undecodable packet in sequence"""
    codec = CODECS[codec_name]
    transcoded_call(variant, routing, caller, term_gw, codec)

    send_frames(caller, codec)
    caller.rtp.send_packet(codec.pt, codec.invalid, ts_step=codec.ts_step)

    check_call_goes_on(variant, cdrs, caller, term_gw, codec)


@pytest.mark.parametrize("late_frames", [1, 5], ids=["late-20ms", "late-100ms"])
@pytest.mark.parametrize("codec_name", CODECS)
def test_late_invalid_duplicate(variant, routing, cdrs, caller, term_gw, codec_name, late_frames):
    """undecodable copy of an already played packet (the same seq/ts) received late_frames frames after it
    (production case: 20ms)"""
    codec = CODECS[codec_name]
    transcoded_call(variant, routing, caller, term_gw, codec)

    sent = send_frames(caller, codec)
    seq, ts = sent[-late_frames]
    caller.rtp.send_packet(codec.pt, codec.invalid, seq=seq, ts=ts)

    check_call_goes_on(variant, cdrs, caller, term_gw, codec)


@pytest.mark.parametrize("case", OVERSIZED)
def test_oversized_valid_packet(variant, routing, cdrs, caller, term_gw, case):
    """valid packet decoded to more than AUDIO_BUFFER_SIZE"""
    codec_name, payload = OVERSIZED[case]
    codec = CODECS[codec_name]
    transcoded_call(variant, routing, caller, term_gw, codec)

    send_frames(caller, codec)
    caller.rtp.send_packet(codec.pt, payload, ts_step=codec.ts_step)

    check_call_goes_on(variant, cdrs, caller, term_gw, codec)
