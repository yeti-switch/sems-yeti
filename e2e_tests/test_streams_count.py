"""
T.38 fax re-INVITE from the termination gateway and media streams count.
port of yeti-test test_streams_count.py

  reuse_media_slot: image stream replaces audio in the same m= line (1 stream)
                    or is added as second one with rejected audio (2 streams)
  filter_noaudio_streams: yeti filters non-audio streams. with rtp relay enabled and
                    the image stream in the only slot the re-INVITE is rejected with 488 by yeti
  caller_rejects:   caller rejects relayed re-INVITE with 488
"""

import pytest

from checks import assert_call_cleaned_up
from profiles import connect_call
import sdp as sdplib

CASES = [
    # reuse_media_slot, count, filter_noaudio_streams, enable_rtprelay, caller_rejects, expect_rejected
    pytest.param(True, 1, True, True, False, True, id="reuse-filter-relay"),
    pytest.param(False, 2, True, False, False, False, id="add-filter-norelay"),
    pytest.param(True, 1, False, True, False, False, id="reuse-nofilter-relay"),
    pytest.param(False, 2, False, False, False, False, id="add-nofilter-norelay"),
    pytest.param(False, 2, False, True, False, False, id="add-nofilter-relay"),
    pytest.param(False, 2, False, True, True, True, id="add-nofilter-relay-caller-rejects"),
]


@pytest.mark.parametrize("reuse_media_slot, count, filter_noaudio_streams, enable_rtprelay, "
                         "caller_rejects, expect_rejected", CASES)
def test_streams_count(rpc, routing, cdrs, caller, term_gw, reuse_media_slot, count,
                       filter_noaudio_streams, enable_rtprelay, caller_rejects, expect_rejected):
    connect_call(routing, caller, term_gw,
                 enable_rtprelay=enable_rtprelay,
                 aleg_dtmf_recv_modes=1,
                 aleg_relay_reinvite=True,
                 bleg_relay_reinvite=True,
                 filter_noaudio_streams=filter_noaudio_streams)
    if caller_rejects:
        caller.reject_reoffer_code = 488

    if reuse_media_slot:
        media = [sdplib.Media("image", term_gw.rtp.port)]
    else:
        media = [sdplib.Media("audio", 0, codecs=term_gw.codecs), sdplib.Media("image", term_gw.rtp.port)]

    reply = term_gw.reinvite(body=term_gw.offer(media=media))
    assert reply is not None, "no final reply for fax re-INVITE"

    fax_invite = caller.wait_request("INVITE", pred=lambda r: r.tag("to") is not None, timeout=1)
    if not expect_rejected or caller_rejects:
        # relayed to the caller
        assert fax_invite is not None, "fax re-INVITE is not relayed to caller"
        assert len(fax_invite.sdp["media"]) == count, fax_invite.raw
    else:
        # rejected by yeti filters before reaching the caller
        assert fax_invite is None, f"fax re-INVITE is relayed to caller:\n{fax_invite.raw}"

    if expect_rejected:
        assert reply.code == 488, reply.raw
    else:
        assert reply.code == 200, reply.raw
        assert len(reply.sdp["media"]) == count, reply.raw

    assert caller.bye().code == 200
    assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
