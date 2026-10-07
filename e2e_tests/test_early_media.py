"""
early media suppression (SBCCallLeg::process_suppress_early_media)

18x replies (180..189) from the termination side are relayed to the caller either as is
or converted to '180 Ringing' without body (suppressed). decision:
  * routing profile 'suppress_early_media' (legacy) if present:
    true - suppress, false - never suppress
  * otherwise max of suppress_early_media_mode_id of A-leg and B-leg gateways
    from the gateways caches (profile lega_gw_cache_id/legb_gw_cache_id):
       0 disabled
      10 not_authorized_only: suppress if reply has no P-Early-Media header
      20 always

gateways (etc/db_map/load_gateway_attributes_cache.json):
  1 - mode not set (disabled), 2 - not_authorized_only, 3 - always

P-Early-Media must be checked in the reply as it was received from the termination gateway,
regardless of B->A headers filter (transit_headers_b2a). currently the filter is applied
before the check (SBCCallLeg::relayEvent), so test_not_authorized_only_with_filtered_header fails
"""

import pytest

from checks import assert_call_cleaned_up
from profiles import (
    GW_EARLY_MEDIA_ALWAYS,
    GW_EARLY_MEDIA_DISABLED,
    GW_EARLY_MEDIA_NOT_AUTHORIZED_ONLY,
    NO_ROUTES,
    YETI,
    route_to,
)
from sip_ua import EarlyReply, sdp_audio

P_EARLY_MEDIA = "P-Early-Media: sendrecv"


@pytest.fixture
def make_call(rpc, routing, cdrs, caller, term_gw):
    def make(early_replies, **profile_fields):
        """routes call to term_gw which sends early_replies before 200 OK.
        returns 18x replies received by the caller"""
        routing.set_profiles([route_to(term_gw, **profile_fields), NO_ROUTES])
        term_gw.early_replies = early_replies

        reply = caller.invite(YETI)
        assert reply is not None, "no final reply for INVITE"
        assert reply.code == 200, reply.raw

        # final answer SDP must be relayed regardless of 18x processing
        _, port = sdp_audio(reply.body)
        assert port and port != term_gw.rtp_port, f"bad SDP in 200 OK:\n{reply.raw}"

        assert caller.bye().code == 200
        assert_call_cleaned_up(rpc, cdrs, caller, term_gw)
        return [r for r in caller.provisional if 180 <= r.code < 190]
    return make


def assert_suppressed(replies):
    assert replies, "no 18x replies received by caller"
    for r in replies:
        assert (r.code, r.reason) == (180, "Ringing"), f"18x is not converted to 180 Ringing:\n{r.raw}"
        assert not r.body, f"18x body is not cleared:\n{r.raw}"


def assert_relayed_183_with_sdp(replies, term_gw):
    r183 = [r for r in replies if r.code == 183]
    assert r183, f"183 is not relayed to caller. got: {replies}"
    _, port = sdp_audio(r183[0].body)
    assert port and port != term_gw.rtp_port, f"bad SDP in relayed 183:\n{r183[0].raw}"


def gws(aleg, bleg):
    return {"lega_gw_cache_id": aleg, "legb_gw_cache_id": bleg}


def test_disabled(make_call, term_gw):
    replies = make_call([EarlyReply()],
                        **gws(GW_EARLY_MEDIA_DISABLED, GW_EARLY_MEDIA_DISABLED))
    assert_relayed_183_with_sdp(replies, term_gw)


def test_always_by_termination_gw(make_call, term_gw):
    replies = make_call([EarlyReply()],
                        **gws(GW_EARLY_MEDIA_DISABLED, GW_EARLY_MEDIA_ALWAYS))
    assert_suppressed(replies)


def test_always_by_origination_gw(make_call, term_gw):
    """mode is max of A-leg and B-leg gateways modes"""
    replies = make_call([EarlyReply()],
                        **gws(GW_EARLY_MEDIA_ALWAYS, GW_EARLY_MEDIA_DISABLED))
    assert_suppressed(replies)


def test_always_overrides_not_authorized_only(make_call, term_gw):
    replies = make_call([EarlyReply(headers=[P_EARLY_MEDIA])],
                        transit_headers_b2a="p-early-media",
                        **gws(GW_EARLY_MEDIA_NOT_AUTHORIZED_ONLY, GW_EARLY_MEDIA_ALWAYS))
    assert_suppressed(replies)


@pytest.mark.parametrize("code, reason", [(180, "Ringing"), (181, "Call Is Being Forwarded"),
                                          (182, "Queued"), (183, "Session Progress")])
def test_always_all_18x_with_sdp(make_call, term_gw, code, reason):
    replies = make_call([EarlyReply(code, reason)],
                        **gws(GW_EARLY_MEDIA_DISABLED, GW_EARLY_MEDIA_ALWAYS))
    assert_suppressed(replies)


def test_not_authorized_only_without_header(make_call, term_gw):
    replies = make_call([EarlyReply()],
                        transit_headers_b2a="p-early-media",
                        **gws(GW_EARLY_MEDIA_DISABLED, GW_EARLY_MEDIA_NOT_AUTHORIZED_ONLY))
    assert_suppressed(replies)


def test_not_authorized_only_with_header(make_call, term_gw):
    replies = make_call([EarlyReply(headers=[P_EARLY_MEDIA])],
                        transit_headers_b2a="p-early-media",
                        **gws(GW_EARLY_MEDIA_DISABLED, GW_EARLY_MEDIA_NOT_AUTHORIZED_ONLY))
    assert_relayed_183_with_sdp(replies, term_gw)


def test_not_authorized_only_with_filtered_header(make_call, term_gw):
    """P-Early-Media from the gateway authorizes early media even if the header itself
    is not relayed to the caller by B->A headers filter"""
    replies = make_call([EarlyReply(headers=[P_EARLY_MEDIA])],
                        **gws(GW_EARLY_MEDIA_DISABLED, GW_EARLY_MEDIA_NOT_AUTHORIZED_ONLY))
    assert_relayed_183_with_sdp(replies, term_gw)


def test_profile_flag_enables(make_call, term_gw):
    """legacy profile flag takes precedence over gateways modes"""
    replies = make_call([EarlyReply()], suppress_early_media=True,
                        **gws(GW_EARLY_MEDIA_DISABLED, GW_EARLY_MEDIA_DISABLED))
    assert_suppressed(replies)


def test_profile_flag_disables(make_call, term_gw):
    """legacy profile flag takes precedence over gateways modes"""
    replies = make_call([EarlyReply()], suppress_early_media=False,
                        **gws(GW_EARLY_MEDIA_ALWAYS, GW_EARLY_MEDIA_ALWAYS))
    assert_relayed_183_with_sdp(replies, term_gw)


def test_ringing_without_sdp_disabled(make_call, term_gw):
    """180 without SDP is relayed as is when suppression is disabled"""
    replies = make_call([EarlyReply(180, "Ringing", with_sdp=False)],
                        **gws(GW_EARLY_MEDIA_DISABLED, GW_EARLY_MEDIA_DISABLED))
    assert [r.code for r in replies] == [180]
    assert not replies[0].body
