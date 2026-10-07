# SRTP gateway restarts sequence numbers after re-INVITE

Production case: calls to the termination gateway **Mitel MBG 12.3** (MiVB 10.5,
`Mitel Border GW(MBG/12.3.0.166 TUG/4.26.0.109-01)`) over TLS with SDES SRTP
(`RTP/SAVP`, `AES_256_CM_HMAC_SHA1_80`). yeti `1.14.39core192`.
A-leg is plain RTP, B-leg is SRTP, PCMA relayed.

Call flow (all three calls): INVITE, 180, 200 OK, ACK, then the caller sends re-INVITE right after
the answer. yeti relays it to the gateway and the gateway answers with **the same `a=crypto` key**
(o= version +1). After that the gateway continues **the same SSRC** from **another sequence number**.

| pcap | gateway seq before -> after re-INVITE | SEMS rx SRTP | result |
|---|---|---|---|
| `9-72434DFC-6AC8FE41000C5DDA-62EF26C0_9.pcap` | 32228 -> 2316 (-29912) | 9 accepted, 410 rejected (`replay_old`) | **no audio from the gateway** (9 packets relayed to the caller) |
| `8-220816C5-6AC8FE34000B42B8-9DEF46C0_8.pcap` | 32331 -> 32226 (-105) | 222 of 223 accepted | ok |
| `9-1FCC123C-6AC8FE2900090FE8-62EF26C0_9.pcap` | 29165 -> 32328 (+3163) | 173 of 174 accepted | ok |

All the gateway SRTP packets authenticate and decrypt with the key from its `a=crypto` (checked with
`lib/srtp.py`): keys are fine. The rejection is the libsrtp replay protection (SEMS bundles
cisco/libsrtp, `AmSrtpConnection`: receive context per SSRC, `window_size = 128`, recreated only on
SSRC change): after the big backward jump every packet index is estimated far behind the highest
received one (32228) and dropped as `replay_old` until the sequence numbers pass it again (~10 min).
Whether a call is affected depends on where the new sequence number of the gateway lands.

The single `rx srtp decrypt error` in the successful calls is the plain RTP latching packet sent by
MBG before the SRTP stream (SSRC `0xdeadbeef`, seq 0, PCMU, no auth tag): harmless.

The gateway violates RFC 3711 3.3.1 (the packet index of an SSRC must not go back under the same
master key). SEMS fix: reset the SRTP receive context when a new SDP answer for the stream is
processed (re-INVITE/UPDATE) even with the unchanged key: the gateway 200 OK to the re-INVITE comes
19-32ms before the restarted stream in all three calls.

Open question: with libsrtp the `back-105` call should lose the 10 packets with the reused sequence
numbers 32322..32331 (`replay_fail`), but production relayed all of them. A SEMS debug log of such
a call (`add RTP receive stream context` / `remove old SRTP context`) would explain it.

## Test

`test_srtp_seq_restart.py` reproduces the three calls on the SEMS variant `srtp` (conftest
`SEMS_VARIANTS`, SDES profiles enabled): a gateway answering with its own key and the same key in the
re-INVITE answer, the latching packet, then the sequence restart taken from each pcap. The test
expects the gateway audio to reach the caller after the restart and the B-leg
`rx_srtp_decrypt_errors` (CDR `media_stats`) to be 1, the latching packet as in the production calls.
Lost packets counted as SRTP decrypt errors are reported as the production issue (`back-29912` fails
so until fixed), lost packets without them fail the test as another issue.

Requires `python3-cryptography` (SRTP in `lib/srtp.py`), the test is skipped without it.

```
python3 -m pytest -v e2e_tests/srtp_seq_restart
```
