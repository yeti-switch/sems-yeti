"""
SDES SRTP (RFC 3711, RFC 4568, AES-256 suites RFC 6188) for e2e RTP endpoints: packets protection by the
sender key, authentication and decryption by the remote key. requires 'cryptography' (python3-cryptography)

  * one ROC per SSRC (ROC 0: test streams do not wrap), no MKI, key derivation rate 0
  * receiver does not implement replay protection: the tests check what SEMS accepts
"""

import base64
import hashlib
import hmac
import os
import re
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# suite: (master key length, auth tag length)
SUITES = {
    "AES_256_CM_HMAC_SHA1_80": (32, 10),
    "AES_256_CM_HMAC_SHA1_32": (32, 4),
    "AES_CM_128_HMAC_SHA1_80": (16, 10),
    "AES_CM_128_HMAC_SHA1_32": (16, 4),
}
SALT_LEN = 14


def _prf(master_key, master_salt, label, length):
    """AES-CM key derivation (RFC 3711 4.3.1, 4.3.3)"""
    x = bytearray(master_salt)
    x[7] ^= label  # key_id = label || index DIV kdr (0), aligned to the right of the 14 bytes salt
    encryptor = Cipher(algorithms.AES(master_key), modes.CTR(bytes(x) + b"\0\0")).encryptor()
    return encryptor.update(b"\0" * length)


class SrtpContext:
    """session keys of one direction for the suite and the base64 'inline' key"""

    def __init__(self, suite, inline):
        self.suite = suite
        key_len, self.tag_len = SUITES[suite]
        raw = base64.b64decode(inline)
        master_key, master_salt = raw[:key_len], raw[key_len:key_len + SALT_LEN]
        self.enc_key = _prf(master_key, master_salt, 0, key_len)
        self.auth_key = _prf(master_key, master_salt, 1, 20)
        self.salt = _prf(master_key, master_salt, 2, SALT_LEN)

    def _keystream_xor(self, ssrc, index, data):
        iv = (int.from_bytes(self.salt, "big") << 16) ^ (ssrc << 64) ^ (index << 16)
        return Cipher(algorithms.AES(self.enc_key), modes.CTR(iv.to_bytes(16, "big"))).encryptor().update(data)

    def _tag(self, authenticated, roc):
        return hmac.new(self.auth_key, authenticated + struct.pack("!I", roc), hashlib.sha1).digest()[:self.tag_len]

    def protect(self, packet, roc=0):
        """RTP packet without CSRC/extensions -> SRTP packet"""
        seq, ssrc = struct.unpack("!H", packet[2:4])[0], struct.unpack("!I", packet[8:12])[0]
        encrypted = packet[:12] + self._keystream_xor(ssrc, (roc << 16) | seq, packet[12:])
        return encrypted + self._tag(encrypted, roc)

    def unprotect(self, packet, roc=0):
        """SRTP packet -> RTP packet or None if authentication failed"""
        if len(packet) < 12 + self.tag_len:
            return None
        body, tag = packet[:-self.tag_len], packet[-self.tag_len:]
        if not hmac.compare_digest(self._tag(body, roc), tag):
            return None
        seq, ssrc = struct.unpack("!H", body[2:4])[0], struct.unpack("!I", body[8:12])[0]
        return body[:12] + self._keystream_xor(ssrc, (roc << 16) | seq, body[12:])


def new_inline(suite):
    """random base64 master key || master salt for the suite"""
    return base64.b64encode(os.urandom(SUITES[suite][0] + SALT_LEN)).decode()


def crypto_lines(sdp_body):
    """[(tag, suite, inline key)] of a=crypto lines (RFC 4568)"""
    return [(int(t), s, k) for t, s, k in re.findall(r"^a=crypto:(\d+) (\S+) inline:([^|\s]+)", sdp_body or "", re.M)]
