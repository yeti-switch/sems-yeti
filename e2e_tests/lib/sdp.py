"""SDP building, parsing and answering for e2e SIP agents"""

import itertools
import re
import time

# payload type -> (encoding name, clock rate)
STATIC_PAYLOADS = {0: ("PCMU", 8000), 8: ("PCMA", 8000), 13: ("CN", 8000), 18: ("G729", 8000)}
DYNAMIC_PAYLOADS = {"telephone-event": 101}

DIRECTIONS = ("sendrecv", "sendonly", "recvonly", "inactive")
ANSWER_DIRECTION = {"sendrecv": "sendrecv", "sendonly": "recvonly", "recvonly": "sendonly", "inactive": "inactive"}

T38_ATTRS = [
    "T38FaxVersion:0",
    "T38MaxBitRate:14400",
    "T38FaxRateManagement:transferredTCF",
    "T38FaxMaxBuffer:2000",
    "T38FaxMaxDatagram:400",
    "T38FaxUdpEC:t38UDPRedundancy",
]

_session_ids = itertools.count(int(time.time()))


class Media:
    """m= line. codecs: encoding names ('pcmu', 'telephone-event', ...) for audio"""

    def __init__(self, type="audio", port=0, codecs=("pcmu", "pcma", "telephone-event"),
                 direction="sendrecv", ptime=None, proto=None):
        self.type = type
        self.port = port
        self.codecs = [c.lower() for c in codecs]
        self.direction = direction
        self.ptime = ptime
        self.proto = proto or ("udptl" if type == "image" else "RTP/AVP")

    def lines(self):
        if self.type == "image":
            out = [f"m=image {self.port} {self.proto} t38"]
            if self.port:
                out += [f"a={a}" for a in T38_ATTRS]
            return out

        pts = []
        attrs = []
        for name in self.codecs:
            pt = payload_type(name)
            pts.append(str(pt))
            enc, rate = encoding(name)
            attrs.append(f"a=rtpmap:{pt} {enc}/{rate}")
            if name == "telephone-event":
                attrs.append(f"a=fmtp:{pt} 0-15")
        out = [f"m={self.type} {self.port} {self.proto} {' '.join(pts)}"] + attrs
        if self.ptime:
            out.append(f"a=ptime:{self.ptime}")
        out.append(f"a={self.direction}")
        return out


def payload_type(name):
    for pt, (enc, _) in STATIC_PAYLOADS.items():
        if enc.lower() == name:
            return pt
    return DYNAMIC_PAYLOADS[name]


def encoding(name):
    for enc, rate in STATIC_PAYLOADS.values():
        if enc.lower() == name:
            return enc, rate
    return name, 8000


class SdpSession:
    """SDP of one SIP agent: keeps origin and increments version on every new SDP"""

    def __init__(self, ip):
        self.ip = ip
        self.session_id = next(_session_ids)
        self.version = 0

    def build(self, media):
        self.version += 1
        lines = [
            "v=0",
            f"o=e2e {self.session_id} {self.version} IN IP4 {self.ip}",
            "s=-",
            f"c=IN IP4 {self.ip}",
            "t=0 0",
        ]
        for m in media:
            lines += m.lines()
        return "\r\n".join(lines) + "\r\n"


def parse(body):
    """returns {'version', 'connection', 'media': [{type, port, proto, fmts, codecs, direction, ptime,
    rtpmap: {pt: 'name/rate' (lowercase)}, fmtp: {pt: params}}]}"""
    sdp = {"version": None, "connection": None, "media": []}
    if not body:
        return sdp
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("o="):
            sdp["version"] = int(line.split()[2])
        elif line.startswith("c=") and not sdp["media"]:
            sdp["connection"] = line.split()[-1]
        elif line.startswith("m="):
            mtype, port, proto, *fmts = line[2:].split()
            sdp["media"].append({"type": mtype, "port": int(port), "proto": proto, "fmts": fmts,
                                 "codecs": [], "direction": "sendrecv", "ptime": None, "rtpmap": {}, "fmtp": {},
                                 "connection": sdp["connection"]})
        elif sdp["media"]:
            m = sdp["media"][-1]
            if line.startswith("c="):
                m["connection"] = line.split()[-1]
            elif line.startswith("a=rtpmap:"):
                pt, enc = line[len("a=rtpmap:"):].split(None, 1)
                m["codecs"].append(enc.split("/")[0].lower())
                m["rtpmap"][pt] = "/".join(enc.lower().split("/")[:2])
            elif line.startswith("a=fmtp:"):
                pt, _, params = line[len("a=fmtp:"):].partition(" ")
                m["fmtp"][pt] = params.strip()
            elif line.startswith("a=ptime:"):
                m["ptime"] = int(line.split(":")[1])
            elif line[2:] in DIRECTIONS:
                m["direction"] = line[2:]
    # static payloads without rtpmap
    for m in sdp["media"]:
        if m["type"] == "audio" and not m["codecs"]:
            m["codecs"] = [STATIC_PAYLOADS[int(f)][0].lower() for f in m["fmts"] if int(f) in STATIC_PAYLOADS]
        for f in m["fmts"]:
            if f.isdigit() and int(f) in STATIC_PAYLOADS and f not in m["rtpmap"]:
                enc, rate = STATIC_PAYLOADS[int(f)]
                m["rtpmap"][f] = f"{enc.lower()}/{rate}"
    return sdp


def audio(sdp):
    """first active audio stream of parsed SDP or None"""
    for m in sdp["media"]:
        if m["type"] == "audio" and m["port"]:
            return m
    return None


def answer(offer_body, session, ports, codecs=("pcmu", "pcma", "cn", "telephone-event"), ptime=None):
    """
    builds SDP answer for the offer:
      * the same number of streams, rejected (port 0) streams stay rejected
      * audio: offered codecs supported by us, direction mirrored
      * image (T.38): accepted on ports['image']
    """
    offer = parse(offer_body)
    media = []
    for m in offer["media"]:
        if m["port"] == 0 or m["type"] not in ports:
            media.append(Media(m["type"], 0, codecs=m["codecs"] or ("pcmu",), direction="inactive", proto=m["proto"]))
            continue
        if m["type"] == "image":
            media.append(Media("image", ports["image"], proto=m["proto"]))
            continue
        common = [c for c in m["codecs"] if c in codecs] or ["pcmu"]
        media.append(Media(m["type"], ports[m["type"]], codecs=common,
                           direction=ANSWER_DIRECTION[m["direction"]], ptime=ptime, proto=m["proto"]))
    return session.build(media)


def first_audio_codec_pt(media):
    """payload type of the first codec in parsed audio media skipping telephone-event and CN"""
    for f in media["fmts"]:
        enc = media["rtpmap"].get(f, "")
        if not enc.startswith(("telephone-event", "cn/")):
            return int(f)
    return None


def is_hold(body):
    m = audio(parse(body))
    return m is not None and m["direction"] in ("sendonly", "inactive")


def connection(body):
    """(ip, port) of the first active audio stream"""
    sdp = parse(body)
    m = audio(sdp)
    if m is None:
        return None
    return (m["connection"] or sdp["connection"], m["port"])


def has_sdp(msg):
    return bool(msg.body) and re.search(r"^v=0", msg.body, re.MULTILINE) is not None
