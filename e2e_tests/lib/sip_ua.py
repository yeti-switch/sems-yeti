"""
SIP user agents over UDP for call tests. each agent handles one dialog:
  Caller             - UAC of the initial INVITE (originator)
  TerminationGateway - UAS of the initial INVITE (termination gateway)

common in-dialog behaviour (SipAgent):
  * re-INVITE/UPDATE with SDP are answered with 200 OK and SDP answer
    (direction mirrored), or rejected with reject_reoffer_code
  * BYE, PRACK, OPTIONS, INFO, NOTIFY are answered with 200 OK
  * hold(), unhold(), reinvite(), update(), bye() send in-dialog requests
  * all received requests are recorded (wait_request)
  * own RTP endpoint (self.rtp), its remote address is learned from peer SDP
"""

import hashlib
import re
import threading
import time
import uuid

import sdp as sdplib
from rtp import RtpEndpoint
from transport import make_transport

COMPACT_HEADERS = {
    "v": "via", "f": "from", "t": "to", "i": "call-id",
    "m": "contact", "l": "content-length", "c": "content-type", "k": "supported",
}


class SipMessage:
    def __init__(self, raw, addr=None):
        self.raw = raw
        self.addr = addr  # source (ip, port)
        self.time = time.monotonic()
        head, _, self.body = raw.partition("\r\n\r\n")
        lines = head.split("\r\n")
        self.start_line = lines[0]
        self.headers = []
        for line in lines[1:]:
            name, _, value = line.partition(":")
            name = name.strip().lower()
            self.headers.append((COMPACT_HEADERS.get(name, name), value.strip()))

        parts = self.start_line.split(" ", 2)
        if parts[0] == "SIP/2.0":
            self.method = None
            self.code = int(parts[1])
            self.reason = parts[2] if len(parts) > 2 else ""
        else:
            self.method = parts[0]
            self.ruri = parts[1]
            self.code = None

    @property
    def is_request(self):
        return self.method is not None

    def header(self, name):
        name = name.lower()
        for n, v in self.headers:
            if n == name:
                return v
        return None

    def header_all(self, name):
        name = name.lower()
        return [v for n, v in self.headers if n == name]

    def has_option_tag(self, header, tag):
        return any(tag in [t.strip().lower() for t in v.split(",")] for v in self.header_all(header))

    @property
    def call_id(self):
        return self.header("call-id")

    @property
    def cseq(self):
        num, method = self.header("cseq").split()
        return int(num), method

    @property
    def branch(self):
        m = re.search(r";branch=([^;,\s]+)", self.header("via") or "")
        return m.group(1) if m else None

    def tag(self, header):
        m = re.search(r";tag=([^;>\s]+)", self.header(header) or "")
        return m.group(1) if m else None

    @property
    def route_set(self):
        """entries of all Route headers: ['<sip:a;lr>', '<sip:b;lr>']"""
        return [r.strip() for v in self.header_all("route") for r in re.findall(r"<[^>]*>[^,]*", v)]

    @property
    def content_type(self):
        return (self.header("content-type") or "").split(";")[0].strip().lower()

    def parts(self):
        """multipart body parts: [{'content_type', 'headers': {name: value}, 'body'}]"""
        ct = self.header("content-type") or ""
        m = re.search(r'boundary="?([^";]+)"?', ct)
        if not self.content_type.startswith("multipart/") or not m:
            return []
        parts = []
        for chunk in self.body.split("--" + m.group(1))[1:]:
            if chunk.startswith("--"):
                break  # closing delimiter
            head, _, body = chunk.lstrip("\r\n").partition("\r\n\r\n")
            headers = {}
            for line in head.split("\r\n"):
                name, _, value = line.partition(":")
                if name.strip():
                    headers[name.strip().lower()] = value.strip()
            if body.endswith("\r\n"):
                body = body[:-2]  # CRLF preceding the delimiter belongs to it
            parts.append({"content_type": headers.get("content-type", "").split(";")[0].strip().lower(),
                          "headers": headers, "body": body})
        return parts

    @property
    def sdp_body(self):
        """SDP of the message: the body or the application/sdp part of multipart body"""
        if self.content_type.startswith("multipart/"):
            body = next((p["body"] for p in self.parts() if p["content_type"] == "application/sdp"), None)
        else:
            body = self.body
        return body if body and re.search(r"^v=0", body, re.MULTILINE) else None

    @property
    def sdp(self):
        return sdplib.parse(self.sdp_body) if self.sdp_body else None

    def __repr__(self):
        return f"<SipMessage {self.start_line}>"


def uri_of(name_addr):
    """extract URI from name-addr header value: '"x" <sip:a@b>;tag=1' -> 'sip:a@b'"""
    m = re.search(r"<([^>]+)>", name_addr)
    return m.group(1) if m else name_addr.split(";")[0].strip()


def uri_hostport(uri):
    """sip:user@host:port;params -> (host, port)"""
    m = re.match(r"sips?:(?:[^@]+@)?([^:;>]+)(?::(\d+))?", uri)
    return m.group(1), int(m.group(2) or 5060)


def uri_user(uri):
    m = re.match(r"sips?:([^@]+)@", uri)
    return m.group(1) if m else None


def sdp_audio(body):
    """returns (connection ip, audio port) from SDP"""
    return sdplib.connection(body) or (None, None)


class SipAgent:
    """
    transport: udp, tcp, tls, ws, wss (lib/transport.py), transport_kw are passed to the transport
    invalid_host: WebSocket client style addressing (RFC 7118): Via and Contact with
      '<random>.invalid' host, so requests to the agent can be sent only over its connection
    """

    def __init__(self, ip="127.0.0.1", port=0, codecs=("pcmu", "pcma", "telephone-event"),
                 transport="udp", invalid_host=False, **transport_kw):
        self.trsp = make_transport(transport, ip=ip, port=port, **transport_kw)
        self.ip, self.port = self.trsp.local
        self.transport = self.trsp.name
        self.invalid_host = f"{uuid.uuid4().hex[:12]}.invalid" if invalid_host else None
        self.tag = uuid.uuid4().hex[:8]

        self.rtp = RtpEndpoint(self.ip)
        self.sdp_session = sdplib.SdpSession(self.ip)
        self.codecs = list(codecs)    # offered/accepted audio codecs
        self.ptime = None
        self.reject_reoffer_code = None  # reject re-INVITE/UPDATE offers with this code
        self.contact_override = None     # Contact name-addr to advertise instead of own address
        self.offer_pending = False       # own re-INVITE/UPDATE offer waits for the answer (glare: 491)

        # dialog
        self.call_id = None
        self.local_hdr = None     # From of own requests (with own tag)
        self.remote_hdr = None    # To of own requests (with peer tag)
        self.remote_target = None
        self.cseq = 0

        self._cond = threading.Condition()
        self.requests = []    # all received requests
        self.replies = []     # all received replies
        self._pending = []    # not consumed replies
        self._running = True
        self.trsp.on_message = self._on_raw_message

    @property
    def rtp_port(self):
        return self.rtp.port

    @property
    def sent_by(self):
        """Via sent-by"""
        return self.invalid_host or f"{self.ip}:{self.port}"

    @property
    def contact_uri(self):
        params = "" if self.transport == "UDP" else f";transport={self.transport.lower()}"
        return f"sip:e2e@{self.sent_by}{params}"

    @property
    def contact(self):
        return self.contact_override or f"<{self.contact_uri}>"

    def stop(self):
        self._running = False
        self.trsp.close()
        self.rtp.stop()

    # transport

    def send(self, data, addr):
        """sends over the connection with addr (stream transports) or opens the new one"""
        self.trsp.send(data.encode() if isinstance(data, str) else data, tuple(addr))

    def _on_raw_message(self, data, addr, conn):
        if not self._running:
            return
        msg = SipMessage(data.decode(errors="replace"), addr)
        msg.conn = conn  # stream connection the message was received on (None for UDP)
        with self._cond:
            if msg.is_request:
                self.requests.append(msg)
            else:
                self.replies.append(msg)
                self._pending.append(msg)
            self._cond.notify_all()
        if msg.is_request:
            try:
                self.on_request(msg)
            except OSError:
                pass

    # messages

    def offer(self, direction="sendrecv", media=None):
        if media is None:
            media = [sdplib.Media("audio", self.rtp.port, codecs=self.codecs, direction=direction, ptime=self.ptime)]
        return self.sdp_session.build(media)

    def answer(self, offer_body, rtp=None):
        port = (rtp or self.rtp).port
        return sdplib.answer(offer_body, self.sdp_session, {"audio": port, "image": port},
                             codecs=self.codecs + ["cn"], ptime=self.ptime)

    def learn_remote_media(self, msg):
        if sdplib.has_sdp(msg):
            conn = sdplib.connection(msg.sdp_body)
            if conn:
                self.rtp.remote = conn

    def reply(self, req, code, reason, to_tag=None, body=None, extra=()):
        to = req.header("to")
        if to_tag and ";tag=" not in to:
            to += f";tag={to_tag}"
        lines = [f"SIP/2.0 {code} {reason}"]
        lines += [f"Via: {v}" for v in req.header_all("via")]
        lines += [
            f"From: {req.header('from')}",
            f"To: {to}",
            f"Call-ID: {req.call_id}",
            f"CSeq: {req.header('cseq')}",
        ]
        if 100 < code < 300 and req.method in ("INVITE", "UPDATE"):
            lines.append(f"Contact: {self.contact}")
        lines += extra
        if body:
            lines.append("Content-Type: application/sdp")
        lines.append(f"Content-Length: {len(body.encode()) if body else 0}")
        self.send("\r\n".join(lines) + "\r\n\r\n" + (body or ""), req.addr)

    def request(self, method, ruri, cseq, dst, to_hdr=None, body=None, extra=(), branch=None, contact=None,
                content_type="application/sdp"):
        branch = branch or "z9hG4bK" + uuid.uuid4().hex[:16]
        lines = [
            f"{method} {ruri} SIP/2.0",
            f"Via: SIP/2.0/{self.transport} {self.sent_by};branch={branch};rport",
            "Max-Forwards: 70",
            f"From: {self.local_hdr}",
            f"To: {to_hdr or self.remote_hdr}",
            f"Call-ID: {self.call_id}",
            f"CSeq: {cseq} {method}",
            *([] if contact == "" else [f"Contact: {contact or self.contact}"]),
            *extra,
        ]
        if body:
            lines.append(f"Content-Type: {content_type}")
        lines.append(f"Content-Length: {len(body.encode()) if body else 0}")
        self.send("\r\n".join(lines) + "\r\n\r\n" + (body or ""), dst)
        return branch

    # waiting

    def wait_request(self, method, timeout=5, call_id=None, pred=None, after=None):
        """wait for the first received request matching method/call-id/predicate
        (and received after the 'after' monotonic time)"""
        def find():
            for r in self.requests:
                if (r.method == method and (call_id is None or r.call_id == call_id)
                        and (pred is None or pred(r)) and (after is None or r.time >= after)):
                    return r
            return None
        with self._cond:
            self._cond.wait_for(find, timeout)
            return find()

    def requests_of(self, method, after=None):
        with self._cond:
            return [r for r in self.requests if r.method == method and (after is None or r.time >= after)]

    def wait_reply(self, cseq_method, cseq=None, timeout=5, final=True):
        """consume replies for own request, returns the first final (or any) one"""
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                for r in list(self._pending):
                    if (r.call_id == self.call_id and r.cseq[1] == cseq_method
                            and (cseq is None or r.cseq[0] == cseq)):
                        self._pending.remove(r)
                        if not final or r.code >= 200:
                            return r
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                self._cond.wait(left)

    # in-dialog requests

    def in_dialog(self, method, body=None, extra=(), timeout=5, content_type="application/sdp"):
        """send in-dialog request, returns final reply. INVITE final replies are ACKed"""
        self.cseq += 1
        cseq = self.cseq
        dst = uri_hostport(self.remote_target)
        is_offer = method in ("INVITE", "UPDATE") and bool(body)
        if is_offer:
            self.offer_pending = True
        try:
            branch = self.request(method, self.remote_target, cseq, dst, body=body, extra=extra,
                                  content_type=content_type)
            reply = self.wait_reply(method, cseq, timeout)
        finally:
            if is_offer:
                self.offer_pending = False
        if reply is not None and method == "INVITE":
            if reply.code < 300:
                self.request("ACK", self.remote_target, cseq, dst)
            else:
                self.request("ACK", self.remote_target, cseq, dst, branch=branch)
        if reply is not None and reply.code < 300:
            self.learn_remote_media(reply)
        return reply

    def reinvite(self, direction="sendrecv", body=None, extra=(), content_type="application/sdp"):
        return self.in_dialog("INVITE", body or self.offer(direction), extra, content_type=content_type)

    def update(self, direction="sendrecv", body=None, extra=()):
        return self.in_dialog("UPDATE", body or self.offer(direction), extra)

    def hold(self):
        return self.reinvite("sendonly")

    def unhold(self):
        return self.reinvite("sendrecv")

    def bye(self, timeout=5):
        return self.in_dialog("BYE", timeout=timeout)

    def is_in_dialog(self, req):
        return req.call_id == self.call_id and req.tag("to") is not None

    def on_request(self, req):
        if req.method in ("INVITE", "UPDATE") and self.is_in_dialog(req):
            if req.method == "INVITE":
                self.reply(req, 100, "Trying")
            if self.reject_reoffer_code:
                self.reply(req, self.reject_reoffer_code, "Rejected by test")
                return
            if self.offer_pending and sdplib.has_sdp(req):
                # RFC 3311 5.2 / RFC 3261 14.2: offer while own offer is pending
                self.reply(req, 491, "Request Pending", extra=["Retry-After: 1"])
                return
            body = None
            if sdplib.has_sdp(req):
                self.learn_remote_media(req)
                body = self.answer(req.sdp_body)
            elif req.method == "INVITE":
                body = self.offer()  # late offer, answer comes in ACK
            self.reply(req, 200, "OK", body=body)
        elif req.method == "ACK":
            self.learn_remote_media(req)
        elif req.method in ("BYE", "PRACK", "OPTIONS", "INFO", "NOTIFY"):
            self.reply(req, 200, "OK")
        else:
            self.reply(req, 405, "Method Not Allowed")


class Caller(SipAgent):
    """originates one call. supported/require: option tags for the initial INVITE"""

    def __init__(self, supported=(), require=(), **kw):
        super().__init__(**kw)
        self.call_id = uuid.uuid4().hex
        self.local_hdr = f"<sip:caller@{self.ip}>;tag={self.tag}"
        self.supported = list(supported)
        self.require = list(require)
        self.provisional = []    # 1xx replies received for the initial INVITE
        self.prack_replies = []  # final replies for PRACKs sent
        self.remote_tag = None

    def invite(self, dst, user="1234", timeout=10, body=None, headers=(), content_type="application/sdp"):
        """send INVITE with SDP offer (own or the given body), returns final reply.
        final reply is ACKed. reliable provisional replies are PRACKed"""
        ruri = f"sip:{user}@{dst[0]}:{dst[1]}"
        to_hdr = f"<{ruri}>"
        self.remote_hdr = to_hdr
        extra = list(headers)
        if self.supported:
            extra.append(f"Supported: {', '.join(self.supported)}")
        if self.require:
            extra.append(f"Require: {', '.join(self.require)}")

        self.cseq += 1
        invite_cseq = self.cseq
        branch = self.request("INVITE", ruri, invite_cseq, dst, to_hdr=to_hdr, body=body or self.offer(), extra=extra,
                              content_type=content_type)

        pracked = set()
        deadline = time.monotonic() + timeout
        while True:
            reply = self.wait_reply("INVITE", invite_cseq, deadline - time.monotonic(), final=False)
            if reply is None:
                return None
            if reply.code >= 200:
                break
            self.provisional.append(reply)
            self.learn_remote_media(reply)
            rseq = reply.header("rseq")
            if rseq and reply.has_option_tag("require", "100rel") and rseq not in pracked:
                pracked.add(rseq)
                self._prack(reply, invite_cseq, rseq)

        self.remote_tag = reply.tag("to")
        self.remote_hdr = reply.header("to")
        if 200 <= reply.code < 300:
            self.remote_target = uri_of(reply.header("contact"))
            self.learn_remote_media(reply)
            self.request("ACK", self.remote_target, invite_cseq, uri_hostport(self.remote_target))
        else:
            self.request("ACK", ruri, invite_cseq, dst, branch=branch)
        return reply

    def _prack(self, reply, invite_cseq, rseq):
        self.remote_hdr = reply.header("to")
        self.remote_target = uri_of(reply.header("contact"))
        self.cseq += 1
        cseq = self.cseq
        self.request("PRACK", self.remote_target, cseq, uri_hostport(self.remote_target),
                     extra=[f"RAck: {rseq} {invite_cseq} INVITE"])

        def wait():
            r = self.wait_reply("PRACK", cseq, timeout=5)
            if r is not None:
                self.prack_replies.append(r)
        threading.Thread(target=wait, daemon=True).start()


class EarlyReply:
    """provisional reply sent by TerminationGateway before answering"""

    def __init__(self, code=183, reason="Session Progress", with_sdp=True, headers=(), reliable=False):
        self.code = code
        self.reason = reason
        self.with_sdp = with_sdp
        self.headers = list(headers)
        self.reliable = reliable  # send with Require: 100rel and wait for PRACK before answering


class TerminationGateway(SipAgent):
    """
    answers INVITEs with 200 OK and SDP answer.
    early_replies: provisional replies sent before 200 OK. answered after answer_delay
    or after PRACK for the reliable one.
    answer_codecs/answer_ptime: change SDP answer in 200 OK comparing to early SDP
    no_answer: do not answer the INVITE (wait for CANCEL or reject())
    CANCEL of the pending INVITE is answered with 200 OK and the INVITE with 487
    auth: GatewayAuth to challenge requests (yeti B-leg authentication)
    """

    def __init__(self, **kw):
        super().__init__(**kw)
        self.invite_req = None
        self.early_replies = []
        self.answer_delay = 0.2
        self.answer_codecs = None
        self.answer_ptime = None
        self.answer_rtp = None  # RtpEndpoint for SDP in 200 OK (RTP address change comparing to 18x)
        self.no_answer = False
        self.final_code = None  # final reply code sent for the initial INVITE
        self.auth = None
        self._rseq = 0
        self._waiting_prack = False
        self._early_sdp = None

    def on_request(self, req):
        if self.auth is not None and not self.auth.check(self, req):
            return
        if req.method == "INVITE" and req.tag("to") is None:
            self._on_initial_invite(req)
        elif req.method == "CANCEL" and self.invite_req is not None and req.branch == self.invite_req.branch:
            self.reply(req, 200, "OK", to_tag=self.tag)
            self.reject(487, "Request Terminated")
        elif req.method == "PRACK" and req.call_id == self.call_id and self._waiting_prack:
            self.reply(req, 200, "OK")
            self._waiting_prack = False
            self._answer_later()
        else:
            super().on_request(req)

    def _on_initial_invite(self, req):
        if self.invite_req is not None and req.branch == self.invite_req.branch:
            return  # retransmission. 100 Trying was sent already
        self.invite_req = req
        self.call_id = req.call_id
        self.local_hdr = f"{req.header('to')};tag={self.tag}"
        self.remote_hdr = req.header("from")
        self.remote_target = uri_of(req.header("contact"))
        self.learn_remote_media(req)

        self.reply(req, 100, "Trying")
        early_sdp = self.answer(req.sdp_body) if sdplib.has_sdp(req) and self.early_replies else None
        self._early_sdp = early_sdp
        for early in self.early_replies:
            extra = list(early.headers)
            if early.reliable:
                self._rseq += 1
                extra += ["Require: 100rel", f"RSeq: {self._rseq}"]
                self._waiting_prack = True
            self.reply(req, early.code, early.reason, to_tag=self.tag,
                       body=early_sdp if early.with_sdp else None, extra=extra)
        if not self._waiting_prack:
            if self.early_replies:
                self._answer_later()
            else:
                self._answer()

    @property
    def early_sdp(self):
        """SDP sent in provisional replies"""
        return self._early_sdp

    def reject(self, code, reason):
        """final non-2xx reply for the pending initial INVITE (ignored if it was replied already)"""
        if self.invite_req is None or self.final_code is not None:
            return
        self.final_code = code
        self.reply(self.invite_req, code, reason, to_tag=self.tag)

    def _answer_later(self):
        if self.no_answer:
            return
        if self.answer_delay:
            threading.Timer(self.answer_delay, self._answer).start()
        else:
            self._answer()

    def _answer(self):
        if not self._running or self.no_answer:
            return
        req = self.invite_req
        if self.answer_codecs or self.answer_ptime or self.answer_rtp:
            # SDP in 200 OK differs from the early one
            self.codecs = list(self.answer_codecs or self.codecs)
            self.ptime = self.answer_ptime or self.ptime
            body = self.answer(req.sdp_body, rtp=self.answer_rtp)
        elif self._early_sdp:
            body = self._early_sdp  # the same SDP as in 18x
        else:
            body = self.answer(req.sdp_body) if sdplib.has_sdp(req) else self.offer()
        self.final_code = 200
        self.reply(req, 200, "OK", to_tag=self.tag, body=body)


DIGEST_HASHES = {"MD5": hashlib.md5, "SHA-256": hashlib.sha256}


def challenge_params(challenge):
    """parameters of 'Digest k=v, ...' challenge or credentials"""
    return {k.lower(): q or t
            for k, q, t in re.findall(r'(\w+)=(?:"([^"]*)"|([^\s,]+))', challenge.partition(" ")[2])}


def pick_challenge(reply, algorithm=None):
    """WWW-Authenticate challenge of the reply for the algorithm (the first one if not set)"""
    for c in reply.header_all("www-authenticate") + reply.header_all("proxy-authenticate"):
        if algorithm is None or challenge_params(c).get("algorithm", "MD5").upper() == algorithm.upper():
            return c
    return None


def digest_authorization(challenge, method, uri, user, password, qop="auto", nc=1, cnonce=None, body="",
                         algorithm=None):
    """
    Authorization header value for the WWW-Authenticate/Proxy-Authenticate challenge (RFC 7616/2617)
      qop: 'auto' (auth if offered), 'auth', 'auth-int' or None (RFC 2069 response without qop)
      nc, cnonce: nonce count (int or raw string) and client nonce
      body: request body for auth-int
      algorithm: MD5, SHA-256 (default: the challenge one)
    """
    params = challenge_params(challenge)
    realm, nonce = params["realm"], params["nonce"]
    algorithm = (algorithm or params.get("algorithm") or "MD5").upper()
    hash_func = DIGEST_HASHES[algorithm]

    def h(v):
        return hash_func(v.encode()).hexdigest()

    if qop == "auto":
        offered = [q.strip() for q in params.get("qop", "").split(",") if q.strip()]
        qop = "auth" if "auth" in offered else (offered[0] if offered else None)

    ha1 = h(f"{user}:{realm}:{password}")
    ha2 = h(f"{method}:{uri}:{h(body)}") if qop == "auth-int" else h(f"{method}:{uri}")
    auth = [f'username="{user}"', f'realm="{realm}"', f'nonce="{nonce}"', f'uri="{uri}"',
            f"algorithm={algorithm}"]
    if qop:
        nc = nc if isinstance(nc, str) else f"{nc:08x}"
        cnonce = cnonce or uuid.uuid4().hex[:16]
        response = h(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        auth += [f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"']
    else:
        response = h(f"{ha1}:{nonce}:{ha2}")
    auth.append(f'response="{response}"')
    if "opaque" in params:
        auth.append(f'opaque="{params["opaque"]}"')
    return "Digest " + ", ".join(auth)


class Registrant(SipAgent):
    """
    registers contacts for the AoR of the user from incoming auth credentials
    (etc/db_map/load_incoming_auth.json). yeti uses the credentials id as AoR id.
    REGISTER is sent from own socket, the registered Contact points to another agent (device),
    so the registrant acts as an edge proxy when Path is added
    """

    def __init__(self, user, password, **kw):
        super().__init__(**kw)
        self.user = user
        self.password = password
        self.call_id = uuid.uuid4().hex
        self.local_hdr = f"<sip:{user}@{self.ip}>;tag={self.tag}"
        self.remote_hdr = f"<sip:{user}@{self.ip}>"
        self.registered_dst = None  # where bindings were registered (for unregister_all)

    def register(self, dst, contact, expires=60, path=None, extra=(), retry_auth=True):
        """REGISTER answering digest challenge. returns final reply
        contact: name-addr (with params), list of them, '*' or '' (no Contact: query bindings)
        expires: Expires header value or None (no header)
        path: Path header value or list of values (separate headers)
        retry_auth: answer the challenge, otherwise return the first reply"""
        ruri = f"sip:{dst[0]}:{dst[1]}"
        if isinstance(contact, (list, tuple)):
            contact = ", ".join(contact)
        extra = list(extra)
        if expires is not None:
            extra.append(f"Expires: {expires}")
        for p in ([path] if isinstance(path, str) else path or []):
            extra.append(f"Path: {p}")

        reply = None
        for _ in range(2):
            self.cseq += 1
            self.request("REGISTER", ruri, self.cseq, dst, extra=extra, contact=contact)
            reply = self.wait_reply("REGISTER", self.cseq)
            if reply is None or reply.code not in (401, 407) or not retry_auth:
                break
            challenge = reply.header("www-authenticate") or reply.header("proxy-authenticate")
            auth_hdr = "Authorization" if reply.code == 401 else "Proxy-Authorization"
            extra = [h for h in extra if not h.startswith(auth_hdr)]
            extra.append(f"{auth_hdr}: {digest_authorization(challenge, 'REGISTER', ruri, self.user, self.password)}")

        if reply is not None and reply.code == 200 and contact:
            self.registered_dst = dst
        return reply

    def unregister_all(self):
        """remove all bindings of the AoR (Contact: *)"""
        dst = self.registered_dst
        if dst:
            self.register(dst, "*", expires=0)


def bindings(reply):
    """{contact uri: expires} from Contact headers of REGISTER reply"""
    ret = {}
    for value in reply.header_all("contact"):
        for c in re.findall(r"<[^>]*>[^,]*", value):
            m = re.search(r";\s*expires\s*=\s*(\d+)", c[c.index(">"):])
            ret[uri_of(c)] = int(m.group(1)) if m else None
    return ret


def contact_key(uri):
    """
    comparison key for SIP URIs (RFC 3261 19.1.4) to compare registered contacts:
    scheme, user, host (case-insensitive), port (default 5060) and the uri-parameters
    which must match when present in either URI (user, ttl, method, maddr).
    other parameters (e.g. transport added by registrar) are ignored
    """
    m = re.match(r"(sips?):(?:([^@]+)@)?([^:;>?]+)(?::(\d+))?([^?>]*)", uri.strip().strip("<>"))
    scheme, user, host, port, params = m.groups()
    strict = sorted(p.lower() for p in params.split(";")[1:] if p.split("=")[0].lower() in ("user", "ttl", "method", "maddr"))
    return f"{scheme}:{user + '@' if user else ''}{host.lower()}:{port or 5060}{''.join(';' + p for p in strict)}"


def verify_digest(req, credentials, user, password):
    """verifies digest credentials (Authorization/Proxy-Authorization value) of the request
    independently from digest_authorization: MD5/SHA-256, qop auth/auth-int/none.
    returns (valid, credentials params)"""
    p = challenge_params(credentials)
    hash_func = DIGEST_HASHES.get((p.get("algorithm") or "MD5").upper())
    if hash_func is None or p.get("username") != user:
        return False, p

    def h(v):
        return hash_func(v.encode()).hexdigest()

    try:
        ha1 = h(f"{user}:{p['realm']}:{password}")
        qop = p.get("qop")
        ha2 = h(f"{req.method}:{p['uri']}:{h(req.body)}") if qop == "auth-int" else h(f"{req.method}:{p['uri']}")
        if qop:
            expected = h(f"{ha1}:{p['nonce']}:{p['nc']}:{p['cnonce']}:{qop}:{ha2}")
        else:
            expected = h(f"{ha1}:{p['nonce']}:{ha2}")
    except KeyError:
        return False, p
    return expected == p.get("response"), p


def check_digest(req, user, password):
    """verifies Authorization of the request (independently from digest_authorization)"""
    auth = req.header("authorization")
    return bool(auth) and verify_digest(req, auth, user, password)[0]


class GatewayAuth:
    """
    digest authentication of requests received by TerminationGateway (UAS side, RFC 7616)
      algorithms: challenge per algorithm in order of preference
      qop: qop challenge parameter ('auth', 'auth-int', 'auth,auth-int') or None
      code: 401 (WWW-Authenticate/Authorization) or 407 (Proxy-Authenticate/Proxy-Authorization)
      stale_methods: requests of these methods with valid credentials are challenged once more
        with a new nonce and stale=true (previous nonces become invalid)
    requests without credentials or with invalid ones are challenged (ACK and CANCEL are not).
    received: (request, credentials params, status: 'ok', 'invalid' or 'stale') for every request
      with credentials
    """

    REALM = "e2e.gw"

    def __init__(self, user, password, algorithms=("MD5",), qop="auth,auth-int", code=401):
        self.user = user
        self.password = password
        self.algorithms = list(algorithms)
        self.qop = qop
        self.code = code
        self.stale_methods = set()
        self.nonces = {}  # valid nonce -> algorithm
        self.challenged = []  # challenged requests
        self.received = []

    @property
    def credentials_header(self):
        return "authorization" if self.code == 401 else "proxy-authorization"

    def check(self, agent, req):
        """returns True if the request is authenticated, otherwise it is challenged"""
        if req.method in ("ACK", "CANCEL"):
            return True
        credentials = req.header(self.credentials_header)
        if credentials is None:
            self.challenge(agent, req)
            return False
        valid, p = verify_digest(req, credentials, self.user, self.password)
        valid = (valid and p.get("realm") == self.REALM
                 and self.nonces.get(p.get("nonce")) == (p.get("algorithm") or "MD5").upper())
        if not valid:
            self.received.append((req, p, "invalid"))
            self.challenge(agent, req)
            return False
        if req.method in self.stale_methods:
            self.received.append((req, p, "stale"))
            self.stale_methods.discard(req.method)
            self.nonces.clear()
            self.challenge(agent, req, stale=True)
            return False
        self.received.append((req, p, "ok"))
        return True

    def challenge(self, agent, req, stale=False):
        self.challenged.append(req)
        name = "WWW-Authenticate" if self.code == 401 else "Proxy-Authenticate"
        extra = []
        for alg in self.algorithms:
            nonce = uuid.uuid4().hex
            self.nonces[nonce] = alg.upper()
            params = [f'realm="{self.REALM}"', f'nonce="{nonce}"']
            if self.qop:
                params.append(f'qop="{self.qop}"')
            params.append(f"algorithm={alg}")
            if stale:
                params.append("stale=true")
            extra.append(f"{name}: Digest {', '.join(params)}")
        reason = "Unauthorized" if self.code == 401 else "Proxy Authentication Required"
        agent.reply(req, self.code, reason, to_tag=agent.tag, extra=extra)

    def authenticated(self, method=None):
        """(request, credentials params) of accepted requests"""
        return [(r, p) for r, p, status in self.received if status == "ok" and (method is None or r.method == method)]


class RemoteServer(SipAgent):
    """
    remote SIP server for yeti outgoing requests: registrar for outgoing registrations
    and target for OPTIONS probers.
      auth: (user, password) to challenge REGISTER/OPTIONS with 401 and verify digest (403 on mismatch)
      reply_code: fixed final reply code (e.g. 503)
    REGISTER 200 OK:
      granted_expires: expires of the binding (None: requested one)
      expires_in: 'param' (Contact ';expires='), 'header' (Expires header) or 'none'
      contact_mode: 'echo' (requested Contact) or 'other' (another contact only)
    """

    REALM = "e2e.registrar"

    def __init__(self, **kw):
        super().__init__(**kw)
        self.auth = None
        self.reply_code = None
        self.granted_expires = None
        self.expires_in = "param"
        self.contact_mode = "echo"
        self._nonce = 0

    def on_request(self, req):
        if req.method not in ("REGISTER", "OPTIONS"):
            return super().on_request(req)

        if self.auth:
            if not req.header("authorization"):
                self._nonce += 1
                challenge = f'Digest realm="{self.REALM}", nonce="e2e{self._nonce}", qop="auth", algorithm=MD5'
                self.reply(req, 401, "Unauthorized", to_tag=self.tag, extra=[f"WWW-Authenticate: {challenge}"])
                return
            if not check_digest(req, *self.auth):
                self.reply(req, 403, "Forbidden", to_tag=self.tag)
                return

        if self.reply_code:
            self.reply(req, self.reply_code, "Rejected by test", to_tag=self.tag)
            return

        if req.method == "OPTIONS":
            self.reply(req, 200, "OK", to_tag=self.tag)
            return

        requested = req.header("expires")
        expires = self.granted_expires if self.granted_expires is not None else int(requested or 3600)
        contact = req.header("contact") or ""
        if self.contact_mode == "other":
            contact = "<sip:somebody-else@192.0.2.1:5060>"
        contact = contact.split(";expires=")[0]
        extra = []
        if contact and expires:
            if self.expires_in == "param":
                contact += f";expires={expires}"
            elif self.expires_in == "header":
                extra.append(f"Expires: {expires}")
            extra.insert(0, f"Contact: {contact}")
        self.reply(req, 200, "OK", to_tag=self.tag, extra=extra)
