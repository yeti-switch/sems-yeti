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

import re
import socket
import threading
import time
import uuid

import sdp as sdplib
from rtp import RtpEndpoint

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
    def sdp(self):
        return sdplib.parse(self.body) if sdplib.has_sdp(self) else None

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
    def __init__(self, ip="127.0.0.1", port=0, codecs=("pcmu", "pcma", "telephone-event")):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))
        self.sock.settimeout(0.1)
        self.ip, self.port = self.sock.getsockname()
        self.tag = uuid.uuid4().hex[:8]

        self.rtp = RtpEndpoint(self.ip)
        self.sdp_session = sdplib.SdpSession(self.ip)
        self.codecs = list(codecs)    # offered/accepted audio codecs
        self.ptime = None
        self.reject_reoffer_code = None  # reject re-INVITE/UPDATE offers with this code

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
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    @property
    def rtp_port(self):
        return self.rtp.port

    @property
    def contact(self):
        return f"<sip:e2e@{self.ip}:{self.port}>"

    def stop(self):
        self._running = False
        self._thread.join()
        self.sock.close()
        self.rtp.stop()

    # transport

    def send(self, data, addr):
        self.sock.sendto(data.encode(), addr)

    def _run(self):
        while self._running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            msg = SipMessage(data.decode(errors="replace"), addr)
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
                    break

    # messages

    def offer(self, direction="sendrecv", media=None):
        if media is None:
            media = [sdplib.Media("audio", self.rtp.port, codecs=self.codecs, direction=direction, ptime=self.ptime)]
        return self.sdp_session.build(media)

    def answer(self, offer_body):
        return sdplib.answer(offer_body, self.sdp_session, {"audio": self.rtp.port, "image": self.rtp.port},
                             codecs=self.codecs + ["cn"], ptime=self.ptime)

    def learn_remote_media(self, msg):
        if sdplib.has_sdp(msg):
            conn = sdplib.connection(msg.body)
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

    def request(self, method, ruri, cseq, dst, to_hdr=None, body=None, extra=(), branch=None):
        branch = branch or "z9hG4bK" + uuid.uuid4().hex[:16]
        lines = [
            f"{method} {ruri} SIP/2.0",
            f"Via: SIP/2.0/UDP {self.ip}:{self.port};branch={branch};rport",
            "Max-Forwards: 70",
            f"From: {self.local_hdr}",
            f"To: {to_hdr or self.remote_hdr}",
            f"Call-ID: {self.call_id}",
            f"CSeq: {cseq} {method}",
            f"Contact: {self.contact}",
            *extra,
        ]
        if body:
            lines.append("Content-Type: application/sdp")
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

    def in_dialog(self, method, body=None, extra=(), timeout=5):
        """send in-dialog request, returns final reply. INVITE final replies are ACKed"""
        self.cseq += 1
        cseq = self.cseq
        dst = uri_hostport(self.remote_target)
        branch = self.request(method, self.remote_target, cseq, dst, body=body, extra=extra)
        reply = self.wait_reply(method, cseq, timeout)
        if reply is not None and method == "INVITE":
            if reply.code < 300:
                self.request("ACK", self.remote_target, cseq, dst)
            else:
                self.request("ACK", self.remote_target, cseq, dst, branch=branch)
        if reply is not None and reply.code < 300:
            self.learn_remote_media(reply)
        return reply

    def reinvite(self, direction="sendrecv", body=None, extra=()):
        return self.in_dialog("INVITE", body or self.offer(direction), extra)

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
            body = None
            if sdplib.has_sdp(req):
                self.learn_remote_media(req)
                body = self.answer(req.body)
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

    def invite(self, dst, user="1234", timeout=10, body=None):
        """send INVITE with SDP offer (own or the given body), returns final reply.
        final reply is ACKed. reliable provisional replies are PRACKed"""
        ruri = f"sip:{user}@{dst[0]}:{dst[1]}"
        to_hdr = f"<{ruri}>"
        self.remote_hdr = to_hdr
        extra = []
        if self.supported:
            extra.append(f"Supported: {', '.join(self.supported)}")
        if self.require:
            extra.append(f"Require: {', '.join(self.require)}")

        self.cseq += 1
        invite_cseq = self.cseq
        branch = self.request("INVITE", ruri, invite_cseq, dst, to_hdr=to_hdr, body=body or self.offer(), extra=extra)

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
    """

    def __init__(self, **kw):
        super().__init__(**kw)
        self.invite_req = None
        self.early_replies = []
        self.answer_delay = 0.2
        self.answer_codecs = None
        self.answer_ptime = None
        self._rseq = 0
        self._waiting_prack = False
        self._early_sdp = None

    def on_request(self, req):
        if req.method == "INVITE" and req.tag("to") is None:
            self._on_initial_invite(req)
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
        early_sdp = self.answer(req.body) if sdplib.has_sdp(req) and self.early_replies else None
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

    def _answer_later(self):
        if self.answer_delay:
            threading.Timer(self.answer_delay, self._answer).start()
        else:
            self._answer()

    def _answer(self):
        if not self._running:
            return
        req = self.invite_req
        if self.answer_codecs or self.answer_ptime:
            # SDP in 200 OK differs from the early one
            self.codecs = list(self.answer_codecs or self.codecs)
            self.ptime = self.answer_ptime or self.ptime
            body = self.answer(req.body)
        elif self._early_sdp:
            body = self._early_sdp  # the same SDP as in 18x
        else:
            body = self.answer(req.body) if sdplib.has_sdp(req) else self.offer()
        self.reply(req, 200, "OK", to_tag=self.tag, body=body)
