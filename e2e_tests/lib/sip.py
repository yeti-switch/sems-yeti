"""Minimal SIP UAC for black-box tests: sends one request, returns the final reply."""

import re
import socket
import time
import uuid

SIP_HOST = "127.0.0.1"


class SipReply:
    def __init__(self, raw):
        self.raw = raw
        status_line = raw.split("\r\n", 1)[0]
        _, code, reason = (status_line.split(" ", 2) + [""])[:3]
        self.code = int(code)
        self.reason = reason

    def header(self, name):
        m = re.search(rf"^{re.escape(name)}\s*:\s*(.*)$", self.raw, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else None

    def __repr__(self):
        return f"<SipReply {self.code} {self.reason}>"


class SipClient:
    """
    transport: 'udp' or 'tcp'
    local_ip:  source address. any 127.0.0.0/8 address can be bound on Linux loopback
    """

    def __init__(self, transport="udp", local_ip="127.0.0.1"):
        self.transport = transport
        self.local_ip = local_ip

    def _build(self, method, port, lport, call_id, branch, from_tag, to_tag, cseq_method=None):
        to = f"<sip:test@{SIP_HOST}:{port}>" + (f";tag={to_tag}" if to_tag else "")
        lines = [
            f"{method} sip:test@{SIP_HOST}:{port} SIP/2.0",
            f"Via: SIP/2.0/{self.transport.upper()} {self.local_ip}:{lport};branch=z9hG4bK{branch};rport",
            "Max-Forwards: 70",
            f"From: <sip:e2e@{self.local_ip}>;tag={from_tag}",
            f"To: {to}",
            f"Call-ID: {call_id}",
            f"CSeq: 1 {cseq_method or method}",
            f"Contact: <sip:e2e@{self.local_ip}:{lport};transport={self.transport}>",
        ]
        if method == "REGISTER":
            lines.append("Expires: 60")
        lines.append("Content-Length: 0")
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    def request(self, method, port, to_tag=None, timeout=3.0):
        """send out-of-dialog request (or in-dialog one if to_tag is set).
        returns final SipReply or None if nothing was received within timeout"""
        call_id = uuid.uuid4().hex
        branch = uuid.uuid4().hex[:16]
        from_tag = uuid.uuid4().hex[:8]

        if self.transport == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((self.local_ip, 0))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.local_ip, 0))
            sock.settimeout(timeout)
            sock.connect((SIP_HOST, port))
        lport = sock.getsockname()[1]

        try:
            msg = self._build(method, port, lport, call_id, branch, from_tag, to_tag)
            if self.transport == "udp":
                sock.sendto(msg, (SIP_HOST, port))
            else:
                sock.sendall(msg)

            reply = self._wait_final(sock, timeout)

            if reply and method == "INVITE" and reply.code >= 300:
                # ACK non-2xx final reply to stop retransmissions
                ack_to_tag = re.search(r";tag=([^;>\s]+)", reply.header("To") or "")
                ack = self._build("ACK", port, lport, call_id, branch, from_tag,
                                  ack_to_tag.group(1) if ack_to_tag else None, cseq_method="ACK")
                if self.transport == "udp":
                    sock.sendto(ack, (SIP_HOST, port))
                else:
                    sock.sendall(ack)
            return reply
        finally:
            sock.close()

    def _wait_final(self, sock, timeout):
        deadline = time.monotonic() + timeout
        buf = b""
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            sock.settimeout(left)
            try:
                data = sock.recv(65535)
            except (socket.timeout, ConnectionResetError):
                return None
            if not data:
                # TCP connection closed by peer
                return None
            buf += data
            for raw in self._split(buf):
                reply = SipReply(raw)
                if reply.code >= 200:
                    return reply
            if self.transport == "udp":
                buf = b""

    def _split(self, buf):
        """split stream into complete messages (bodies are ignored, replies have none here)"""
        text = buf.decode(errors="replace")
        return [m + "\r\n\r\n" for m in text.split("\r\n\r\n") if m.startswith("SIP/2.0 ")]
