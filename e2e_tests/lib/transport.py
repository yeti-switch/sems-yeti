"""
SIP transports for e2e test agents: UDP, TCP, TLS, WS, WSS (python stdlib only).

common interface:
  local            (ip, port) of the transport (listening port for stream transports)
  name             Via transport token: UDP, TCP, TLS, WS, WSS
  send(data, dst)  sends SIP message to dst (ip, port). stream transports reuse the connection
                   with the peer address dst or open the new one
  on_message       callback(raw bytes, peer (ip, port), conn) for every received SIP message
  connections      log of all stream connections (Connection objects)
  close_connection(peer) / close()

stream transports (TCP/TLS/WS/WSS) accept incoming connections on the listening socket and
open outgoing ones on demand, so an agent can be both client and server like a SIP endpoint.
SIP messages are framed by Content-Length (TCP/TLS) or by WebSocket messages (RFC 7118)
"""

import base64
import hashlib
import os
import select
import socket
import ssl
import struct
import threading
import time

CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "etc", "certs")
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

TRANSPORT_IDS = {"UDP": 1, "TCP": 2, "TLS": 3, "WS": 5, "WSS": 6}  # sip_transport::sip_transport_id


def cert_path(name):
    return os.path.join(CERTS_DIR, name)


def client_tls_context(client_cert=False):
    """verifies peer certificate by the test CA, optionally presents the client certificate"""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cert_path("ca.pem"))
    if client_cert:
        ctx.load_cert_chain(cert_path("client.pem"), cert_path("client.key"))
    return ctx


def server_tls_context():
    """gateway certificate, client certificate is requested but optional"""
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=cert_path("ca.pem"))
    ctx.load_cert_chain(cert_path("gw.pem"), cert_path("gw.key"))
    ctx.verify_mode = ssl.CERT_OPTIONAL
    return ctx


class UdpTransport:
    name = "UDP"

    def __init__(self, ip="127.0.0.1", port=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))
        self.sock.settimeout(0.1)
        self.local = self.sock.getsockname()
        self.on_message = None
        self.connections = []
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while self._running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if self.on_message and data.strip():
                self.on_message(data, addr, None)

    def send(self, data, dst):
        self.sock.sendto(data, dst)

    def close_connection(self, peer):
        pass

    def close(self):
        self._running = False
        self._thread.join()
        self.sock.close()


class Connection:
    """stream connection with the peer. direction: 'in' (accepted) or 'out' (connected)"""

    _ids = iter(range(1, 1 << 31))

    def __init__(self, sock, peer, direction):
        self.id = next(Connection._ids)
        self.sock = sock
        self.peer = peer
        self.local = sock.getsockname()
        self.direction = direction
        self.opened = time.monotonic()
        self.closed = None  # monotonic time of close
        self.closed_by_peer = False
        self.tls_version = sock.version() if isinstance(sock, ssl.SSLSocket) else None
        self.peer_cert = None
        self.lock = threading.Lock()
        self.buf = b""

    def __repr__(self):
        return f"<Connection {self.id} {self.direction} {self.local}->{self.peer}{' closed' if self.closed else ''}>"


class StreamTransport:
    """TCP and TLS. SIP messages framed by Content-Length, CRLF keep-alives are skipped"""

    name = "TCP"

    def __init__(self, ip="127.0.0.1", port=0, tls_client_ctx=None, tls_server_ctx=None, connect_timeout=3):
        self.ip = ip
        self.tls_client_ctx = tls_client_ctx
        self.tls_server_ctx = tls_server_ctx
        self.connect_timeout = connect_timeout
        self.on_message = None
        self.connections = []
        self._conns = {}  # peer -> Connection (open ones)
        self._lock = threading.Lock()
        self._running = True

        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((ip, port))
        self.listener.listen(16)
        self.listener.settimeout(0.1)
        self.local = self.listener.getsockname()
        self._threads = [threading.Thread(target=self._accept_loop, daemon=True)]
        self._threads[0].start()

    # connections

    def _accept_loop(self):
        while self._running:
            try:
                sock, peer = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                sock = self._wrap_server(sock)
                conn = Connection(sock, peer, "in")
                if isinstance(sock, ssl.SSLSocket):
                    conn.peer_cert = sock.getpeercert()
                self._server_handshake(conn)
            except (OSError, ssl.SSLError, ValueError):
                sock.close()
                continue
            self._add(conn)

    def _wrap_server(self, sock):
        if self.tls_server_ctx:
            sock.settimeout(self.connect_timeout)
            return self.tls_server_ctx.wrap_socket(sock, server_side=True)
        return sock

    def _server_handshake(self, conn):
        pass

    def _client_handshake(self, conn, dst):
        pass

    def connect(self, dst):
        """opens the new connection to dst"""
        sock = socket.create_connection(dst, timeout=self.connect_timeout, source_address=(self.ip, 0))
        if self.tls_client_ctx:
            sock = self.tls_client_ctx.wrap_socket(sock, server_hostname=dst[0])
        conn = Connection(sock, dst, "out")
        self._client_handshake(conn, dst)
        self._add(conn)
        return conn

    def _add(self, conn):
        conn.sock.settimeout(0.1)
        with self._lock:
            self.connections.append(conn)
            self._conns[conn.peer] = conn
        t = threading.Thread(target=self._read_loop, args=(conn,), daemon=True)
        self._threads.append(t)
        t.start()

    def connection(self, peer):
        with self._lock:
            return self._conns.get(tuple(peer))

    def open_connections(self):
        with self._lock:
            return list(self._conns.values())

    def _on_closed(self, conn, by_peer):
        with self._lock:
            if conn.closed is None:
                conn.closed = time.monotonic()
                conn.closed_by_peer = by_peer
            if self._conns.get(conn.peer) is conn:
                del self._conns[conn.peer]

    def close_connection(self, peer):
        conn = self.connection(peer)
        if conn:
            self._close_conn(conn)

    def _close_conn(self, conn):
        try:
            conn.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.sock.close()
        self._on_closed(conn, by_peer=False)

    # data

    def _recv(self, conn):
        """TLS: SSL object is not safe for concurrent read and write, so recv is done under the
        connection lock (shared with writes) after waiting for readability outside of it"""
        if not isinstance(conn.sock, ssl.SSLSocket):
            return conn.sock.recv(65536)
        if not conn.sock.pending() and not select.select([conn.sock], [], [], 0.1)[0]:
            raise socket.timeout()
        with conn.lock:
            return conn.sock.recv(65536)

    def _read_loop(self, conn):
        while self._running and conn.closed is None:
            try:
                data = self._recv(conn)
            except (socket.timeout, ssl.SSLWantReadError):
                continue
            except (OSError, ssl.SSLError):
                self._on_closed(conn, by_peer=True)
                break
            if not data:
                self._on_closed(conn, by_peer=True)
                break
            for msg in self._feed(conn, data):
                if self.on_message:
                    self.on_message(msg, conn.peer, conn)

    def _feed(self, conn, data):
        """splits the stream into SIP messages by Content-Length"""
        conn.buf += data
        out = []
        while True:
            conn.buf = conn.buf.lstrip(b"\r\n")  # keep-alive CRLFs
            end = conn.buf.find(b"\r\n\r\n")
            if end < 0:
                break
            head = conn.buf[:end].decode(errors="replace")
            length = 0
            for line in head.split("\r\n")[1:]:
                name, _, value = line.partition(":")
                if name.strip().lower() in ("content-length", "l"):
                    length = int(value.strip() or 0)
            total = end + 4 + length
            if len(conn.buf) < total:
                break
            out.append(conn.buf[:total])
            conn.buf = conn.buf[total:]
        return out

    def _write(self, conn, data):
        with conn.lock:
            conn.sock.sendall(data)

    def send(self, data, dst, new_connection=False):
        dst = tuple(dst)
        conn = None if new_connection else self.connection(dst)
        if conn is None:
            conn = self.connect(dst)
        self._write(conn, data)
        return conn

    def close(self):
        self._running = False
        for conn in self.open_connections():
            self._close_conn(conn)
        self.listener.close()
        for t in self._threads:
            t.join(1)


class TcpTransport(StreamTransport):
    name = "TCP"


class TlsTransport(StreamTransport):
    name = "TLS"

    def __init__(self, ip="127.0.0.1", port=0, client_cert=False, tls_client_ctx=None, tls_server_ctx=None, **kw):
        super().__init__(ip, port,
                         tls_client_ctx=tls_client_ctx or client_tls_context(client_cert),
                         tls_server_ctx=tls_server_ctx or server_tls_context(), **kw)


class WebSocketError(Exception):
    pass


def ws_accept_key(key):
    return base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()


def ws_frame(payload, opcode=0x1, mask=True):
    """single FIN frame. client frames must be masked (RFC 6455 5.1)"""
    head = bytes([0x80 | opcode])
    n = len(payload)
    mask_bit = 0x80 if mask else 0
    if n < 126:
        head += bytes([mask_bit | n])
    elif n < 65536:
        head += bytes([mask_bit | 126]) + struct.pack("!H", n)
    else:
        head += bytes([mask_bit | 127]) + struct.pack("!Q", n)
    if not mask:
        return head + payload
    key = os.urandom(4)
    return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def ws_parse_frame(buf):
    """returns (fin, opcode, payload, consumed) or None if the frame is incomplete"""
    if len(buf) < 2:
        return None
    fin, opcode = buf[0] & 0x80, buf[0] & 0x0F
    masked, n = buf[1] & 0x80, buf[1] & 0x7F
    pos = 2
    if n == 126:
        if len(buf) < 4:
            return None
        n, pos = struct.unpack("!H", buf[2:4])[0], 4
    elif n == 127:
        if len(buf) < 10:
            return None
        n, pos = struct.unpack("!Q", buf[2:10])[0], 10
    key = b""
    if masked:
        if len(buf) < pos + 4:
            return None
        key, pos = buf[pos:pos + 4], pos + 4
    if len(buf) < pos + n:
        return None
    payload = buf[pos:pos + n]
    if masked:
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return bool(fin), opcode, payload, pos + n


class WsTransport(StreamTransport):
    """
    SIP over WebSocket (RFC 7118). client connections send HTTP Upgrade with Sec-WebSocket-Protocol: sip
    and masked frames, accepted connections answer the Upgrade and send unmasked frames.
    ws_protocols: protocols offered by the client handshake (None: no Sec-WebSocket-Protocol header)
    ws_reply_version: add Sec-WebSocket-Version to the server 101 reply. not required by RFC 6455 4.2.2,
    but SEMS WS client rejects 101 without it ('missing sec_websocket_version header field')
    """

    name = "WS"
    secure = False

    def __init__(self, ip="127.0.0.1", port=0, ws_protocols=("sip",), ws_path="/", ws_reply_version=True, **kw):
        self.ws_protocols = ws_protocols
        self.ws_reply_version = ws_reply_version
        self.ws_path = ws_path
        self.handshake_replies = []  # status lines of client handshakes
        super().__init__(ip, port, **kw)

    @staticmethod
    def _read_http(conn, timeout=3):
        deadline = time.monotonic() + timeout
        while b"\r\n\r\n" not in conn.buf:
            if time.monotonic() > deadline:
                raise WebSocketError("no HTTP handshake")
            try:
                data = conn.sock.recv(4096)
            except (socket.timeout, ssl.SSLWantReadError):
                continue
            if not data:
                raise WebSocketError("connection closed during handshake")
            conn.buf += data
        head, _, conn.buf = conn.buf.partition(b"\r\n\r\n")
        lines = head.decode(errors="replace").split("\r\n")
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        return lines[0], headers

    def _client_handshake(self, conn, dst):
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [
            f"GET {self.ws_path} HTTP/1.1",
            f"Host: {dst[0]}:{dst[1]}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        if self.ws_protocols:
            lines.append(f"Sec-WebSocket-Protocol: {', '.join(self.ws_protocols)}")
        conn.sock.settimeout(0.1)
        conn.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        status, headers = self._read_http(conn)
        self.handshake_replies.append(status)
        if " 101 " not in status + " ":
            raise WebSocketError(f"handshake rejected: {status}")
        if headers.get("sec-websocket-accept") != ws_accept_key(key):
            raise WebSocketError("wrong Sec-WebSocket-Accept")
        conn.ws_protocol = headers.get("sec-websocket-protocol")
        conn.ws_client = True
        conn.ws_frags = b""

    def _server_handshake(self, conn):
        conn.sock.settimeout(0.1)
        _, headers = self._read_http(conn)
        protocols = [p.strip() for p in headers.get("sec-websocket-protocol", "").split(",") if p.strip()]
        lines = [
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Accept: {ws_accept_key(headers.get('sec-websocket-key', ''))}",
        ]
        if "sip" in protocols:
            lines.append("Sec-WebSocket-Protocol: sip")
        if self.ws_reply_version:
            lines.append("Sec-WebSocket-Version: 13")
        conn.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        conn.ws_protocol = "sip" if "sip" in protocols else None
        conn.ws_client = False
        conn.ws_frags = b""
        conn.ws_request_headers = headers

    def _feed(self, conn, data):
        conn.buf += data
        out = []
        while True:
            parsed = ws_parse_frame(conn.buf)
            if parsed is None:
                break
            fin, opcode, payload, consumed = parsed
            conn.buf = conn.buf[consumed:]
            if opcode in (0x0, 0x1, 0x2):
                conn.ws_frags += payload
                if fin:
                    if conn.ws_frags.strip():
                        out.append(conn.ws_frags)
                    conn.ws_frags = b""
            elif opcode == 0x8:  # close
                try:
                    self._write_frame(conn, payload[:2], 0x8)
                except OSError:
                    pass
                self._close_conn(conn)
                conn.closed_by_peer = True
                break
            elif opcode == 0x9:  # ping
                self._write_frame(conn, payload, 0xA)
        return out

    def _write_frame(self, conn, payload, opcode=0x1):
        with conn.lock:
            conn.sock.sendall(ws_frame(payload, opcode, mask=conn.ws_client))

    def _write(self, conn, data):
        self._write_frame(conn, data)

    def ping(self, peer, payload=b"e2e"):
        self._write_frame(self.connection(peer), payload, 0x9)


class WssTransport(WsTransport):
    name = "WSS"
    secure = True

    def __init__(self, ip="127.0.0.1", port=0, client_cert=False, tls_client_ctx=None, tls_server_ctx=None, **kw):
        super().__init__(ip, port,
                         tls_client_ctx=tls_client_ctx or client_tls_context(client_cert),
                         tls_server_ctx=tls_server_ctx or server_tls_context(), **kw)


TRANSPORTS = {"udp": UdpTransport, "tcp": TcpTransport, "tls": TlsTransport, "ws": WsTransport, "wss": WssTransport}


def make_transport(name, **kw):
    return TRANSPORTS[name.lower()](**kw)
