"""RTP endpoint for e2e SIP agents: sends packets and counts received ones by payload type.
SRTP: srtp_tx/srtp_rx (lib/srtp.py SrtpContext) protect sent packets and unprotect received ones"""

import collections
import random
import socket
import struct
import threading
import time


class RtpEndpoint:
    def __init__(self, ip="127.0.0.1"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, 0))
        self.sock.settimeout(0.1)
        self.ip, self.port = self.sock.getsockname()
        self.remote = None  # (ip, port) from the peer SDP

        self.ssrc = random.getrandbits(32)
        self.seq = random.getrandbits(16)
        self.ts = random.getrandbits(32)

        self._lock = threading.Lock()
        self.received = collections.Counter()  # payload type -> packets count
        self.packets = []  # (payload type, seq, timestamp, ssrc, source addr) of received packets
        self.srtp_tx = None  # SrtpContext to protect sent packets
        self.srtp_rx = None  # SrtpContext to unprotect received packets
        self.srtp_errors = 0  # received packets failed SRTP authentication
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        self._thread.join()
        self.sock.close()

    def _run(self):
        while self._running:
            try:
                data, src = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if self.srtp_rx is not None and len(data) >= 12 and data[1] & 0x7f not in range(72, 77):
                data = self.srtp_rx.unprotect(data)
                if data is None:
                    with self._lock:
                        self.srtp_errors += 1
                    continue
            if len(data) >= 12 and data[0] >> 6 == 2:
                pt = data[1] & 0x7f
                seq, ts, ssrc = struct.unpack("!HII", data[2:12])
                with self._lock:
                    self.received[pt] += 1
                    if len(self.packets) < 10000:
                        self.packets.append((pt, seq, ts, ssrc, src))

    def send(self, pt, count=25, interval=0.02, payload_size=160):
        """send count packets with given payload type to self.remote"""
        assert self.remote, "remote RTP address is unknown"
        payload = bytes([0xff if pt == 0 else 0xd5]) * payload_size if pt in (0, 8) else bytes([0x40])
        for _ in range(count):
            self.seq = (self.seq + 1) & 0xffff
            self.ts = (self.ts + 160) & 0xffffffff
            header = struct.pack("!BBHII", 0x80, pt & 0x7f, self.seq, self.ts, self.ssrc)
            self.send_raw(self._protect(header + payload))
            time.sleep(interval)

    def send_packet(self, pt, payload, seq=None, ts=None, ts_step=160):
        """send one packet with the payload to self.remote. the next seq/ts (ts advanced by ts_step)
        are used unless seq/ts are given (e.g. to repeat an already sent packet). returns (seq, ts)"""
        assert self.remote, "remote RTP address is unknown"
        if seq is None:
            self.seq = (self.seq + 1) & 0xffff
            self.ts = (self.ts + ts_step) & 0xffffffff
            seq, ts = self.seq, self.ts
        header = struct.pack("!BBHII", 0x80, pt & 0x7f, seq, ts, self.ssrc)
        self.send_raw(self._protect(header + payload))
        return seq, ts

    def _protect(self, packet):
        return self.srtp_tx.protect(packet) if self.srtp_tx is not None else packet

    def send_raw(self, data):
        """send the datagram as is (not protected by srtp_tx)"""
        assert self.remote, "remote RTP address is unknown"
        self.sock.sendto(data, self.remote)

    def timestamp_steps(self, pt):
        """RTP timestamp increments between consecutive received packets of the payload type"""
        with self._lock:
            ts = [p[2] for p in self.packets if p[0] == pt]
        return [(b - a) & 0xffffffff for a, b in zip(ts, ts[1:])]

    def count(self, pt=None):
        with self._lock:
            return sum(self.received.values()) if pt is None else self.received[pt]

    def wait(self, pt=None, packets=1, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.count(pt) >= packets:
                return True
            time.sleep(0.05)
        return self.count(pt) >= packets
