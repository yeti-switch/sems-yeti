"""RTP endpoint for e2e SIP agents: sends packets and counts received ones by payload type"""

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
                data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) >= 12 and data[0] >> 6 == 2:
                with self._lock:
                    self.received[data[1] & 0x7f] += 1

    def send(self, pt, count=25, interval=0.02, payload_size=160):
        """send count packets with given payload type to self.remote"""
        assert self.remote, "remote RTP address is unknown"
        payload = bytes([0xff if pt == 0 else 0xd5]) * payload_size if pt in (0, 8) else bytes([0x40])
        for _ in range(count):
            self.seq = (self.seq + 1) & 0xffff
            self.ts = (self.ts + 160) & 0xffffffff
            header = struct.pack("!BBHII", 0x80, pt & 0x7f, self.seq, self.ts, self.ssrc)
            self.sock.sendto(header + payload, self.remote)
            time.sleep(interval)

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
