"""Minimal client for SEMS jsonrpc module (JSON-RPC 2.0 over netstrings)."""

import json
import socket
import uuid


class JsonRpcError(Exception):
    pass


class JsonRpc:
    def __init__(self, host="127.0.0.1", port=7080, timeout=5):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""

    def close(self):
        self.sock.close()

    def call(self, method, params=None):
        req_id = str(uuid.uuid4())
        data = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method,
                           "params": params if params is not None else []}).encode()
        self.sock.sendall(str(len(data)).encode() + b":" + data + b",")

        while True:
            reply = self._read_netstring()
            if reply.get("id") != req_id:
                continue  # skip notifications and unrelated replies
            if "error" in reply:
                raise JsonRpcError(f"{method}: {reply['error']}")
            return reply.get("result")

    def _recv(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise JsonRpcError("connection closed")
        self.buf += chunk

    def _read_netstring(self):
        while b":" not in self.buf:
            self._recv()
        colon = self.buf.index(b":")
        length = int(self.buf[:colon])
        end = colon + 1 + length
        while len(self.buf) < end + 1:
            self._recv()
        if self.buf[end:end + 1] != b",":
            raise JsonRpcError("malformed netstring")
        payload, self.buf = self.buf[colon + 1:end], self.buf[end + 1:]
        return json.loads(payload)
