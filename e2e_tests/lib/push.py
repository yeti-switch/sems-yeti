"""
HTTP server receiving push notifications sent by yeti through http_client destinations
(fcm, apns, apns_sandbox, webhook in etc/sems.conf). emulates push provider + mobile device:
records notifications, replies with configured code and calls on_push callback
(e.g. to register the device) after the reply
"""

import http.server
import json
import threading
import time


class PushRequest:
    def __init__(self, path, body):
        self.path = path
        self.raw = body
        self.time = time.monotonic()
        try:
            self.json = json.loads(body)
        except ValueError:
            self.json = None

    def __repr__(self):
        return f"<PushRequest {self.path} {self.raw}>"


class PushServer:
    def __init__(self, host="127.0.0.1", port=8098):
        self.requests = []
        self.reply_code = 200
        self.on_push = None  # callable(PushRequest), called in separate thread after the reply
        self._cond = threading.Condition()

        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length", 0))).decode(errors="replace")
                req = PushRequest(self.path, body)
                with server._cond:
                    server.requests.append(req)
                    server._cond.notify_all()
                self.send_response(server.reply_code)
                self.send_header("Content-Length", "0")
                self.end_headers()
                if server.on_push:
                    threading.Thread(target=server.on_push, args=(req,), daemon=True).start()

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer((host, port), Handler)
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def reset(self):
        with self._cond:
            self.requests = []
        self.reply_code = 200
        self.on_push = None

    def wait(self, timeout=5):
        with self._cond:
            self._cond.wait_for(lambda: self.requests, timeout)
            return self.requests[0] if self.requests else None

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
