"""HTTP surface: POST /v1/chat with a Bearer token, GET /metrics, GET /healthz."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock

MAX_BODY = 65536


def make_handler(gw):
    lock = Lock()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # request lines can carry identifiers
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/healthz":
                return self._send(200, {"ok": True})
            if self.path == "/metrics":
                with lock:
                    return self._send(200, gw.metrics.render().encode(), "text/plain; version=0.0.4")
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/v1/chat":
                return self._send(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._send(413, {"error": "too large"})
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
                prompt = body["prompt"]
                assert isinstance(prompt, str)
            except Exception:
                return self._send(400, {"error": "body needs a string prompt"})
            tok = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
            with lock:
                r = gw.chat(tok, prompt, body.get("data_class", "internal"))
            self._send(r["status"], r)

    return H


def serve(gw, port=8080):
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(gw))
