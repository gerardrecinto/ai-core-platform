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


def serve(gw, port=8080, host="127.0.0.1"):
    return ThreadingHTTPServer((host, port), make_handler(gw))


def main():
    """Lab server: fresh keys, mock providers, one printed token. Real deployments verify tokens from the identity provider."""
    import os
    import time
    from .gateway import Gateway
    from .jwtlite import gen_rsa, sign_token
    from .router import Provider
    key = gen_rsa(1024)
    iss, aud = "https://login.example.test/tenant/v2.0", "api://ai-core"
    gw = Gateway({"k1": key[:2]}, iss, aud, [Provider("commercial-api", "commercial", 0.5, 1.5),
                 Provider("bedrock-claude", "bedrock", 0.8, 2.4), Provider("vllm-onprem", "selfhosted", 0.1, 0.1)], {"fw": 5.0})
    tok = sign_token(key, "k1", {"iss": iss, "aud": aud, "sub": "alice", "roles": ["engineer"], "team": "fw", "exp": time.time() + 3600})
    port = int(os.environ.get("PORT", "8080"))
    print(f"listening on :{port}. Try:\ncurl -s localhost:{port}/v1/chat -H 'Authorization: Bearer {tok}' -d '{{\"prompt\":\"hello\",\"data_class\":\"public\"}}'", flush=True)
    serve(gw, port, os.environ.get("HOST", "127.0.0.1")).serve_forever()


if __name__ == "__main__":
    main()
