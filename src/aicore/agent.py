"""On-prem agent HTTP shell around OnPremAgent. POST /jobs takes a signed ticket, GET /jobs/<id> returns state.
Users come from the host's account database, and only uid 1000 and up are accepted. Job execution is simulated."""
import json
import os
import pwd
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .hybrid import OnPremAgent, TicketError


def make_handler(agent, now):
    lock = threading.Lock()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.path != "/jobs":
                return self._send(404, {"error": "not found"})
            ticket = self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 4096)).decode()
            try:
                with lock:
                    self._send(202, {"job": agent.accept(ticket, now())})
            except (TicketError, ValueError, KeyError) as e:
                self._send(403, {"error": str(e)})

        def do_GET(self):
            jid = self.path.removeprefix("/jobs/")
            with lock:
                j = agent.jobs.get(jid)
            self._send(200, j) if j else self._send(404, {"error": "not found"})

    return H


def main():
    import time
    secret = open(os.environ.get("TICKET_KEY", "/opt/aicore-agent/ticket.key"), "rb").read().strip()
    users = {p.pw_name: p.pw_uid for p in pwd.getpwall() if p.pw_uid >= 1000}
    agent = OnPremAgent(secret, users)
    stop = threading.Event()

    def loop():
        while not stop.wait(1):
            agent.tick()
    threading.Thread(target=loop, daemon=True).start()
    ThreadingHTTPServer((os.environ.get("HOST", "0.0.0.0"), int(os.environ.get("PORT", "9090"))), make_handler(agent, time.time)).serve_forever()


if __name__ == "__main__":
    main()
