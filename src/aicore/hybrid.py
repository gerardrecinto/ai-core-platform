"""On-prem execution broker. The gateway signs a short ticket naming the requesting engineer and one allowlisted
command; the on-prem agent verifies it once, maps it to that engineer's own uid, and queues it behind license seats.
This is a simulation of the pattern: no VMware, LSF or real EDA tools are involved."""
import base64
import hashlib
import hmac
import json
import re
import uuid

ARG = re.compile(r"^[A-Za-z0-9_./-]{1,128}$")
ALLOW = {"eda-lint": None, "sim-run": "sim"}  # command -> license feature that needs a seat


class TicketError(Exception):
    pass


def issue_ticket(secret, sub, command, args, now, ttl=60):
    body = base64.urlsafe_b64encode(json.dumps(
        {"sub": sub, "cmd": command, "args": args, "aud": "onprem-agent", "exp": now + ttl, "jti": uuid.uuid4().hex}).encode()).decode()
    return body + "." + hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()


class OnPremAgent:
    def __init__(self, secret, users, seats=None):
        self.secret, self.users, self.seats = secret, users, dict(seats or {"sim": 1})
        self.seen, self.jobs, self.free = set(), {}, dict(self.seats)

    def accept(self, ticket, now):
        try:
            body, sig = ticket.rsplit(".", 1)
        except ValueError:
            raise TicketError("malformed") from None
        if not hmac.compare_digest(hmac.new(self.secret, body.encode(), hashlib.sha256).hexdigest(), sig):
            raise TicketError("signature")
        t = json.loads(base64.urlsafe_b64decode(body))
        if t["aud"] != "onprem-agent" or now > t["exp"]:
            raise TicketError("expired")
        if t["jti"] in self.seen:
            raise TicketError("replay")
        if t["cmd"] not in ALLOW or not all(ARG.match(a) for a in t["args"]):
            raise TicketError("command not allowed")
        uid = self.users.get(t["sub"])
        if uid is None or uid < 1000:
            raise TicketError("no personal account")  # never run as root or a shared service user
        self.seen.add(t["jti"])
        jid = uuid.uuid4().hex[:8]
        self.jobs[jid] = {"state": "PEND", "cmd": t["cmd"], "args": t["args"], "uid": uid, "sub": t["sub"]}
        return jid

    def tick(self):
        """Finish running jobs, free their seats, then start pending jobs in submit order."""
        for j in self.jobs.values():
            if j["state"] == "RUN":
                j["state"] = "DONE"
                j["out"] = f"ran {j['cmd']} as uid {j['uid']}"
                if ALLOW[j["cmd"]]:
                    self.free[ALLOW[j["cmd"]]] += 1
        for j in self.jobs.values():
            f = ALLOW[j["cmd"]]
            if j["state"] == "PEND" and (f is None or self.free[f] > 0):
                if f:
                    self.free[f] -= 1
                j["state"] = "RUN"
