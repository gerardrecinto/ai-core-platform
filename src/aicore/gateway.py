"""The request pipeline: identity, data-class ceiling, DLP, rate limit, budget, route with fallback, then audit and trace.
Prompts are never stored. The audit trail keeps a short hash of the prompt instead."""
import hashlib
import time
import uuid

from . import policy
from .jwtlite import JwtError, verify_token
from .observe import Audit, Metrics, Tracer
from .quota import Budgets, TokenBucket
from .router import NoRoute, Router, tokens


class Gateway:
    def __init__(self, jwks, issuer, audience, providers, budgets, per_minute=30, burst=5):
        self.jwks, self.issuer, self.audience = jwks, issuer, audience
        self.router, self.budgets = Router(providers), Budgets(budgets)
        self.buckets, self.per_minute, self.burst = {}, per_minute, burst
        self.audit, self.tracer, self.metrics = Audit(), Tracer(), Metrics()

    def _deny(self, status, reason, actor, trace, now):
        self.metrics.inc("aicore_requests_total", status=status)
        self.audit.record(actor, f"deny.{reason}", trace[:12], ts=now)
        return {"status": status, "error": reason, "trace_id": trace}

    def identity(self, token, now):
        c = verify_token(token, self.jwks, self.issuer, self.audience, now)
        return {"sub": c["sub"], "roles": c.get("roles", []), "team": c.get("team", "")}

    def chat(self, token, prompt, classification="internal", now=None):
        now = time.time() if now is None else now
        trace, t0 = uuid.uuid4().hex, time.perf_counter()
        with self.tracer.span("gateway.chat", trace) as root:
            try:
                who = self.identity(token, now)
            except JwtError as e:
                return self._deny(401, f"auth_{e}", "anonymous", trace, now)
            root["attributes"].update(user=who["sub"], team=who["team"], data_class=classification)
            if classification not in policy.CLASSES:
                return self._deny(400, "bad_class", who["sub"], trace, now)
            cap = policy.ceiling(who["roles"])
            if cap is None or policy.rank(classification) > policy.rank(cap):
                return self._deny(403, "class_above_role", who["sub"], trace, now)
            clean, findings, blocked = policy.scan(prompt)
            if blocked:
                return self._deny(422, "dlp_block", who["sub"], trace, now)
            b = self.buckets.setdefault(who["sub"], TokenBucket(self.per_minute, self.burst))
            if not b.take(now):
                return self._deny(429, "rate_limited", who["sub"], trace, now)
            state = self.budgets.check(who["team"])
            if state == "deny":
                return self._deny(402, "budget_exhausted", who["sub"], trace, now)
            try:
                with self.tracer.span("router.route", trace, parent=root["spanId"]) as rs:
                    p, text, tried = self.router.route(clean, classification, now)
                    rs["attributes"]["tried"] = tried
            except NoRoute:
                return self._deny(503, "no_route", who["sub"], trace, now)
            tin, tout = tokens(clean), tokens(text)
            cost = tin / 1000 * p.in_per_1k + tout / 1000 * p.out_per_1k
            self.budgets.add(who["team"], cost)
            warnings = (["budget_80_percent"] if state == "warn" else []) + [f"redacted_{f}" for f in findings]
            self.metrics.inc("aicore_requests_total", status=200)
            self.metrics.add("aicore_tokens_total", tin + tout, provider=p.name)
            self.metrics.add("aicore_cost_usd_total", round(cost, 6), team=who["team"])
            self.metrics.observe(time.perf_counter() - t0)
            self.audit.record(who["sub"], "chat.ok", f"{p.name}:{hashlib.sha256(prompt.encode()).hexdigest()[:12]}", ts=now)
            return {"status": 200, "provider": p.name, "text": text, "tokens": tin + tout, "cost_usd": round(cost, 6),
                    "warnings": warnings, "tried": tried, "trace_id": trace}
