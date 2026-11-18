import json
import threading
import urllib.request

import pytest

from aicore import policy
from aicore.demo import AUD, ISS, NOW, build
from aicore.jwtlite import JwtError, b64u, gen_rsa, sign_token, verify_token
from aicore.quota import Budgets, TokenBucket
from aicore.router import Breaker, NoRoute, Provider, Router
from aicore.server import serve


@pytest.fixture(scope="module")
def key():
    return gen_rsa(1024)


def claims(**o):
    return {"iss": ISS, "aud": AUD, "sub": "a", "exp": NOW + 60, **o}


def test_valid_token_and_each_rejection(key):
    jwks = {"k": key[:2]}
    assert verify_token(sign_token(key, "k", claims()), jwks, ISS, AUD, NOW)["sub"] == "a"
    bad = {"iss": claims(iss="x"), "aud": claims(aud="y"), "expired": claims(exp=NOW - 999), "nbf": claims(nbf=NOW + 999)}
    for name, c in bad.items():
        with pytest.raises(JwtError):
            verify_token(sign_token(key, "k", c), jwks, ISS, AUD, NOW)


def test_signature_tamper_wrong_kid_and_alg_none(key):
    jwks = {"k": key[:2]}
    t = sign_token(key, "k", claims())
    h, p, s = t.split(".")
    forged = f"{h}.{b64u(json.dumps(claims(sub='root')).encode())}.{s}"
    for tok in (forged, sign_token(key, "other", claims())):
        with pytest.raises(JwtError):
            verify_token(tok, jwks, ISS, AUD, NOW)
    none = f"{b64u(json.dumps({'alg': 'none'}).encode())}.{h}.".replace(f".{h}.", f".{p}.")
    with pytest.raises(JwtError):
        verify_token(none, jwks, ISS, AUD, NOW)
    with pytest.raises(JwtError):
        verify_token("garbage", jwks, ISS, AUD, NOW)


def test_dlp_redacts_and_blocks():
    t, f, b = policy.scan("key AKIAABCDEFGHIJKLMNOP and password=hunter2")
    assert not b and "AKIA" not in t and "hunter2" not in t and len(f) == 2
    assert policy.scan("-----BEGIN PRIVATE KEY-----")[2]


def test_ceilings():
    assert policy.ceiling(["intern"]) == "internal" and policy.ceiling(["intern", "engineer"]) == "confidential"
    assert policy.ceiling(["guest"]) is None


def test_confidential_never_reaches_commercial():
    gw, tok = build()
    for p in gw.router.providers:
        if p.kind == "selfhosted":
            p.fail = True
    r = gw.chat(tok("a", ["engineer"], "fw"), "x", "confidential", NOW)
    assert r["provider"] == "bedrock-claude"
    for p in gw.router.providers:
        if p.kind == "bedrock":
            p.fail = True
    r = gw.chat(tok("a", ["engineer"], "fw"), "x", "confidential", NOW + 100)
    assert r["status"] == 503  # commercial is above the provider ceiling, so no route


def test_breaker_opens_and_recovers():
    b = Breaker()
    for _ in range(3):
        b.fail(0)
    assert not b.allow(10) and b.allow(31)
    b.ok()
    assert b.allow(32)


def test_router_skips_open_breaker_and_reports_no_route():
    p = Provider("p", "bedrock", 1, 1, fail=True)
    r = Router([p])
    for t in range(3):
        with pytest.raises(NoRoute):
            r.route("x", "internal", t)
    with pytest.raises(NoRoute) as e:
        r.route("x", "internal", 5)
    assert e.value.args[0] == [("p", "circuit_open")]


def test_rate_limit_and_refill():
    b = TokenBucket(60, 2)
    assert [b.take(0), b.take(0), b.take(0)] == [True, True, False]
    assert b.take(2)


def test_budget_states():
    b = Budgets({"t": 10})
    assert b.check("t") == "ok"
    b.add("t", 8)
    assert b.check("t") == "warn"
    b.add("t", 2)
    assert b.check("t") == "deny" and b.check("unknown") == "deny"


def test_budget_report():
    b = Budgets({"a": 10, "b": 4})
    b.add("a", 8.5)
    assert b.report() == [{"team": "a", "spent_usd": 8.5, "limit_usd": 10, "used_pct": 85.0, "state": "warn"},
                          {"team": "b", "spent_usd": 0.0, "limit_usd": 4, "used_pct": 0.0, "state": "ok"}]


def test_gateway_statuses_and_no_prompt_stored():
    gw, tok = build(burst=2)
    eng = tok("a", ["engineer"], "fw")
    assert gw.chat(eng, "hello", "public", NOW)["status"] == 200
    assert gw.chat(tok("b", ["intern"], "fw"), "x", "confidential", NOW)["status"] == 403
    assert gw.chat(eng, "x", "bogus", NOW)["status"] == 400
    assert gw.chat(eng, "-----BEGIN PRIVATE KEY-----", "public", NOW)["status"] == 422
    assert gw.chat("nope", "x", "public", NOW)["status"] == 401
    gw.chat(eng, "secret plan", "public", NOW)
    assert gw.chat(eng, "x", "public", NOW)["status"] == 429
    dump = " ".join(str(r) for r in gw.audit.db.execute("select * from audit"))
    assert "secret plan" not in dump


def test_trace_and_metrics_and_audit_tamper():
    gw, tok = build()
    r = gw.chat(tok("a", ["engineer"], "fw"), "hello", "public", NOW)
    spans = gw.tracer.for_trace(r["trace_id"])
    assert {s["name"] for s in spans} == {"gateway.chat", "router.route"}
    root = next(s for s in spans if s["name"] == "gateway.chat")
    assert all(s["parentSpanId"] in (None, root["spanId"]) for s in spans)
    m = gw.metrics.render()
    assert 'aicore_requests_total{status="200"} 1' in m and "aicore_request_seconds_count 1" in m
    assert gw.audit.verify() is None
    gw.audit.db.execute("update audit set actor='x' where seq=1")
    assert gw.audit.verify() == 1


def test_http_chat_and_metrics(key):
    import time
    from aicore.gateway import Gateway
    gw = Gateway({"k": key[:2]}, ISS, AUD, [Provider("p", "bedrock", 1, 1)], {"t": 5})
    srv = serve(gw, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    tok = sign_token(key, "k", claims(exp=time.time() + 60, roles=["engineer"], team="t"))

    def post(data, token):
        return urllib.request.Request(base + "/v1/chat", data=data, headers={"Authorization": "Bearer " + token})
    try:
        r = urllib.request.urlopen(post(b'{"prompt":"hi","data_class":"public"}', tok))
        assert r.status == 200 and json.loads(r.read())["provider"] == "p"
        for data, token, code in ((b'{"prompt":"hi"}', "bad", 401), (b"not json", tok, 400)):
            with pytest.raises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(post(data, token))
            assert e.value.code == code
        assert urllib.request.urlopen(base + "/healthz").status == 200
        assert b'aicore_requests_total{status="200"} 1' in urllib.request.urlopen(base + "/metrics").read()
    finally:
        srv.shutdown()
