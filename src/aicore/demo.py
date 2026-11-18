"""Eight gateway decisions with synthetic identities and mock providers. Run: python -m aicore.demo"""
from .gateway import Gateway
from .jwtlite import gen_rsa, sign_token
from .router import Provider

ISS, AUD, NOW = "https://login.example.test/tenant/v2.0", "api://ai-core", 1_000_000.0


def build(**kw):
    key = gen_rsa(1024)
    providers = [Provider("commercial-api", "commercial", 0.50, 1.50), Provider("bedrock-claude", "bedrock", 0.80, 2.40),
                 Provider("vllm-onprem", "selfhosted", 0.10, 0.10)]
    gw = Gateway({"k1": key[:2]}, ISS, AUD, providers, {"rtl": 0.01, "fw": 5.0}, **kw)

    def tok(sub, roles, team):
        return sign_token(key, "k1", {"iss": ISS, "aud": AUD, "sub": sub, "roles": roles, "team": team, "exp": NOW + 3600})
    return gw, tok


def main():
    gw, tok = build()
    eng, intern = tok("alice", ["engineer"], "fw"), tok("bob", ["intern"], "fw")
    rows = [
        ("public question", gw.chat(eng, "Explain NFS attribute caching", "public", NOW)),
        ("confidential goes self-hosted", gw.chat(eng, "Review this clock tree netlist summary", "confidential", NOW)),
        ("intern asks confidential", gw.chat(intern, "Review this netlist", "confidential", NOW)),
        ("key in prompt is redacted", gw.chat(eng, "deploy with AKIAABCDEFGHIJKLMNOP now", "internal", NOW)),
        ("private key is blocked", gw.chat(eng, "-----BEGIN RSA PRIVATE KEY----- abc", "internal", NOW)),
        ("bad token", gw.chat(eng[:-4] + "AAAA", "hi", "public", NOW)),
    ]
    gw.router.providers[2].fail = True
    rows.append(("self-hosted down, falls back", gw.chat(eng, "Summarize this timing report", "confidential", NOW + 1)))
    rows.append(("team over budget", gw.chat(tok("carol", ["engineer"], "rtl"), "hello " * 200, "public", NOW + 2)))
    rows.append(("team stays blocked", gw.chat(tok("carol", ["engineer"], "rtl"), "hello", "public", NOW + 3)))
    for label, r in rows:
        print(f"{label:32} {r['status']}  {r.get('provider') or r.get('error')}  {r.get('warnings', '')}")
    print("audit chain intact:", gw.audit.verify() is None)


if __name__ == "__main__":
    main()
