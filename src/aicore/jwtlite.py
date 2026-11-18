"""OIDC-style JWT verification (RS256 only) plus a lab RSA keygen for tests.
Dependency-free on purpose. A production gateway should use a vetted library and a real JWKS endpoint."""
import base64
import hashlib
import hmac
import json
import secrets
import time

SHA256_DI = bytes.fromhex("3031300d060960864801650304020105000420")


class JwtError(Exception):
    pass


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _em(msg, k):
    t = SHA256_DI + hashlib.sha256(msg).digest()
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def rs256_verify(n, e, msg, sig):
    """Rebuild the expected padded block and compare, never parse the padding."""
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    return hmac.compare_digest(pow(s, e, n).to_bytes(k, "big"), _em(msg, k))


def rs256_sign(n, d, msg):
    k = (n.bit_length() + 7) // 8
    return pow(int.from_bytes(_em(msg, k), "big"), d, n).to_bytes(k, "big")


def _is_prime(n, rounds=24):
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_prime(c):
            return c


def gen_rsa(bits=1024):
    """Lab-size key. Returns (n, e, d)."""
    e = 65537
    while True:
        p, q = _prime(bits // 2), _prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            return p * q, e, pow(e, -1, phi)


def sign_token(key, kid, claims):
    h = b64u(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}).encode())
    p = b64u(json.dumps(claims).encode())
    return f"{h}.{p}.{b64u(rs256_sign(key[0], key[2], f'{h}.{p}'.encode()))}"


def verify_token(token, jwks, issuer, audience, now=None, leeway=30):
    """jwks maps kid -> (n, e). Rejects any alg other than RS256, so alg=none and HS256 confusion fail."""
    now = time.time() if now is None else now
    try:
        h, p, s = token.split(".")
        header, claims, sig = json.loads(b64d(h)), json.loads(b64d(p)), b64d(s)
    except Exception:
        raise JwtError("malformed") from None
    if header.get("alg") != "RS256":
        raise JwtError("alg")
    key = jwks.get(header.get("kid"))
    if not key:
        raise JwtError("kid")
    if not rs256_verify(key[0], key[1], f"{h}.{p}".encode(), sig):
        raise JwtError("signature")
    if claims.get("iss") != issuer:
        raise JwtError("iss")
    aud = claims.get("aud")
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise JwtError("aud")
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or now > exp + leeway:
        raise JwtError("expired")
    if now + leeway < claims.get("nbf", 0):
        raise JwtError("nbf")
    if not claims.get("sub"):
        raise JwtError("sub")
    return claims
