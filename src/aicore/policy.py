"""Role ceilings, provider ceilings and prompt DLP. A request is allowed only where both ceilings cover its data class."""
import re

CLASSES = ["public", "internal", "confidential"]
ROLE_CEILING = {"intern": "internal", "contractor": "internal", "engineer": "confidential", "ai-admin": "confidential"}
PROVIDER_CEILING = {"commercial": "internal", "bedrock": "confidential", "selfhosted": "confidential"}

BLOCK = [("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"))]
REDACT = [
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret_assign", re.compile(r"(?i)\b(password|passwd|api[_-]?key|secret|token)\s*[=:]\s*\S+")),
]


def rank(c):
    return CLASSES.index(c)


def ceiling(roles):
    known = [ROLE_CEILING[r] for r in roles if r in ROLE_CEILING]
    return max(known, key=rank) if known else None


def scan(text):
    """Return (clean_text, finding names, blocked). Blocking beats redaction."""
    found = [n for n, rx in BLOCK if rx.search(text)]
    if found:
        return text, found, True
    for n, rx in REDACT:
        if rx.search(text):
            found.append(n)
            text = rx.sub(f"[{n.upper()}]", text)
    return text, found, False
