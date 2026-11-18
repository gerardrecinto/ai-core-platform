"""Agent eval harness with a release gate, plus a small TF-IDF retriever with recall@k."""
import math
import re
from collections import Counter


def run_suite(agent, cases, threshold=0.9):
    """agent(prompt) -> {"tool": str or None, "text": str}. Each case is a dict."""
    results = []
    for c in cases:
        out = agent(c["prompt"])
        ok = (c.get("tool") is None or out.get("tool") == c["tool"]) \
            and all(s in out["text"] for s in c.get("contains", [])) \
            and not any(s in out["text"] for s in c.get("excludes", []))
        results.append((c["name"], ok))
    rate = sum(ok for _, ok in results) / len(results)
    return {"pass_rate": rate, "gate": rate >= threshold, "failed": [n for n, ok in results if not ok]}


def _tok(s):
    return re.findall(r"[a-z0-9]+", s.lower())


class Index:
    def __init__(self, docs):
        self.docs = {k: Counter(_tok(v)) for k, v in docs.items()}
        n = len(self.docs)
        df = Counter(t for c in self.docs.values() for t in c)
        self.idf = {t: math.log((1 + n) / (1 + d)) + 1 for t, d in df.items()}

    def _vec(self, c):
        return {t: f * self.idf.get(t, 0) for t, f in c.items()}

    def search(self, query, k=3):
        q = self._vec(Counter(_tok(query)))
        qn = math.sqrt(sum(v * v for v in q.values())) or 1
        scored = []
        for name, c in self.docs.items():
            d = self._vec(c)
            dn = math.sqrt(sum(v * v for v in d.values())) or 1
            scored.append((sum(q[t] * d.get(t, 0) for t in q) / (qn * dn), name))
        return [n for s, n in sorted(scored, reverse=True)[:k] if s > 0]


def recall_at_k(index, labelled, k=3):
    """labelled: list of (query, relevant doc name)."""
    return sum(rel in index.search(q, k) for q, rel in labelled) / len(labelled)
