"""Hash-chained audit log, OpenTelemetry-shaped spans and Prometheus text metrics."""
import hashlib
import sqlite3
import time
import uuid
from contextlib import contextmanager


class Audit:
    def __init__(self):
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.execute("create table audit(seq integer primary key autoincrement, ts real, actor text, action text, ref text, prev text, hash text)")

    @staticmethod
    def _h(prev, ts, actor, action, ref):
        return hashlib.sha256(f"{prev}|{ts}|{actor}|{action}|{ref}".encode()).hexdigest()

    def record(self, actor, action, ref, ts=None):
        ts = time.time() if ts is None else ts
        row = self.db.execute("select hash from audit order by seq desc limit 1").fetchone()
        prev = row[0] if row else "0" * 64
        self.db.execute("insert into audit(ts,actor,action,ref,prev,hash) values(?,?,?,?,?,?)",
                        (ts, actor, action, ref, prev, self._h(prev, ts, actor, action, ref)))
        self.db.commit()

    def verify(self):
        prev = "0" * 64
        for seq, ts, actor, action, ref, p, h in self.db.execute("select seq,ts,actor,action,ref,prev,hash from audit order by seq"):
            if p != prev or h != self._h(prev, ts, actor, action, ref):
                return seq
            prev = h
        return None


class Tracer:
    def __init__(self):
        self.spans = []

    @contextmanager
    def span(self, name, trace_id, parent=None, **attrs):
        s = {"traceId": trace_id, "spanId": uuid.uuid4().hex[:16], "parentSpanId": parent, "name": name,
             "attributes": dict(attrs), "status": "OK", "start": time.time()}
        try:
            yield s
        except Exception:
            s["status"] = "ERROR"
            raise
        finally:
            s["end"] = time.time()
            self.spans.append(s)

    def for_trace(self, trace_id):
        return [s for s in self.spans if s["traceId"] == trace_id]


class Metrics:
    BUCKETS = (0.005, 0.01, 0.05, 0.1, 0.5, 1.0)

    def __init__(self):
        self.c, self.h = {}, {"count": 0, "sum": 0.0, "b": [0] * len(self.BUCKETS)}

    def inc(self, name, **labels):
        k = (name, tuple(sorted(labels.items())))
        self.c[k] = self.c.get(k, 0) + 1

    def add(self, name, v, **labels):
        k = (name, tuple(sorted(labels.items())))
        self.c[k] = self.c.get(k, 0) + v

    def observe(self, seconds):
        self.h["count"] += 1
        self.h["sum"] += seconds
        for i, b in enumerate(self.BUCKETS):
            if seconds <= b:
                self.h["b"][i] += 1

    def render(self):
        out = []
        for (n, labels), v in sorted(self.c.items()):
            lab = ",".join(f'{k}="{x}"' for k, x in labels)
            out.append(f"{n}{{{lab}}} {v}" if lab else f"{n} {v}")
        for b, v in zip(self.BUCKETS, self.h["b"]):
            out.append(f'aicore_request_seconds_bucket{{le="{b}"}} {v}')
        out.append(f'aicore_request_seconds_bucket{{le="+Inf"}} {self.h["count"]}')
        out.append(f"aicore_request_seconds_sum {self.h['sum']}")
        out.append(f"aicore_request_seconds_count {self.h['count']}")
        return "\n".join(out) + "\n"
