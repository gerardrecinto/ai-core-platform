"""MCP server over stdio (newline-delimited JSON-RPC 2.0). Every tool call goes through the registry
(approved, role, data class, pinned digest) and the gateway. Identity is a lab identity set with AICORE_ROLES;
a real deployment passes an OIDC token and verifies it the same way the gateway does."""
import json
import os
import sys
import time

from .demo import build
from .evals import Index
from .hybrid import OnPremAgent, issue_ticket
from .registry import Registry

DOCS = {"nfs-tuning": "NFS attribute caching and actimeo settings for CAD homes",
        "license-servers": "License server seats, queue limits and checkout timeouts for simulators",
        "perforce-triage": "Perforce sync failures, stale workspaces and lock cleanup"}

TOOLS = {
    "ask_model": ("Ask the governed model gateway", "internal", ["engineer", "contractor", "intern", "ai-admin"],
                  {"prompt": {"type": "string"}, "data_class": {"type": "string"}}),
    "search_docs": ("Search engineering docs", "internal", ["engineer", "contractor", "intern", "ai-admin"],
                    {"query": {"type": "string"}}),
    "run_eda_job": ("Queue an allowlisted on-prem job as the requesting engineer", "confidential", ["engineer", "ai-admin"],
                    {"command": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}}}),
}


class Server:
    def __init__(self, roles, user="alice"):
        self.gw, tok = build()
        self.roles, self.user = roles, user
        self.token = tok(user, roles, "fw")
        self.now = 1_000_000.0
        self.reg = Registry(self.gw.audit)
        self.pins = {}
        for n, (desc, dc, allowed, _) in TOOLS.items():
            self.pins[n] = self.reg.submit({"name": n, "version": "1", "description": desc, "allowed_roles": allowed,
                                            "data_class_max": dc, "entrypoint": f"aicore.mcp_server:{n}"}, "platform-team")
            self.reg.approve(n, "1", "security-reviewer", ["ai-admin"])
        self.index = Index(DOCS)
        self.agent = OnPremAgent(b"lab-secret", {"alice": 1001})

    def call(self, name, args):
        dc = args.get("data_class", "internal")
        self.reg.resolve(name, "1", self.user, self.roles, "confidential" if name == "run_eda_job" else dc, self.pins.get(name))
        if name == "ask_model":
            r = self.gw.chat(self.token, args["prompt"], dc, self.now)
            return json.dumps({k: r[k] for k in ("status", "provider", "text", "trace_id") if k in r})
        if name == "search_docs":
            return json.dumps(self.index.search(args["query"]))
        t = issue_ticket(b"lab-secret", self.user, args["command"], args.get("args", []), self.now)
        jid = self.agent.accept(t, self.now)
        self.agent.tick(); self.agent.tick()
        return json.dumps({"job": jid, **self.agent.jobs[jid]})

    def handle(self, msg):
        m, i = msg.get("method"), msg.get("id")
        if i is None:
            return None
        if m == "initialize":
            res = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "ai-core", "version": "0.1.0"}}
        elif m == "tools/list":
            res = {"tools": [{"name": n, "description": d, "inputSchema": {"type": "object", "properties": p}}
                             for n, (d, _, _, p) in TOOLS.items()]}
        elif m == "tools/call":
            p = msg.get("params", {})
            try:
                res = {"content": [{"type": "text", "text": self.call(p["name"], p.get("arguments", {}))}], "isError": False}
            except Exception as e:  # any denial or bad input becomes an MCP tool error, never a crash
                res = {"content": [{"type": "text", "text": f"denied: {type(e).__name__}: {e}"}], "isError": True}
        else:
            return {"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "method not found"}}
        return {"jsonrpc": "2.0", "id": i, "result": res}


def main():
    s = Server(os.environ.get("AICORE_ROLES", "engineer").split(","))
    for line in sys.stdin:
        try:
            out = s.handle(json.loads(line))
        except json.JSONDecodeError:
            out = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        if out:
            sys.stdout.write(json.dumps(out) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
