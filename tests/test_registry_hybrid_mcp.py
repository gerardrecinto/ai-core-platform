import json
import os
import subprocess
import sys

import pytest

from aicore.evals import Index, recall_at_k, run_suite
from aicore.hybrid import OnPremAgent, TicketError, issue_ticket
from aicore.observe import Audit
from aicore.registry import Registry, RegistryError, digest

M = {"name": "t", "version": "1", "description": "d", "allowed_roles": ["engineer"], "data_class_max": "internal", "entrypoint": "x:y"}


def reg():
    return Registry(Audit())


def test_four_eyes_and_admin_only():
    r = reg()
    r.submit(M, "alice")
    with pytest.raises(RegistryError):
        r.approve("t", "1", "alice", ["ai-admin"])  # owner
    with pytest.raises(RegistryError):
        r.approve("t", "1", "bob", ["engineer"])  # not admin
    with pytest.raises(RegistryError):
        r.resolve("t", "1", "a", ["engineer"], "public")  # still pending
    r.approve("t", "1", "bob", ["ai-admin"])
    assert r.resolve("t", "1", "a", ["engineer"], "public")["name"] == "t"


def test_resolve_checks_role_class_pin_and_tamper():
    r = reg()
    d = r.submit(M, "alice")
    r.approve("t", "1", "bob", ["ai-admin"])
    with pytest.raises(RegistryError):
        r.resolve("t", "1", "a", ["intern"], "public")
    with pytest.raises(RegistryError):
        r.resolve("t", "1", "a", ["engineer"], "confidential")
    with pytest.raises(RegistryError):
        r.resolve("t", "1", "a", ["engineer"], "public", pin="0" * 64)
    assert r.resolve("t", "1", "a", ["engineer"], "public", pin=d)
    r.items[("t", "1")]["manifest"]["entrypoint"] = "evil:y"  # swapped after approval
    with pytest.raises(RegistryError):
        r.resolve("t", "1", "a", ["engineer"], "public")


def test_versions_are_immutable_revoke_and_list():
    r = reg()
    r.submit(M, "alice")
    with pytest.raises(RegistryError):
        r.submit(M, "alice")
    r.approve("t", "1", "bob", ["ai-admin"])
    assert len(r.approved()) == 1
    r.revoke("t", "1", "bob", ["ai-admin"])
    assert r.approved() == []
    with pytest.raises(RegistryError):
        r.submit({**M, "extra": 1}, "alice")
    assert digest(M) == digest(dict(reversed(list(M.items()))))


def agent():
    return OnPremAgent(b"s", {"alice": 1001, "svc": 5}, {"sim": 1})


def test_ticket_replay_expiry_tamper_and_args():
    a = agent()
    t = issue_ticket(b"s", "alice", "eda-lint", ["top.v"], 0)
    a.accept(t, 1)
    for bad, why in ((t, "replay"), (issue_ticket(b"s", "alice", "eda-lint", [], 0), "expired"),
                     (issue_ticket(b"x", "alice", "eda-lint", [], 0), "signature"),
                     (issue_ticket(b"s", "alice", "rm", ["-rf"], 0), "command not allowed"),
                     (issue_ticket(b"s", "alice", "eda-lint", ["a;b"], 0), "command not allowed"),
                     (issue_ticket(b"s", "svc", "eda-lint", [], 0), "no personal account"),
                     (issue_ticket(b"s", "ghost", "eda-lint", [], 0), "no personal account")):
        with pytest.raises(TicketError, match=why if why != "expired" else "expired"):
            a.accept(bad, 1 if why != "expired" else 500)


def test_runs_as_requesting_uid_and_license_queue():
    a = agent()
    j1 = a.accept(issue_ticket(b"s", "alice", "sim-run", ["a"], 0), 1)
    j2 = a.accept(issue_ticket(b"s", "alice", "sim-run", ["b"], 0), 1)
    a.tick()
    assert (a.jobs[j1]["state"], a.jobs[j2]["state"]) == ("RUN", "PEND")  # one seat
    a.tick()
    assert (a.jobs[j1]["state"], a.jobs[j2]["state"]) == ("DONE", "RUN")
    a.tick()
    assert a.jobs[j2]["out"] == "ran sim-run as uid 1001"


def test_eval_gate_and_retrieval():
    cases = [{"name": "a", "prompt": "x", "tool": "search_docs", "contains": ["ok"]},
             {"name": "b", "prompt": "y", "excludes": ["secret"]}]
    good = run_suite(lambda p: {"tool": "search_docs", "text": "ok"}, cases, 1.0)
    assert good["gate"] and good["pass_rate"] == 1.0
    bad = run_suite(lambda p: {"tool": None, "text": "ok secret"}, cases, 0.9)
    assert not bad["gate"] and bad["failed"] == ["a", "b"]
    idx = Index({"nfs": "nfs attribute caching actimeo", "lic": "license seats queue checkout", "p4": "perforce sync workspace"})
    assert idx.search("license seat queue", 1) == ["lic"] and idx.search("zzz") == []
    assert recall_at_k(idx, [("actimeo caching", "nfs"), ("perforce workspace", "p4")], 1) == 1.0


def rpc(roles, *msgs):
    env = {**os.environ, "PYTHONPATH": "src", "AICORE_ROLES": roles}
    p = subprocess.run([sys.executable, "-m", "aicore.mcp_server"], input="\n".join(json.dumps(m) for m in msgs) + "\n",
                       capture_output=True, text=True, env=env, timeout=60)
    return [json.loads(x) for x in p.stdout.splitlines()]


def test_mcp_protocol_and_tool_calls():
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    out = rpc("engineer", init, {"jsonrpc": "2.0", "method": "notifications/initialized"},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
              {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "search_docs", "arguments": {"query": "license seats"}}},
              {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "run_eda_job", "arguments": {"command": "eda-lint", "args": ["top.v"]}}},
              {"jsonrpc": "2.0", "id": 5, "method": "nope"})
    by = {o["id"]: o for o in out}
    assert by[1]["result"]["serverInfo"]["name"] == "ai-core" and len(out) == 5  # the notification gets no reply
    assert {t["name"] for t in by[2]["result"]["tools"]} == {"ask_model", "search_docs", "run_eda_job"}
    assert "license-servers" in by[3]["result"]["content"][0]["text"]
    assert "uid 1001" in by[4]["result"]["content"][0]["text"] and by[5]["error"]["code"] == -32601


def test_mcp_intern_is_denied_the_eda_tool():
    out = rpc("intern", {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "run_eda_job", "arguments": {"command": "eda-lint", "args": []}}})
    assert out[0]["result"]["isError"] and "role not allowed" in out[0]["result"]["content"][0]["text"]
