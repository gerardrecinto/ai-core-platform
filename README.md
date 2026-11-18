# ai-core-platform

One governed way for engineers to use AI assistants. A gateway checks who is asking, what data class they may use, scans the prompt, enforces rate and budget limits, routes to an allowed model with fallback, and audits every call. Approved tools are served over MCP and can queue jobs on-prem as the requesting engineer.

A lab: stdlib Python, mock model providers, synthetic identities. No real Entra, Bedrock, vLLM, VMware or LSF. Docs and live simulator: https://gerardrecinto.github.io/ai-core-platform/

## Run

```
git clone https://github.com/gerardrecinto/ai-core-platform
cd ai-core-platform
python3 -m venv .venv && . .venv/bin/activate
pip install pytest
PYTHONPATH=src python -m aicore.demo
python -m pytest -q
```

The demo prints nine decisions (200, 401, 403, 422, 402 and a fallback) and ends with `audit chain intact: True`.

Serve it with `PYTHONPATH=src python -m aicore.server`. It prints a ready-to-paste curl with a one-hour lab token. `GET /metrics` returns Prometheus text.

## Layout

- `src/aicore/gateway.py` the request pipeline; `jwtlite.py` RS256 verification; `policy.py` ceilings and DLP
- `router.py` circuit breakers and fallback; `quota.py` rate limits and budgets; `observe.py` audit chain, spans, metrics
- `registry.py` approved tools with pinned digests; `mcp_server.py` MCP over stdio; `plugins/` Claude Code and VS Code config
- `hybrid.py` and `agent.py` signed one-time job tickets, run as the requester's uid, license seat queue (simulated)
- `evals.py` agent eval gate and retrieval recall
- `deploy/helm`, `infra/aws`, `deploy/ansible`, `Dockerfile`, `.github/workflows/ci.yml`: CI lints the chart, validates Terraform, syntax-checks Ansible and builds the image. Nothing has been applied to AWS.
