# Qualys MCP Server

> ⚠️ **Unofficial project.** This is a personal project to showcase the viability of connecting AI assistants to Qualys via the Model Context Protocol. It is not affiliated with, endorsed by, or supported by Qualys, Inc.

An MCP server that connects AI assistants to Qualys security data. **7 workflow tools** covering vulnerability management, cloud security, containers, compliance, remediation, and more. Pure Python, zero config beyond credentials.

**📖 [Full documentation →](https://qualys-mcp.netlify.app/)**

## Setup

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "qualys": {
      "command": "uvx",
      "args": ["qualys-mcp"],
      "env": {
        "QUALYS_USERNAME": "your-username",
        "QUALYS_PASSWORD": "your-password",
        "QUALYS_POD": "US2"
      }
    }
  }
}
```

Set `QUALYS_POD` to your platform POD — the server derives the correct API and gateway URLs automatically.

**Supported pods:** `US1` `US2` `US3` `US4` `EU1` `EU2` `EU3` `IN1` `CA1` `AE1` `UK1` `AU1` `KSA1`

> **Advanced:** If you need to override the auto-derived URLs, set `QUALYS_BASE_URL` and `QUALYS_GATEWAY_URL` explicitly instead of `QUALYS_POD`. Explicit URLs take priority.

Requires [uv](https://docs.astral.sh/uv/): `brew install uv` or `curl -LsSf https://astral.sh/uv/install.sh | sh`

### Alternative

```bash
pip install qualys-mcp
qualys-mcp
```

### Self-Signed Certificates

For environments with self-signed certs, add `"QUALYS_SSL_VERIFY": "false"` to the env block.

## Tools

7 workflow tools that intelligently dispatch to 42 internal aggregators across all Qualys modules. Each tool handles routing, concurrent API calls, cross-domain correlation, and response synthesis automatically.

| Tool | What it answers |
|------|----------------|
| `investigate` | Deep-dive any security topic — CVEs, threat actors, assets, EDR/FIM events, KB searches |
| `assess_risk` | Cross-domain risk — VMs, cloud (AWS/Azure/GCP/OCI), containers, web apps, certificates, assets |
| `check_compliance` | Compliance posture — PCI, HIPAA, CIS, NIST, SOC2 pass/fail, failing controls, exceptions |
| `plan_remediation` | Patch priorities, deployment status, mitigation coverage, program gap analysis |
| `security_overview` | Daily/weekly/monthly briefing — scanner health, scan status, vulnerability findings |
| `reports` | Generate, list, download, and manage Qualys reports |
| `cache_status` | View and clear API caches |

### Key Parameters

**investigate**
- `target` — CVE ID, threat actor, hostname, IP, or free-text topic
- `depth` — `quick` (~10s) / `standard` (~20s) / `deep` (~45s)
- `scope` — `all` / `vulns` / `threats` / `assets` / `edr` / `fim`

**assess_risk**
- `scope` — `all` / `cloud` / `containers` / `web` / `certs` / `assets`
- `tag` / `asset_group` — filter by business group
- `provider` — `aws` / `azure` / `gcp` (cloud scope)
- `asset_id` — single asset deep-dive

**check_compliance**
- `framework` — `PCI` / `HIPAA` / `CIS` / `NIST` / `SOC2`
- `include_exceptions` — include risk acceptances

**plan_remediation**
- `scope` — `all` / `patches` / `mitigations` / `program`
- `severity` — `critical` / `high` / `moderate`
- `cves` / `qids` — check mitigation coverage for specific vulns

**security_overview**
- `period` — `today` / `week` / `month`
- `quick` — fast snapshot (~2s) vs full briefing

## Example Conversations

### Daily Operations
```
"Give me a security overview"                  → security_overview(quick=True)
"What happened this week?"                     → security_overview(period="week")
"What should we patch first?"                  → plan_remediation(scope="patches", severity="critical")
"How's our compliance?"                        → check_compliance()
```

### Investigation
```
"Tell me about CVE-2024-3400"                  → investigate(target="CVE-2024-3400")
"Are we exposed to ransomware?"                → investigate(target="ransomware")
"What do we know about Iranian threats?"        → investigate(target="iran")
"Investigate this host: 10.0.0.1"              → investigate(target="10.0.0.1", scope="edr")
```

### Risk Assessment
```
"What's our overall risk?"                     → assess_risk(scope="all")
"How's our cloud security?"                    → assess_risk(scope="cloud")
"Any container vulnerabilities?"               → assess_risk(scope="containers")
"Web app security status?"                     → assess_risk(scope="web")
"Show me risk for Production assets"           → assess_risk(tag="Production")
```

### Compliance & Remediation
```
"Are we PCI compliant?"                        → check_compliance(framework="PCI")
"What's our patch coverage?"                   → plan_remediation(scope="patches")
"Is there a mitigation for CVE-2024-3400?"     → plan_remediation(cves=["CVE-2024-3400"])
"What security gaps do we have?"               → plan_remediation(scope="program")
```

### Multi-Step Workflows
```
"New critical CVE dropped — what do I need to know?"
→ investigate(target="CVE-...") → plan_remediation(cves=["CVE-..."]) → check_compliance()

"Prepare me for the weekly security standup"
→ security_overview(period="week") → assess_risk(scope="all") → plan_remediation(scope="patches")

"PCI audit prep"
→ check_compliance(framework="PCI", include_exceptions=True) → assess_risk(scope="all") → plan_remediation()
```

## Architecture

```
AI Assistant → qualys_mcp.py (7 tools) → workflows/ (dispatch + synthesis) → aggregators.py (42 functions) → api.py (HTTP + caching) → Qualys APIs
```

Each workflow tool:
1. Builds a dispatch plan based on parameters
2. Runs selected aggregators concurrently
3. Merges results into a unified response envelope
4. Applies cross-domain correlation
5. Returns prioritized findings and recommended actions

## Performance

Tested on an 89,000-asset environment (US2 POD):

| Workflow | Time |
|----------|------|
| `security_overview(quick=True)` | 1.7s |
| `assess_risk(scope="cloud")` | 1.3s |
| `assess_risk(scope="containers")` | 3.1s |
| `check_compliance()` | <1ms (cached) |
| `plan_remediation(scope="patches")` | 2.6s |
| `investigate(target="CVE-2024-3400")` | 12.8s |
| `assess_risk(scope="all")` | 4.9s |

## Eval Harness

300 routing test questions + 900 variants + 30 multi-turn conversation workflows for automated evaluation.

```bash
# Install eval dependencies
pip install anthropic mcp python-dotenv pyyaml

# Run eval
python -m eval --quick
```

## Testing

```bash
# Unit tests (282 tests)
pip install pytest
pytest tests/ --ignore=tests/conversations -q

# Smoke test
bash test_tools.sh fast
```

## Qualys PODs

| POD | BASE_URL | GATEWAY_URL |
|-----|----------|-------------|
| US1 | qualysapi.qualys.com | gateway.qg1.apps.qualys.com |
| US2 | qualysapi.qg2.apps.qualys.com | gateway.qg2.apps.qualys.com |
| US3 | qualysapi.qg3.apps.qualys.com | gateway.qg3.apps.qualys.com |
| US4 | qualysapi.qg4.apps.qualys.com | gateway.qg4.apps.qualys.com |
| EU1 | qualysapi.qualys.eu | gateway.qg1.apps.qualys.eu |
| EU2 | qualysapi.qg2.apps.qualys.eu | gateway.qg2.apps.qualys.eu |
| EU3 | qualysapi.qg3.apps.qualys.eu | gateway.qg3.apps.qualys.eu |
| IN1 | qualysapi.qg1.apps.qualys.in | gateway.qg1.apps.qualys.in |
| CA1 | qualysapi.qg1.apps.qualys.ca | gateway.qg1.apps.qualys.ca |
| AE1 | qualysapi.qg1.apps.qualys.ae | gateway.qg1.apps.qualys.ae |
| UK1 | qualysapi.qg1.apps.qualys.co.uk | gateway.qg1.apps.qualys.co.uk |
| AU1 | qualysapi.qg1.apps.qualys.com.au | gateway.qg1.apps.qualys.com.au |
| KSA1 | qualysapi.qg1.apps.qualysksa.com | gateway.qg1.apps.qualysksa.com |

## License

MIT - Copyright (c) 2026 Andrew Nelson
