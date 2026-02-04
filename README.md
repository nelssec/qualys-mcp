# Qualys MCP Server

A lightweight MCP server for Qualys security data - **8 tools** that answer your security questions.

## Quick Start

```bash
pip install fastmcp

export QUALYS_USERNAME="your-username"
export QUALYS_PASSWORD="your-password"
export QUALYS_BASE_URL="https://qualysapi.qualys.com"
export QUALYS_GATEWAY_URL="https://gateway.qg1.apps.qualys.com"

python qualys_mcp.py
```

## Claude Desktop Config

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "qualys": {
      "command": "python",
      "args": ["/path/to/qualys_mcp.py"],
      "env": {
        "QUALYS_USERNAME": "your-username",
        "QUALYS_PASSWORD": "your-password",
        "QUALYS_BASE_URL": "https://qualysapi.qualys.com",
        "QUALYS_GATEWAY_URL": "https://gateway.qg1.apps.qualys.com"
      }
    }
  }
}
```

## Tools

| Tool | Question it answers |
|------|---------------------|
| `get_weekly_priorities` | What should my team fix this week? |
| `investigate_cve` | Are we affected by CVE-XXXX? |
| `get_security_posture` | How secure are we overall? |
| `get_patch_status` | What's our patching coverage? |
| `get_compliance_gaps` | What will fail our audit? |
| `get_cloud_risk` | What's our cloud security posture? |
| `get_asset_risk` | Why is this asset risky? |
| `get_tech_debt` | How do we reduce EOL software? |

## Qualys PODs

| POD | BASE_URL | GATEWAY_URL |
|-----|----------|-------------|
| US1 | qualysapi.qualys.com | gateway.qg1.apps.qualys.com |
| US2 | qualysapi.qg2.apps.qualys.com | gateway.qg2.apps.qualys.com |
| US3 | qualysapi.qg3.apps.qualys.com | gateway.qg3.apps.qualys.com |
| EU1 | qualysapi.qualys.eu | gateway.qg1.apps.qualys.eu |
| EU2 | qualysapi.qg2.apps.qualys.eu | gateway.qg2.apps.qualys.eu |

## Legacy Go Version

The original Go version with 70+ granular tools is in `cmd/qualys-mcp/`.

## License

MIT - Copyright (c) 2025 Andrew Nelson
