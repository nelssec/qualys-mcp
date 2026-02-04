# @nelssec/qualys-mcp

MCP server for Qualys security APIs - enables natural language interaction with vulnerability, asset, and cloud security data through Claude and other MCP-compatible AI assistants.

## Quick Start

```bash
# Run with MCP Inspector
npx @modelcontextprotocol/inspector npx @nelssec/qualys-mcp

# Or install globally
npm install -g @nelssec/qualys-mcp
```

## Configuration

Set environment variables:

```bash
export QUALYS_USERNAME=your-username
export QUALYS_PASSWORD=your-password
export QUALYS_POD=US1  # US1, US2, US3, US4, EU1, EU2, EU3, CA1, IN1, AE1, UK1, AU1
```

### Custom Platform Support

For engineering, development, or private cloud deployments:

```bash
export QUALYS_PLATFORM=qualysguard.p03.eng.sjc01.qualys.com
```

Or specify URLs directly:

```bash
export QUALYS_API_URL=https://qualysapi.custom.qualys.com
export QUALYS_GATEWAY_URL=https://gateway.custom.qualys.com
```

## Usage with Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "qualys": {
      "command": "npx",
      "args": ["@nelssec/qualys-mcp"],
      "env": {
        "QUALYS_USERNAME": "your-username",
        "QUALYS_PASSWORD": "your-password",
        "QUALYS_POD": "US1"
      }
    }
  }
}
```

For custom/engineering platforms:

```json
{
  "mcpServers": {
    "qualys": {
      "command": "npx",
      "args": ["@nelssec/qualys-mcp"],
      "env": {
        "QUALYS_USERNAME": "your-username",
        "QUALYS_PASSWORD": "your-password",
        "QUALYS_PLATFORM": "qualysguard.p03.eng.sjc01.qualys.com"
      }
    }
  }
}
```

## Features

- **61 MCP Tools** across 13 Qualys modules
- VMDR, Container Security, Global AssetView, KnowledgeBase
- TotalCloud (AWS, Azure, GCP, OCI), Patch Management
- EDR, FIM, WAS, Compliance, CertView, CAR
- Cross-module workflows for risk prioritization

## Example Queries

- "Am I affected by CVE-2024-3094?"
- "Show me critical vulnerabilities on internet-facing assets"
- "What should I fix first on my external attack surface?"
- "List AWS EC2 instances with failing security controls"

## Documentation

See [GitHub repo](https://github.com/nelssec/qualys-mcp) for full documentation.

## License

MIT
