# Conversational SecOps: Building an MCP Server for Qualys

*How we built a natural language interface to security data using the Model Context Protocol*

**By Andrew Nelson** | [github.com/nelssec](https://github.com/nelssec)

---

Security operations has a context-switching problem. Your vulnerability data lives in VMDR. Container security is in a different dashboard. Cloud posture is somewhere else. Endpoint detections are in EDR. Certificates are in CertView. And when a new CVE drops, you're frantically clicking between tabs trying to answer one simple question: *Am I affected?*

What if you could just ask?

```
"Is CVE-2024-3094 in my environment?"
```

And get an answer that spans your entire security stack—vulnerabilities, cloud resources, containers, endpoints—in seconds?

That's what we built with **qualys-mcp**: a Model Context Protocol server that gives AI assistants like Claude direct access to 60 security tools across 13 Qualys modules.

## The Problem: Security Data Silos

Modern security teams don't lack data. They're drowning in it. The challenge is correlation and context.

Consider a typical "Am I vulnerable?" workflow:

1. Search the KnowledgeBase for the CVE
2. Find the associated QID(s)
3. Switch to VMDR to search for detections
4. Cross-reference with asset inventory
5. Check if affected assets are in cloud (switch to TotalCloud)
6. See if there are related security control failures
7. Check for any active exploitation (switch to EDR/CDR)

That's 7 context switches, 4 different query syntaxes, and 15 minutes minimum—for a single CVE. During a zero-day, multiply that by every CVE variant and you're looking at hours of manual correlation.

## The Solution: MCP as a Security Integration Layer

The Model Context Protocol (MCP) is Anthropic's standard for giving AI models access to external tools and data. Think of it as a universal adapter between AI and your software—Claude can now reach into your systems and pull data on your behalf.

We built qualys-mcp to expose the entire Qualys API surface as MCP tools:

| Module | Tools | What It Covers |
|--------|-------|----------------|
| VMDR | 8 | Vulnerability scanning, host detections, stats & summaries |
| Container Security | 6 | Images, containers, runtime vulnerabilities |
| TotalCloud | 7 | AWS/Azure/GCP/OCI posture, CDR findings |
| Global AssetView | 6 | Unified asset inventory, high-risk assets |
| KnowledgeBase | 4 | CVE/QID research |
| EDR | 5 | Endpoint events, indicators of compromise |
| FIM | 5 | File integrity events |
| Patch Management | 5 | Patch status, deployment jobs |
| WAS | 5 | Web application vulnerabilities |
| CertView | 5 | SSL/TLS certificates |
| Compliance | 4 | Policy compliance |
| CAR | 6 | Custom assessment and remediation scripts |
| Workflows | 2 | Cross-module risk summaries and remediation plans |

**60 tools. One conversation.**

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Claude / AI Assistant                │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│                 MCP Gateway (Optional)               │
│  ┌─────────┐ ┌────────┐ ┌──────────┐ ┌───────────┐ │
│  │  Auth   │ │ Policy │ │  Audit   │ │   Rate    │ │
│  │JWT/OIDC │ │ Engine │ │  Logger  │ │  Limiter  │ │
│  └─────────┘ └────────┘ └──────────┘ └───────────┘ │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│                    qualys-mcp                        │
│  ┌──────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐ │
│  │ VMDR │ │ Container │ │TotalCloud│ │    EDR    │ │
│  └──────┘ └───────────┘ └──────────┘ └───────────┘ │
│  ┌──────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐ │
│  │ GAV  │ │    FIM    │ │   WAS    │ │  Patch    │ │
│  └──────┘ └───────────┘ └──────────┘ └───────────┘ │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│                    Qualys APIs                       │
│         Gateway API  •  REST API  •  XML API         │
└─────────────────────────────────────────────────────┘
```

The MCP server handles:
- **Authentication**: JWT tokens for Qualys Gateway API, basic auth for classic API
- **Multi-cloud**: AWS, Azure, GCP, and OCI connectors
- **Response normalization**: Consistent JSON structures across different API versions
- **Error handling**: Graceful degradation when modules aren't available

### Example: CVE Triage in Seconds

Here's what that 7-step manual workflow looks like with qualys-mcp:

**User:** "Check if we're affected by CVE-2024-3094 (the xz backdoor)"

**Claude:**
```
Let me check across your environment...

[Calling kb_get_cve_mapping with CVE-2024-3094]
[Calling vmdr_search_detections with QID 379548]
[Calling cs_search_images with vulnerability filter]
[Calling tc_list_cdr_findings for related activity]

Results:

AFFECTED HOSTS: 3 found
   - prod-web-01 (10.0.1.15) - Ubuntu 22.04, xz 5.6.0
   - prod-web-02 (10.0.1.16) - Ubuntu 22.04, xz 5.6.0
   - staging-api (10.0.2.8) - Debian 12, xz 5.6.1

AFFECTED CONTAINERS: 1 image
   - myregistry/api-server:latest - contains vulnerable xz-utils

CDR ACTIVITY: No exploitation attempts detected

RECOMMENDATION: Prioritize prod-web-01 and prod-web-02
   (internet-facing). The xz version can be downgraded to 5.4.x
   as a mitigation.
```

One question. Ten seconds. Complete visibility.

## Multi-Cloud Security Posture

TotalCloud support was a key focus. Cloud security data is notoriously siloed—AWS findings in one place, Azure in another, GCP somewhere else.

With qualys-mcp, you can ask cloud-agnostic questions:

```
"Show me failing security controls across all cloud providers"
```

And Claude will query AWS, Azure, GCP, and OCI connectors, aggregate the results, and present a unified view:

```
[Calling tc_list_controls for AWS - 847 controls, 12 failing]
[Calling tc_list_controls for Azure - 423 controls, 8 failing]
[Calling tc_list_controls for GCP - 156 controls, 3 failing]

CROSS-CLOUD CONTROL FAILURES:

AWS (12 failing):
  - CID-1: MFA not enabled for root account [CRITICAL]
  - CID-23: S3 bucket 'logs-prod' allows public read [HIGH]
  ...

Azure (8 failing):
  - CID-50001: SQL TDE not enabled [HIGH]
  - CID-50015: NSG allows 0.0.0.0/0 inbound on RDP [CRITICAL]
  ...

GCP (3 failing):
  - CID-100003: Cloud Storage bucket is public [HIGH]
  ...

Common theme: Public access misconfigurations across all providers.
```

## Cloud Detection and Response (CDR)

The CDR integration brings real-time threat detection into the conversation:

```
"Any suspicious activity in my cloud environments this week?"
```

```
[Calling tc_list_cdr_findings for last 7 days]

CDR FINDINGS (Last 7 Days):

CRITICAL (2):
  - Cryptominer behavior detected on i-0abc123
    - Outbound connection to known mining pool
    - First seen: 2024-01-15 03:42 UTC

  - Container escape attempt in eks-prod cluster
    - Process tried to access host /etc/shadow
    - Container: nginx:latest in pod api-gateway

HIGH (5):
  - Traffic to known C2 infrastructure (3 instances)
  - Unusual IAM activity from new geolocation (2 events)
```

## Cross-Module Workflows

One of the most powerful features is the ability to orchestrate multiple modules in a single query:

### Asset Risk Summary

```
"What's the risk on this server and how do I fix it?"
```

```
[Calling get_asset_risk_summary]
→ Combines GAV (asset details, TruRisk score)
→ VMDR (top 10 vulnerabilities)
→ KnowledgeBase (remediation guidance)
→ Patch Management (available patches)

ASSET: prod-web-01 (10.0.1.15)
TRURISK SCORE: 847/1000 (Critical)
CRITICALITY: 5/5

TOP VULNERABILITIES:
  1. QID 379548 - xz backdoor (Severity 5)
  2. QID 91983 - OpenSSL vulnerability (Severity 5)
  3. QID 38739 - Apache Log4j (Severity 5)

AVAILABLE PATCHES: 12 missing
REMEDIATION: Prioritize QID 379548 - downgrade xz-utils to 5.4.x
```

### Remediation Planning

```
"Give me a remediation plan for Log4Shell"
```

The workflows module automatically:
1. Maps CVE to QID(s)
2. Finds all affected assets across your environment
3. Retrieves available patches
4. Gets remediation scripts from CAR
5. Provides manual remediation steps from the KnowledgeBase

## Custom Remediation with CAR

The CAR (Custom Assessment and Remediation) module enables automated remediation:

```
"List remediation scripts for Windows patching"
```

```
[Calling car_list_scripts with type:REMEDIATION, platform:WINDOWS]

AVAILABLE SCRIPTS:
  - Script 1234: "Windows Update Deployment" (Windows)
  - Script 1235: "Service Pack Installation" (Windows)
  - Script 1240: "Registry Security Hardening" (Windows)
```

Scripts can be executed on targeted assets or asset groups, with test mode for validation before deployment.

## Security for the Whole Organization

One of the most powerful aspects of conversational security is accessibility. You don't need to know Qualys Query Language or which dashboard to use.

**For Developers:**
```
"Are there any vulnerabilities in the containers I pushed this week?"
```

**For Compliance:**
```
"What's our CIS benchmark compliance percentage for AWS?"
```

**For Executives:**
```
"Give me a one-paragraph security summary for the board"
```

**For Incident Response:**
```
"Show me all activity from IP 185.220.101.x in the last 24 hours"
```

Same tools, different questions, appropriate answers for each audience.

## Production Considerations

### Security of the MCP Server Itself

We built qualys-mcp with security-conscious deployments in mind:

**Gateway Mode**: Optional MCP Gateway with:
- JWT/OIDC authentication (Okta, Azure AD, etc.)
- Policy-based access control (limit tools by role)
- Audit logging (JSON trail of all queries)
- Rate limiting (prevent abuse)
- Input validation (block injection attempts)

**Example Policy:**
```json
{
  "policies": {
    "security-analyst": {
      "description": "Full read access to vulnerability and threat data",
      "allowed_tools": ["vmdr_*", "kb_*", "gav_*", "cs_*", "edr_*", "fim_*"],
      "rate_limit_per_min": 100
    },
    "cloud-security": {
      "description": "Cloud security posture and CDR access",
      "allowed_tools": ["tc_*", "gav_*", "kb_*"],
      "rate_limit_per_min": 150
    },
    "soc-analyst": {
      "description": "SOC with EDR, FIM, CDR for threat hunting",
      "allowed_tools": ["edr_*", "fim_*", "tc_list_cdr_findings", "gav_*"],
      "rate_limit_per_min": 200
    },
    "developer": {
      "description": "Container security only",
      "allowed_tools": ["cs_*", "kb_get_cve_mapping"],
      "rate_limit_per_min": 50
    }
  }
}
```

### API Rate Limits

Qualys APIs have rate limits. The MCP server handles this gracefully:
- Configurable rate limiting at the gateway level
- Appropriate page sizes for bulk queries
- Timeout handling for long-running operations

## What's Next

Recent additions:
- **Cross-Module Workflows**: Risk summaries and remediation plans that span multiple modules
- **CAR Integration**: Execute custom remediation scripts on assets
- **Smart Output Modes**: Auto-selects response detail level based on query specificity

Still exploring:
1. **Scheduled Summaries**: Daily security briefings generated automatically
2. **Alert Triage**: Connect to Qualys alerting for conversational incident response
3. **Custom Reporting**: Generate compliance reports through conversation

## Try It Yourself

qualys-mcp is open source: [github.com/nelssec/qualys-mcp](https://github.com/nelssec/qualys-mcp)

```bash
# Clone and build
git clone https://github.com/nelssec/qualys-mcp
cd qualys-mcp
go build -o qualys-mcp ./cmd/qualys-mcp

# Configure
export QUALYS_USERNAME="your-username"
export QUALYS_PASSWORD="your-password"
export QUALYS_POD="US1"  # or EU1, CA1, etc.

# Add to Claude Desktop config
# ~/Library/Application Support/Claude/claude_desktop_config.json
```

```json
{
  "mcpServers": {
    "qualys": {
      "command": "/path/to/qualys-mcp",
      "env": {
        "QUALYS_USERNAME": "your-username",
        "QUALYS_PASSWORD": "your-password",
        "QUALYS_POD": "US1"
      }
    }
  }
}
```

Then just ask Claude:
- "Am I affected by Log4Shell?"
- "Show me critical vulnerabilities from this week"
- "List failing AWS security controls"

## Conclusion

Security operations shouldn't require a PhD in query languages and dashboard navigation. The data exists—it's just locked behind interfaces designed for a pre-AI world.

MCP gives us a path to conversational security operations. Ask questions in plain English. Get answers that span your entire security stack. Correlate data that was previously siloed.

qualys-mcp is our implementation of this vision for the Qualys ecosystem. 60 tools, 13 modules, one conversation.

The future of SecOps is conversational. Let's build it.

---

*qualys-mcp is an independent open-source project and is not affiliated with or endorsed by Qualys, Inc.*

*Copyright (c) 2025 Andrew Nelson. MIT License.*
