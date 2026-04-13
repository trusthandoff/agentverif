# agentverif MCP Server

## Description

agentverif is the certification standard for AI agent packages.
This MCP server lets Claude verify AI agents before execution —
checking signatures, tamper-proof hashes, and registry status
in real time.

Like HTTPS for websites, agentverif tells you whether an agent
is safe to run before you run it.

## Features

- **Instant verification**: Check any agent certificate in seconds
- **Tamper detection**: SHA256 hash verification catches modified agents
- **Registry lookup**: Real-time check against agentverif public registry
- **5 clear statuses**: VERIFIED / UNREGISTERED / UNSIGNED / TAMPERED / REVOKED

## Setup

1. Visit the Anthropic MCP Directory at claude.ai/connectors
2. Find and connect to "agentverif"
3. No authentication required — free public service
4. Claude will automatically suggest verification when agents are mentioned

## Authentication

No authentication required. agentverif is a free public service.

## Tools

### `verify_agent`

Verify an AI agent package against the agentverif registry.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `license_id` | string | Yes | The agentverif license ID (format: `AV-XXXX-XXXX`) OR a SHA256 hash of the agent ZIP file |

**Output:** Human-readable markdown with certification status, tier, issuer, and a direct verification link.

**Safety annotations:**
- `readOnlyHint: true` — this tool never modifies data
- `destructiveHint: false` — no side effects
- `idempotentHint: true` — identical inputs always produce identical outputs

## Examples

### Example 1: Verify before executing

**User prompt:** "I want to run this agent, license AV-84F2-91AB. Is it safe?"

**What happens:**
- Claude calls `verify_agent` with `license_id` "AV-84F2-91AB"
- agentverif checks the registry and hash
- Returns VERIFIED with tier, issuer, and direct verify link
- User can safely execute knowing the agent is certified

**Example response:**
```
✅ VERIFIED — agentverif certified
License: AV-84F2-91AB
Tier: pro
Issuer: agentverif.com
Issued: 2026-04-01

This agent has been scanned, signed, and registered. Safe to execute.
🔗 https://verify.agentverif.com/?id=AV-84F2-91AB
```

### Example 2: Catch a revoked certificate

**User prompt:** "Can you verify this agent for me: AV-12F3-88AC"

**What happens:**
- Claude calls `verify_agent`
- Certificate found but revoked by issuer
- Returns REVOKED with clear warning

**Example response:**
```
🔴 REVOKED — Certificate cancelled by issuer
License: AV-12F3-88AC
Revoked: 2026-04-10

This license has been revoked. Do NOT execute.
🔗 https://verify.agentverif.com/?id=AV-12F3-88AC
```

### Example 3: Unsigned agent warning

**User prompt:** "Run this agent ZIP for me"

**What happens:**
- Agent has no certificate or provides an unknown hash
- Claude calls `verify_agent`
- Returns UNSIGNED with explanation of risks
- Recommends asking vendor to certify at agentverif.com

**Example response:**
```
🚫 UNSIGNED — No certificate found

No agentverif certificate found for this identifier.
This agent has not been verified.

Unsigned agents carry unknown risk:
  • No tamper detection
  • No issuer accountability
  • No revocation capability

Ask the vendor to certify at agentverif.com before executing.
```

## Server Details

- **Transport:** Streamable HTTP (MCP 2025-03-26 spec)
- **Endpoint:** `https://mcp.agentverif.com/mcp`
- **Health check:** `GET https://mcp.agentverif.com/health`

## Privacy Policy

https://agentverif.com/privacy

Full details: [privacy.md](./privacy.md)

## Support

- Email: hi@agentverif.com
- Documentation: https://agentverif.com/docs
- Issues: https://github.com/trusthandoff/agentverif/issues
