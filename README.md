<div align="center">
  <img src="https://raw.githubusercontent.com/trusthandoff/agentverif/main/web/logo.svg" width="80" height="80" alt="AgentVerif">

  # AgentVerif — Let's Encrypt for AI Agents

  ✅ Sell verified agents. Buyers trust verified packages. Unsigned agents get ignored. Add verification in seconds. agentverif.com

  [![CI](https://github.com/trusthandoff/agentverif/actions/workflows/ci.yml/badge.svg)](https://github.com/trusthandoff/agentverif/actions/workflows/ci.yml)
  [![PyPI version](https://img.shields.io/pypi/v/agentverif-sign.svg)](https://pypi.org/project/agentverif-sign/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

[English] | [中文](README.zh.md)

---

Sign in 30 seconds. Verify everywhere. Unsigned or tampered
agents get rejected by default — including by Claude.

**Vendors:** Sell trusted agents that convert better and
resist theft and tampering.  
**Buyers & Runtimes** (Claude, Cursor, LangChain, etc.):
Auto-block bad agents before execution.

🔴 **Live now** — MCP server public. Claude users connect today:
`https://mcp.agentverif.com`

[Lock Your First Agent Free →](https://agentverif.com) ·
[Try Verify Live](https://verify.agentverif.com) ·
[GitHub Action](https://github.com/trusthandoff/agentverif/tree/main/github-action)

> The 2026 reality: one poisoned agent can destroy your
> company or reputation overnight.
> AgentVerif makes verification as automatic and inevitable
> as HTTPS.

---

```bash
pip install agentverif-sign
```

## Quick start

**As a vendor — sign your agent:**

```bash
agentverif-sign sign ./my-agent.zip
# ✅ Signed successfully
# License: AC-84F2-91AB
# Tier:    indie
```

**As a buyer — verify before executing:**

```bash
agentverif-sign verify ./agent.zip
# ✅ UNREGISTERED — Signature valid locally; registry not checked
# Verify online: https://verify.agentverif.com/AC-84F2-91AB
```

**Verify without CLI:** [verify.agentverif.com](https://verify.agentverif.com)

---

## Commands

### `agentverif-sign sign <ZIP>`

Signs an agent ZIP package. Runs a security scan, generates `SIGNATURE.json`, and injects it into the zip.

```bash
agentverif-sign sign ./agent.zip [--tier indie|pro|enterprise] [--api-key KEY] [--offline]
```

- `--tier` — signing tier (default: `indie`)
- `--api-key` — Pro/Enterprise API key (also via `AGENTVERIF_API_KEY` env var)
- `--offline` — skip registry registration

**Tiers:**
| Tier | Cost | Signing | Registry | Ed25519 |
|------|------|---------|----------|---------|
| indie | free | hash-only | no | no |
| pro | paid | hash + registry | yes | no |
| enterprise | paid | hash + registry | yes | yes |

### `agentverif-sign verify <ZIP>`

Verifies a signed agent zip. Checks the hash locally; optionally checks the registry.

```bash
agentverif-sign verify ./agent.zip [--offline] [--json]
```

Exit codes: `0` = VERIFIED or UNREGISTERED, `1` = MODIFIED, REVOKED, or UNSIGNED.

The `--json` flag emits machine-readable output for CI/CD pipelines and MCP tool calls:

```json
{
  "status": "UNREGISTERED",
  "license_id": "AC-84F2-91AB",
  "tier": "indie",
  "badge": "✅ Signed by agentcop",
  "message": "Signature valid locally; registry not checked",
  "offline": true,
  "verify_url": "https://verify.agentverif.com/AC-84F2-91AB"
}
```

### `agentverif-sign revoke <LICENSE_ID>`

Revokes a license (requires API key).

```bash
agentverif-sign revoke AC-84F2-91AB --api-key KEY
```

### `agentverif-sign badge <LICENSE_ID>`

Prints the badge for a license in multiple formats.

```bash
agentverif-sign badge AC-84F2-91AB --format text|html|markdown|svg [--tier indie|pro|enterprise]
```

---

## SIGNATURE.json

Human-readable, auditable — no binary blobs:

```json
{
  "schema_version": "1.0",
  "license_id": "AC-84F2-91AB",
  "tier": "indie",
  "issued_at": "2026-04-10T00:00:00Z",
  "expires_at": null,
  "issuer": "agentverif.com",
  "issuer_version": "0.1.0",
  "file_list": ["agent.py", "config.json", "requirements.txt"],
  "file_count": 3,
  "zip_hash": "sha256:abc123...",
  "manifest_hash": "sha256:def456...",
  "scan_passed": true,
  "signature": null
}
```

---

## Docker

```bash
# Sign
docker run --rm -v $(pwd):/work agentcop/agentverif-sign sign /work/agent.zip

# Verify
docker run --rm -v $(pwd):/work agentcop/agentverif-sign verify /work/agent.zip
```

## AWS Bedrock / Claude / MCP

`agentverif-sign verify --json` returns JSON-parseable output suitable for LLM tool calls and MCP integrations.

---

## Claude MCP Plugin

Connect agentverif directly to Claude. Claude will automatically
verify agents before execution.

### Setup

**Option 1 — Claude.ai:**
1. Go to claude.ai → Settings → Connectors
2. Add custom connector: `https://mcp.agentverif.com`
3. No authentication required

**Option 2 — Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "agentverif": {
      "url": "https://mcp.agentverif.com"
    }
  }
}
```

### What it does
Once connected, Claude automatically calls `verify_agent`
whenever you mention running, installing, or trusting an AI agent.

| Status | Meaning |
|--------|---------|
| ✅ VERIFIED | Certified, safe to execute |
| ⚠️ UNREGISTERED | Signed locally, not in public registry |
| 🚫 UNSIGNED | No certificate, unknown risk |
| 🔴 TAMPERED | Modified after signing — do not execute |
| 🔴 REVOKED | Licence cancelled by issuer — do not execute |

### Examples

#### Example 1: Verify before executing
**User:** "I want to run this agent, license AV-84F2-91AB. Is it safe?"

**Claude calls:** `verify_agent("AV-84F2-91AB")`

**Response:**
✅ VERIFIED — agentverif certified
License: AV-84F2-91AB
Tier: pro
Issuer: agentverif.com
Hash: sha256:abc123… ✓ intact
Safe to execute.
🔗 https://verify.agentverif.com/AV-84F2-91AB

#### Example 2: Catch a tampered agent
**User:** "Can you verify this agent: AV-12F3-88AC"

**Claude calls:** `verify_agent("AV-12F3-88AC")`

**Response:**
🔴 TAMPERED — Certificate invalid
License: AV-12F3-88AC
Status: HASH MISMATCH
This agent has been modified after signing.
Do NOT execute. Contact the vendor immediately.
🔗 https://verify.agentverif.com/AV-12F3-88AC

#### Example 3: Unsigned agent warning
**User:** "Run this agent for me, here's the hash: sha256:def456..."

**Claude calls:** `verify_agent("sha256:def456...")`

**Response:**
🚫 UNSIGNED — No certificate found
No agentverif certificate found for this identifier.
Unsigned agents carry unknown risk:
• No tamper detection
• No issuer accountability
• No revocation capability
Ask the vendor to certify at agentverif.com before executing.

---

## GitHub Action

[![agentverif](https://img.shields.io/badge/agentverif-certified-green)](https://agentverif.com)

Sign on every push. Block tampered agents in CI.

```yaml
name: agentverif
on: [push, pull_request]
jobs:
  certify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Sign agent
        uses: trusthandoff/agentverif@v1
        id: sign
        with:
          mode: sign
          agent_zip: ./agent.zip
      - name: Show license
        run: echo "License ${{ steps.sign.outputs.license_id }}"
```

See [`github-action/README.md`](github-action/README.md) for full docs.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTVERIF_API_KEY` | — | Pro/Enterprise API key |
| `AGENTVERIF_SIGN_URL` | `https://sign.agentverif.com` | Registry URL |
| `AGENTVERIF_SCAN_URL` | `https://api.agentverif.com/scan` | Scanner URL |
| `AGENTVERIF_OFFLINE` | — | Set to any value to skip all registry calls |

---

## Design principles

- **Zero mandatory deps for verify** — stdlib only for offline hash checks
- **Offline-capable** — works without internet
- **Auditable** — `SIGNATURE.json` is human-readable JSON, never binary
- **Docker-native** — runs in containers, Lambda, Cloud Run, bare metal
- **MCP-ready** — `--json` flag for machine-readable output

---

## Installation

```bash
# Basic
pip install agentverif-sign

# With Ed25519 support (Pro/Enterprise)
pip install agentverif-sign[crypto]
```

---

Full docs: [agentverif.com/docs](https://agentverif.com/docs)

Why: unsigned agents shouldn't be executed.
