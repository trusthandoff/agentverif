<div align="center">

<a href="https://agentverif.com"><img src="https://raw.githubusercontent.com/trusthandoff/agentverif/main/logo.svg" alt="AgentVerif" width="80" height="92" /></a>

<h1>AgentVerif</h1>

<p>✅ Sell verified agents. Buyers trust verified packages. Unsigned agents get ignored. Add verification in seconds. <a href="https://agentverif.com">agentverif.com</a></p>

<a href="https://github.com/trusthandoff/agentverif/actions/workflows/publish.yml"><img src="https://github.com/trusthandoff/agentverif/actions/workflows/publish.yml/badge.svg" alt="CI" /></a>
<a href="https://pypi.org/project/agentverif-sign/"><img src="https://img.shields.io/pypi/v/agentverif-sign.svg" alt="PyPI version" /></a>
<a href="https://x.com/agentverif"><img src="https://img.shields.io/badge/follow-%40agentverif-000000?logo=x&logoColor=white" alt="X (Twitter)" /></a>
<a href="https://www.moltbook.com/u/agentverif"><img src="https://img.shields.io/badge/Moltbook-agentverif-7B2FFF?logoColor=white" alt="Moltbook" /></a>

</div>

[English] | [中文](README.zh.md)

---

**agentverif-sign** is the SSL certificate for AI agent distribution. Vendors sign. Buyers verify. The registry is the source of truth.

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
