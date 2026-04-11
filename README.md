# agentcop-sign

The trust layer for AI agent distribution.

[![PyPI version](https://img.shields.io/pypi/v/agentcop-sign.svg)](https://pypi.org/project/agentcop-sign/)
[![CI](https://github.com/agentcop/agentcop-sign/actions/workflows/ci.yml/badge.svg)](https://github.com/agentcop/agentcop-sign/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[English] | [中文](README.zh.md)

---

**agentcop-sign** is the SSL certificate for AI agent distribution. Vendors sign. Buyers verify. The registry is the source of truth.

```bash
pip install agentcop-sign
```

## Quick start

**As a vendor — sign your agent:**

```bash
agentcop-sign sign ./my-agent.zip
# ✅ Signed successfully
# License: AC-84F2-91AB
# Tier:    indie
```

**As a buyer — verify before executing:**

```bash
agentcop-sign verify ./agent.zip
# ✅ UNREGISTERED — Signature valid locally; registry not checked
# Verify online: https://verify.agentcop.live/AC-84F2-91AB
```

**Verify without CLI:** [verify.agentcop.live](https://verify.agentcop.live)

---

## Commands

### `agentcop-sign sign <ZIP>`

Signs an agent ZIP package. Runs a security scan, generates `SIGNATURE.json`, and injects it into the zip.

```bash
agentcop-sign sign ./agent.zip [--tier indie|pro|enterprise] [--api-key KEY] [--offline]
```

- `--tier` — signing tier (default: `indie`)
- `--api-key` — Pro/Enterprise API key (also via `AGENTCOP_API_KEY` env var)
- `--offline` — skip registry registration

**Tiers:**
| Tier | Cost | Signing | Registry | Ed25519 |
|------|------|---------|----------|---------|
| indie | free | hash-only | no | no |
| pro | paid | hash + registry | yes | no |
| enterprise | paid | hash + registry | yes | yes |

### `agentcop-sign verify <ZIP>`

Verifies a signed agent zip. Checks the hash locally; optionally checks the registry.

```bash
agentcop-sign verify ./agent.zip [--offline] [--json]
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
  "verify_url": "https://verify.agentcop.live/AC-84F2-91AB"
}
```

### `agentcop-sign revoke <LICENSE_ID>`

Revokes a license (requires API key).

```bash
agentcop-sign revoke AC-84F2-91AB --api-key KEY
```

### `agentcop-sign badge <LICENSE_ID>`

Prints the badge for a license in multiple formats.

```bash
agentcop-sign badge AC-84F2-91AB --format text|html|markdown|svg [--tier indie|pro|enterprise]
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
  "issuer": "agentcop.live",
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
docker run --rm -v $(pwd):/work agentcop/agentcop-sign sign /work/agent.zip

# Verify
docker run --rm -v $(pwd):/work agentcop/agentcop-sign verify /work/agent.zip
```

## AWS Bedrock / Claude / MCP

`agentcop-sign verify --json` returns JSON-parseable output suitable for LLM tool calls and MCP integrations.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTCOP_API_KEY` | — | Pro/Enterprise API key |
| `AGENTCOP_SIGN_URL` | `https://sign.agentcop.live` | Registry URL |
| `AGENTCOP_SCAN_URL` | `https://agentcop.live/api/scan` | Scanner URL |
| `AGENTCOP_OFFLINE` | — | Set to any value to skip all registry calls |

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
pip install agentcop-sign

# With Ed25519 support (Pro/Enterprise)
pip install agentcop-sign[crypto]
```

---

Full docs: [docs.agentcop.live/guides/agentcop-sign](https://docs.agentcop.live/guides/agentcop-sign)

Why: unsigned agents shouldn't be executed.
