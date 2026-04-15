# agentverif GitHub Action

Certify your AI agent packages automatically.
Sign on every push. Block tampered agents in CI.

## How it works

Every agent goes through three steps before a certificate is issued:

```
SCAN → SIGN → VERIFY
```

**SCAN** — ZIP scanned against the OWASP LLM Top 10. Score below 70: refused.  
**SIGN** — Cryptographic hash generated. `SIGNATURE.json` injected. License ID issued.  
**VERIFY** — Hash and registry checked on every use.

## Usage

### Sign your agent (vendors)
```yaml
- uses: trusthandoff/agentverif@v1
  with:
    mode: sign
    agent_zip: ./my-agent.zip
    tier: indie
```

> **Note:** `mode: sign` always runs the OWASP LLM Top 10 scan first.
> Packages scoring below 70 are refused. The `scan_source` field in
> `SIGNATURE.json` records whether the scan was `real` or `offline_fallback`.

### Verify before deploy (buyers/CI gate)
```yaml
- uses: trusthandoff/agentverif@v1
  with:
    mode: verify
    agent_zip: ./my-agent.zip
    fail_on_unsigned: "true"
```

### Full workflow example
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

## Inputs
| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| mode | yes | verify | sign or verify |
| agent_zip | yes | — | Path to ZIP file |
| tier | no | indie | indie / pro / enterprise |
| api_key | no | — | Pro/Enterprise API key |
| fail_on_unsigned | no | true | Fail build if unsigned |

## Outputs
| Output | Description |
|--------|-------------|
| license_id | Generated license ID |
| status | VERIFIED / UNREGISTERED / UNSIGNED / MODIFIED / REVOKED |
| zip_hash | SHA256 hash of package |

## SIGNATURE.json fields
| Field | Type | Description |
|-------|------|-------------|
| `license_id` | string | Issued license ID (AC-XXXX-XXXX or AC-ENT-XXXX-XXXX) |
| `zip_hash` | string | SHA256 of the agent ZIP |
| `scan_passed` | bool | `true` if OWASP scan score ≥ 70 |
| `scan_source` | string | `real` \| `offline_fallback` \| `skipped` |
| `signature` | string\|null | Ed25519 signature (enterprise only) |

## Free tier
Indie plan is free forever.
Sign up at agentverif.com

## Limitations

This action verifies hash-level integrity for all tiers.
Registry-level checks (revocation status, public listing)
require Pro tier via the CLI.
REVOKED licenses appear as UNREGISTERED in offline mode.
For registry operations: use `agentverif-sign` CLI directly.
