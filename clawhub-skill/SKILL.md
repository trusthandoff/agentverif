---
name: agentverif
description: "OWASP LLM Top 10 security scanner + cryptographic verification for OpenClaw skills — detects prompt injection, credential leaks, and tampered packages before your agent runs them"
homepage: https://agentverif.com
user-invocable: true
metadata: {
  "openclaw": {
    "emoji": "🛡️",
    "badge": "✅ AgentVerif Certified",
    "requires": { "anyBins": ["python3", "python"] }
  }
}
---

# 🛡️ AgentVerif — OWASP Scan + Cryptographic Verification

**AgentVerif** is the trust layer for OpenClaw skills.
Every skill you install or distribute is scanned against the
OWASP LLM Top 10 and cryptographically verified —
so you know it's authentic, unmodified, and safe to run.

The former **AgentCop Sentinel** is now **AgentVerif** —
same battle-tested OWASP scanner, now with cryptographic
signing, tamper detection, and license revocation built in.

Install in one line:
```
npx clawhub@latest install agentverif
```

**Requires agentverif-sign (install once):**
```
pip install agentverif-sign
```
This skill never installs packages automatically.
You stay in control of your environment.

---

## What AgentVerif does

| Layer | What it catches | OWASP |
|-------|----------------|-------|
| **SCAN** | Prompt injection, credential leaks, insecure output, tool-call injection | LLM01, LLM02, LLM06, LLM08 |
| **SIGN** | Cryptographic hash + License ID — proves the skill is yours | — |
| **VERIFY** | Tamper detection — catches modified versions before execution | — |
| **REVOKE** | Kill a license instantly if the skill gets redistributed | — |

---

## Slash commands

### /security scan [--last 1h|24h|7d] [--since ISO]
Scan current session for OWASP LLM Top 10 violations.
Score 0–100. Below 70 = refused. Shows exact violations + fixes.

### /security verify <license_id_or_zip>
Verify a skill certificate against the agentverif.com registry.
Returns: VERIFIED / TAMPERED / UNSIGNED / EXPIRED / REVOKED

### /security sign <zip_path>
Sign a skill ZIP. OWASP scan runs first (score ≥ 70 required).
Injects SIGNATURE.json. Issues a License ID.

### /security revoke <license_id>
Revoke a license. Verification fails immediately for all buyers.
Requires AGENTVERIF_API_KEY environment variable.

### /security status
Agent trust score, active violations, session fingerprint.

### /security report
Full violation report grouped by severity (CRITICAL → ERROR → WARN).

### /security taint-check <text>
Check a string for LLM01 prompt injection. Exit 1 if tainted.

### /security output-check <text>
Check agent output for LLM02 insecure patterns.

### /security diff <session1> <session2>
Compare two scan sessions — highlight regressions.

### /security badge
Get your ✅ AgentVerif Certified badge for your skill listing.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no violations, certificate valid |
| 1 | Violations detected or certificate invalid |
| 2 | Error — agentverif-sign not installed or bad arguments |

---

## Requirements

- OpenClaw ≥ 0.1
- Python ≥ 3.11
- `agentverif-sign >= 0.2.0`:
  `pip install agentverif-sign`

This skill never auto-installs packages.

---

Built by [agentverif.com](https://agentverif.com)
Source: [github.com/trusthandoff/agentverif](https://github.com/trusthandoff/agentverif)
