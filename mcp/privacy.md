# Privacy Policy — agentverif MCP Server

**Effective date:** 2026-04-13
**Contact:** hi@agentverif.com

---

## What this service does

The agentverif MCP server allows Claude and other MCP-compatible AI assistants
to look up agent certificates in the agentverif public registry.  When you (or
an AI assistant acting on your behalf) call the `verify_agent` tool, the
server forwards a certificate identifier to the agentverif registry API and
returns the result.

---

## Data collected

| Data | Purpose | Retention |
|------|---------|-----------|
| `license_id` or `sha256:` hash passed to `verify_agent` | Registry lookup | Up to 30 days in server access logs for rate-limiting and abuse prevention |
| Server IP address of the MCP client | Rate limiting | Up to 30 days |

**We do not collect:**
- The content of your conversations with Claude
- Your identity, name, or contact details
- The actual agent ZIP file or its contents
- Any data beyond the identifier you explicitly pass to `verify_agent`

---

## Data sharing

Certificate identifiers (license IDs) are forwarded to the agentverif registry
API running at `http://localhost:8090` (an internal service on the same server).
No data is sent to third parties.

---

## Cookies and tracking

This service sets no cookies and uses no tracking technologies.

---

## Data security

All traffic between your AI assistant and this server is encrypted via HTTPS
(TLS 1.2+).  Internal API calls are made over localhost only.

---

## Your rights

Because we do not collect personally identifiable information, standard data
subject requests (access, deletion) are not applicable.  If you have concerns,
contact hi@agentverif.com.

---

## Changes

We may update this policy.  Material changes will be announced at
agentverif.com.

---

**Contact:** hi@agentverif.com
**Full privacy policy:** https://agentverif.com/privacy
