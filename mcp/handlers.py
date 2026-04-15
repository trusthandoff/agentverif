"""Tool handlers for the agentverif MCP server.

All public functions return a human-readable markdown string suitable for
direct delivery to an LLM context.  They never raise — every error path
returns a helpful message instead.
"""

from __future__ import annotations

import asyncio
import os
import re
import tempfile

import httpx

from models import ApiVerifyResponse

_API_BASE = os.getenv("AGENTVERIF_API_URL", "http://localhost:8090")
_TIMEOUT = 5.0
_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _shorten_id(license_id: str) -> str:
    """Return a URL-safe, normalised license ID."""
    return license_id.upper().strip()


def _fmt_verified(r: ApiVerifyResponse) -> str:
    lines = [
        "✅ VERIFIED — agentverif certified",
        f"License: {r.license_id}",
        f"Tier: {r.tier or 'unknown'}",
        f"Issuer: {r.issuer or 'agentverif.com'}",
    ]
    if r.issued_at:
        lines.append(f"Issued: {r.issued_at[:10]}")
    if r.verify_url:
        lines.append("")
        lines.append("This agent has been scanned, signed, and registered. Safe to execute.")
        lines.append(f"🔗 {r.verify_url}")
    return "\n".join(lines)


def _fmt_revoked(r: ApiVerifyResponse) -> str:
    lines = [
        "🔴 REVOKED — Certificate cancelled by issuer",
        f"License: {r.license_id}",
    ]
    if r.revoked_at:
        lines.append(f"Revoked: {r.revoked_at[:10]}")
    if r.revoked_reason:
        lines.append(f"Reason: {r.revoked_reason}")
    lines.append("")
    lines.append("This license has been revoked. Do NOT execute.")
    if r.license_id:
        lines.append(f"🔗 https://verify.agentverif.com/?id={r.license_id}")
    return "\n".join(lines)


def _fmt_redistribution_blocked(r: ApiVerifyResponse) -> str:
    lines = [
        "⚠️ SINGLE-USE LICENSE — Redistribution blocked",
        f"License: {r.license_id}",
        f"Tier: {r.tier or 'unknown'}",
        "",
        "This is a single-use license that has already been activated by another buyer.",
        "Do NOT execute — contact the vendor if you believe this is an error.",
    ]
    if r.license_id:
        lines.append(f"🔗 https://verify.agentverif.com/?id={r.license_id}")
    return "\n".join(lines)


def _fmt_unsigned() -> str:
    return (
        "🚫 UNSIGNED — No certificate found\n"
        "\n"
        "No agentverif certificate found for this identifier.\n"
        "This agent has not been verified.\n"
        "\n"
        "Unsigned agents carry unknown risk:\n"
        "  • No tamper detection\n"
        "  • No issuer accountability\n"
        "  • No revocation capability\n"
        "\n"
        "Ask the vendor to certify at agentverif.com before executing."
    )


def _fmt_sha256_unsigned(sha: str) -> str:
    short = sha[:18] + "…"
    return (
        f"🚫 UNSIGNED — No certificate found for hash {short}\n"
        "\n"
        "No agentverif certificate is linked to this SHA256 hash.\n"
        "This agent has not been registered in the public registry.\n"
        "\n"
        "Unsigned agents carry unknown risk:\n"
        "  • No tamper detection\n"
        "  • No issuer accountability\n"
        "  • No revocation capability\n"
        "\n"
        "Ask the vendor to certify at agentverif.com before executing."
    )


# ---------------------------------------------------------------------------
# API call
# ---------------------------------------------------------------------------


async def _call_api(license_id: str) -> dict | None:
    """Return parsed JSON dict, or None on 404.  Raises httpx errors."""
    url = f"{_API_BASE}/verify/{license_id}"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Public handler
# ---------------------------------------------------------------------------


async def handle_verify_agent(license_id: str) -> str:
    """Verify an agent certificate. Always returns a human-readable string."""

    # ── Format validation ────────────────────────────────────────────────────
    norm = license_id.strip()

    if _SHA256_RE.match(norm.lower()):
        # Hash-based lookup is not yet supported by the registry API.
        return _fmt_sha256_unsigned(norm.lower())

    norm = _shorten_id(norm)

    # ── Registry lookup (with one retry) ────────────────────────────────────
    data: dict | None = None
    last_err: str = ""

    for attempt in range(2):
        try:
            data = await _call_api(norm)
            break
        except httpx.TimeoutException:
            last_err = "timeout"
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code >= 500:
                last_err = f"server error {exc.response.status_code}"
            else:
                last_err = f"HTTP {exc.response.status_code}"
                break
        except httpx.RequestError:
            last_err = "connection error"

    if last_err and data is None:
        if last_err == "timeout":
            return (
                "⏳ agentverif registry temporarily unavailable.\n"
                "Try again in a moment, or verify manually at "
                f"https://verify.agentverif.com/?id={norm}"
            )
        if "server error" in last_err:
            return (
                "⚠️ Verification service error.\n"
                f"Please verify manually at https://verify.agentverif.com/?id={norm}"
            )
        return (
            f"⚠️ Could not reach agentverif registry ({last_err}).\n"
            f"Please verify manually at https://verify.agentverif.com/?id={norm}"
        )

    # ── Not found → UNSIGNED ─────────────────────────────────────────────────
    if data is None:
        return _fmt_unsigned()

    # ── Map API status to output format ──────────────────────────────────────
    try:
        r = ApiVerifyResponse.model_validate(data)
    except Exception:
        return (
            "⚠️ Unexpected response from agentverif registry.\n"
            f"Please verify manually at https://verify.agentverif.com/?id={norm}"
        )

    status = (r.status or "").upper()

    if status == "REVOKED":
        return _fmt_revoked(r)

    if status == "REDISTRIBUTION_BLOCKED":
        return _fmt_redistribution_blocked(r)

    if r.valid and status == "VERIFIED":
        return _fmt_verified(r)

    # Fallback for any future unknown status
    return (
        f"⚠️ Unknown certificate status: {r.status}\n"
        f"Please verify manually at https://verify.agentverif.com/?id={norm}"
    )


async def handle_scan_agent(zip_url: str) -> str:
    """Scan an AI agent ZIP against OWASP LLM Top 10. Always returns a human-readable string."""
    scan_url = os.getenv("AGENTVERIF_SCAN_URL", "https://api.agentverif.com/scan")
    tmp_path: str | None = None

    try:
        # Download the ZIP
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(zip_url)
                resp.raise_for_status()
                zip_bytes = resp.content  # capture inside context manager
            except httpx.TimeoutException:
                return "⏳ ZIP download timed out. Check the URL and try again."
            except httpx.HTTPStatusError as exc:
                return f"❌ Failed to download ZIP: HTTP {exc.response.status_code}"
            except httpx.RequestError as exc:
                return f"❌ Failed to download ZIP: {exc}"

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(zip_bytes)
            tmp_path = tmp.name

        # scan_zip is synchronous/blocking — run in executor
        from agentverif_sign.scanner import scan_zip

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, lambda: scan_zip(tmp_path, scan_url)
        )

        # Format markdown response
        verdict = "PASS ✅" if result.passed else "REFUSED 🔴"
        lines = [f"## Scan Result: Score {result.score}/100 — {verdict}"]

        if result.source == "offline_fallback":
            lines.append("")
            lines.append(
                "⚠️ WARNING: scan API was unreachable. This result is NOT verified."
            )

        if not result.passed:
            lines.append("")
            lines.append("### Violations (fix required before signing):")
            for i, v in enumerate(result.violations, 1):
                title = v.get("title", "Unknown")
                owasp = v.get("owasp", "")
                severity = v.get("severity", "")
                file_ref = v.get("file", "")
                line_num = v.get("line", "")
                explanation = v.get("explanation", v.get("title", ""))
                snippet = v.get("code_snippet", "")
                lines.append("")
                lines.append(f"**{i}. {title}**")
                lines.append(
                    f"   OWASP: {owasp} | Severity: {severity} | {file_ref}:{line_num}"
                )
                lines.append(f"   Fix: {explanation}")
                if snippet:
                    lines.append(f"   Code: `{snippet}`")
        else:
            lines.append("")
            lines.append("Ready to sign at sign.agentverif.com")

        return "\n".join(lines)

    except Exception as exc:
        return f"❌ Scan error: {exc}"
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
