"""Tool handlers for the agentverif MCP server.

All public functions return a human-readable markdown string suitable for
direct delivery to an LLM context.  They never raise — every error path
returns a helpful message instead.
"""

from __future__ import annotations

import os
import re

import httpx

from models import ApiVerifyResponse

_API_BASE = os.getenv("AGENTVERIF_API_URL", "http://localhost:8090")
_TIMEOUT = 5.0
_LICENSE_RE = re.compile(r"^AV-[A-Z0-9]{4}-[A-Z0-9]{4}$")
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

    if not _LICENSE_RE.match(norm.upper()):
        return (
            "⚠️ Invalid identifier format.\n"
            "License ID must be in format AV-XXXX-XXXX (e.g. AV-84F2-91AB)\n"
            "or a full SHA256 hash prefixed with 'sha256:'."
        )

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
