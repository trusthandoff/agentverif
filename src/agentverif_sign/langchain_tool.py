"""LangChain tool integration for agentverif-sign.

Provides a ``StructuredTool`` that lets any LangChain agent verify a signed
AI-agent package by license ID or zip path.

Usage::

    from agentverif_sign.langchain_tool import verify_tool

    result = verify_tool.invoke({"license_id": "AC-84F2-91AB"})
    # or
    result = verify_tool.invoke({"zip_path": "/path/to/agent.zip"})

Requires ``langchain-core`` (or the full ``langchain`` package).  If neither
is installed the module still imports cleanly — ``verify_tool`` will be
``None`` and ``LANGCHAIN_AVAILABLE`` will be ``False``.
"""

from __future__ import annotations

from typing import Optional

__all__ = ["verify_tool", "sign_tool", "LANGCHAIN_AVAILABLE", "run_verify", "run_sign"]


# ---------------------------------------------------------------------------
# Core logic (no langchain dep)
# ---------------------------------------------------------------------------


def run_verify(
    license_id: str = "",
    zip_path: str = "",
    offline: bool = False,
) -> str:
    """Verify an agentverif-signed agent and return a human-readable status.

    Provide *either* ``license_id`` (checks registry) **or** ``zip_path``
    (checks the local file).  If both are supplied ``zip_path`` takes
    precedence.

    Args:
        license_id: The license ID embedded in a signed package
                    (e.g. ``"AC-84F2-91AB"``).
        zip_path: Local filesystem path to a signed ``.zip`` agent package.
        offline: When ``True`` skips the remote registry check.

    Returns:
        A one-line human-readable status string, e.g.::

            "✅ VERIFIED — Signature valid. Tier: pro | ID: AC-84F2-91AB"
    """
    if not license_id and not zip_path:
        return "Error: supply license_id or zip_path"

    status_icons = {
        "VERIFIED": "\u2705",
        "UNREGISTERED": "\u26a0",
        "MODIFIED": "\u26a0",
        "REVOKED": "\u274c",
        "UNSIGNED": "\u274c",
    }

    if zip_path:
        from agentverif_sign.verifier import verify_zip

        try:
            result = verify_zip(zip_path, offline=offline)
        except FileNotFoundError:
            return f"\u274c File not found: {zip_path}"
        except Exception as exc:
            return f"\u274c Verification error: {exc}"
    else:
        if offline:
            return (
                f"\u26a0\ufe0f UNREGISTERED \u2014 Offline mode. "
                f"License ID noted but registry not checked.\nLicense: {license_id}"
            )
        import httpx
        from agentverif_sign.models import VerifyResult

        try:
            resp = httpx.get(
                f"https://api.agentverif.com/verify/{license_id}",
                timeout=5.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            return f"\u274c Registry error: {exc}"
        result = VerifyResult(
            status=data.get("status", "UNREGISTERED"),
            license_id=license_id,
            tier=data.get("tier"),
            badge=None,
            message=data.get("message", ""),
            offline=False,
            verify_url=f"https://verify.agentverif.com/?id={license_id}",
        )

    icon = status_icons.get(result.status, "?")
    parts = [f"{icon} {result.status} \u2014 {result.message}"]
    if result.tier:
        parts.append(f"Tier: {result.tier}")
    if result.license_id:
        parts.append(f"ID: {result.license_id}")
    if result.verify_url:
        parts.append(result.verify_url)
    return " | ".join(parts)


def run_sign(zip_path: str, tier: str = "indie") -> str:
    """Sign an agent ZIP file and return license ID + hash.

    Args:
        zip_path: Path to the agent ZIP file to sign
        tier: Signing tier — indie (free), pro, enterprise

    Returns:
        Human-readable string with license ID, hash, verify URL
    """
    import os

    if not zip_path:
        return "\u274c No ZIP path provided"

    if not os.path.exists(zip_path):
        return f"\u274c File not found: {zip_path}"

    if not zip_path.endswith(".zip"):
        return f"\u274c File must be a .zip: {zip_path}"

    # Step 1 — Scan
    from agentverif_sign.scanner import scan_zip

    scan_result = scan_zip(
        zip_path,
        os.getenv("AGENTVERIF_SCAN_URL", "https://api.agentverif.com/scan"),
    )
    if not scan_result.passed:
        msgs = [v.get("explanation", v.get("title", "")) for v in scan_result.violations[:3]]
        details = "\n".join(f"  \u2022 {m}" for m in msgs) if msgs else ""
        return (
            f"\u274c Scan failed ({scan_result.score}/100) \u2014 agent not certified.\n"
            f"Fix these issues before signing:\n{details}"
        )

    # Step 2 — Sign directly (no subprocess, no double scan)
    from agentverif_sign.signer import inject_signature, sign_zip

    try:
        record = sign_zip(zip_path, tier=tier, scan_result=scan_result)
        inject_signature(zip_path, record)
    except Exception as exc:
        return f"\u274c Signing failed: {exc}"

    zip_hash_short = (record.zip_hash[:28] + "...") if record.zip_hash else "N/A"
    return (
        f"\u2705 SIGNED \u2014 agentverif certified\n"
        f"License: {record.license_id}\n"
        f"Tier: {tier}\n"
        f"Hash: {zip_hash_short}\n"
        f"Verify: https://verify.agentverif.com/?id={record.license_id}"
    )


# ---------------------------------------------------------------------------
# LangChain integration (optional dep)
# ---------------------------------------------------------------------------

try:
    # langchain-core is the canonical package; the full `langchain` package
    # re-exports from it, so either satisfies this import.
    from langchain_core.tools import StructuredTool

    LANGCHAIN_AVAILABLE: bool = True

    verify_tool: Optional[StructuredTool] = StructuredTool.from_function(
        func=run_verify,
        name="agentverif_verify",
        description=(
            "Verify a signed AI-agent package using agentverif. "
            "Supply 'license_id' (the ID from the package) OR 'zip_path' "
            "(local path to the .zip file). Returns a human-readable status "
            "string: VERIFIED, UNREGISTERED, MODIFIED, REVOKED, or UNSIGNED."
        ),
    )

    sign_tool: Optional[StructuredTool] = StructuredTool.from_function(
        func=run_sign,
        name="sign_agent",
        description=(
            "Sign an AI agent ZIP package with agentverif "
            "to generate a cryptographic certificate and license ID. "
            "Input: path to ZIP file. Returns: license ID and verify URL."
        ),
    )

except ImportError:
    LANGCHAIN_AVAILABLE = False
    verify_tool = None  # type: ignore[assignment]
    sign_tool = None  # type: ignore[assignment]
