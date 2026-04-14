"""LangChain tool integration for agentverif-sign.

Provides a ``StructuredTool`` that lets any LangChain agent verify a signed
AI-agent package by license ID or zip path.

Usage::

    from agentverif_sign.langchain_tool import verify_tool

    result = verify_tool.invoke({"license_id": "INDIE-abc123"})
    # or
    result = verify_tool.invoke({"zip_path": "/path/to/agent.zip"})

Requires ``langchain-core`` (or the full ``langchain`` package).  If neither
is installed the module still imports cleanly — ``verify_tool`` will be
``None`` and ``LANGCHAIN_AVAILABLE`` will be ``False``.
"""

from __future__ import annotations

from typing import Optional

__all__ = ["verify_tool", "LANGCHAIN_AVAILABLE", "run_verify"]


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
                    (e.g. ``"INDIE-a1b2c3"``).
        zip_path: Local filesystem path to a signed ``.zip`` agent package.
        offline: When ``True`` skips the remote registry check.

    Returns:
        A one-line human-readable status string, e.g.::

            "✅ VERIFIED — Signature valid. Tier: pro | ID: INDIE-a1b2c3"
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
        # Registry-only lookup: build a minimal offline check is not possible
        # without the zip, so query the registry directly.
        from agentverif_sign import client

        try:
            # We don't have the hash when given only a license_id;
            # pass empty string — the server returns the stored status.
            result = client.verify(license_id, "", "https://sign.agentverif.com")
        except Exception as exc:
            return f"\u274c Registry error: {exc}"

    icon = status_icons.get(result.status, "?")
    parts = [f"{icon} {result.status} \u2014 {result.message}"]
    if result.tier:
        parts.append(f"Tier: {result.tier}")
    if result.license_id:
        parts.append(f"ID: {result.license_id}")
    if result.verify_url:
        parts.append(result.verify_url)
    return " | ".join(parts)


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

except ImportError:
    LANGCHAIN_AVAILABLE = False
    verify_tool = None  # type: ignore[assignment]
