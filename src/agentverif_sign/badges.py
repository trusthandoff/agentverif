"""Badge rendering for three tiers and four formats."""

from __future__ import annotations

import html
from datetime import datetime


def render_badge(
    tier: str | None,
    license_id: str | None = None,
    expires_at: str | None = None,
    fmt: str = "text",
) -> str:
    """Return a badge string for the given tier and format.

    fmt: text | html | markdown | svg
    """
    tier = (tier or "indie").lower()
    if tier == "enterprise":
        return _enterprise_badge(license_id, expires_at, fmt)
    if tier == "pro":
        return _pro_badge(license_id, fmt)
    return _indie_badge(fmt)


# ---------------------------------------------------------------------------
# Indie
# ---------------------------------------------------------------------------


def _indie_badge(fmt: str) -> str:
    text = "Signed by agentverif"
    icon = "\u2705"  # ✅
    if fmt == "text":
        return f"{icon} {text}"
    if fmt == "html":
        return (
            f'<span class="agentverif-badge agentverif-indie">'
            f"{html.escape(icon)} {html.escape(text)}"
            f"</span>"
        )
    if fmt == "markdown":
        return f"![{text}](https://img.shields.io/badge/agentverif-signed-green)"
    if fmt == "svg":
        return _svg_badge("agentverif", "signed", "4c1")
    raise ValueError(f"Unknown format: {fmt}")


# ---------------------------------------------------------------------------
# Pro
# ---------------------------------------------------------------------------


def _pro_badge(license_id: str | None, fmt: str) -> str:
    icon = "\u2705"
    label = "agentverif VERIFIED"
    detail = f"License: {license_id}" if license_id else ""
    if fmt == "text":
        lines = [f"{icon} {label}"]
        if detail:
            lines.append(detail)
        return "\n".join(lines)
    if fmt == "html":
        detail_html = (
            f'<br><small class="agentverif-license">{html.escape(detail)}</small>' if detail else ""
        )
        return (
            f'<span class="agentverif-badge agentverif-pro">'
            f"{html.escape(icon)} {html.escape(label)}"
            f"{detail_html}"
            f"</span>"
        )
    if fmt == "markdown":
        alt = f"{label} {detail}".strip()
        return f"![{alt}](https://img.shields.io/badge/agentverif-VERIFIED-blue)"
    if fmt == "svg":
        return _svg_badge("agentverif", "VERIFIED", "007ec6")
    raise ValueError(f"Unknown format: {fmt}")


# ---------------------------------------------------------------------------
# Enterprise
# ---------------------------------------------------------------------------


def _enterprise_badge(license_id: str | None, expires_at: str | None, fmt: str) -> str:
    icon = "\U0001f510"  # 🔐
    label = "agentverif ENTERPRISE CERTIFIED"
    parts = [f"{icon} {label}"]
    if license_id:
        parts.append(f"License: {license_id}")
    if expires_at:
        try:
            dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            parts.append(f"Valid until: {dt.strftime('%Y-%m-%d')}")
        except ValueError:
            parts.append(f"Valid until: {expires_at}")

    if fmt == "text":
        return "\n".join(parts)
    if fmt == "html":
        inner = "<br>".join(html.escape(p) for p in parts)
        return f'<span class="agentverif-badge agentverif-enterprise">{inner}</span>'
    if fmt == "markdown":
        alt = " | ".join(parts)
        return f"![{alt}](https://img.shields.io/badge/agentverif-ENTERPRISE-gold)"
    if fmt == "svg":
        return _svg_badge("agentverif", "ENTERPRISE", "e4a000")
    raise ValueError(f"Unknown format: {fmt}")


# ---------------------------------------------------------------------------
# SVG helper (shields.io flat style)
# ---------------------------------------------------------------------------


def _svg_badge(label: str, message: str, color: str) -> str:
    label_width = max(len(label) * 7, 60)
    msg_width = max(len(message) * 7, 50)
    total_width = label_width + msg_width + 20
    label_x = (label_width + 10) // 2
    msg_x = label_width + 10 + msg_width // 2
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">\n'
        f'  <linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>\n'
        f'  <rect rx="3" width="{total_width}" height="20" fill="#555"/>\n'
        f'  <rect rx="3" x="{label_width + 10}" width="{msg_width + 10}" height="20" fill="#{color}"/>\n'
        f'  <rect rx="3" width="{total_width}" height="20" fill="url(#s)"/>\n'
        f'  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">\n'
        f'    <text x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{html.escape(label)}</text>\n'
        f'    <text x="{label_x}" y="14">{html.escape(label)}</text>\n'
        f'    <text x="{msg_x}" y="15" fill="#010101" fill-opacity=".3">{html.escape(message)}</text>\n'
        f'    <text x="{msg_x}" y="14">{html.escape(message)}</text>\n'
        f"  </g>\n"
        f"</svg>"
    )
