"""Tests for badges.py — all 3 tiers × 4 formats."""

from __future__ import annotations

import pytest

from agentverif_sign.badges import render_badge

# ---------------------------------------------------------------------------
# Indie
# ---------------------------------------------------------------------------


def test_indie_text():
    b = render_badge("indie", fmt="text")
    assert "Signed by agentcop" in b
    assert "\u2705" in b


def test_indie_html():
    b = render_badge("indie", fmt="html")
    assert "agentcop-indie" in b
    assert "<span" in b


def test_indie_markdown():
    b = render_badge("indie", fmt="markdown")
    assert "![" in b
    assert "agentcop" in b.lower()


def test_indie_svg():
    b = render_badge("indie", fmt="svg")
    assert "<svg" in b
    assert "signed" in b.lower()


# ---------------------------------------------------------------------------
# Pro
# ---------------------------------------------------------------------------


def test_pro_text_no_license():
    b = render_badge("pro", fmt="text")
    assert "VERIFIED" in b


def test_pro_text_with_license():
    b = render_badge("pro", license_id="AC-1234-ABCD", fmt="text")
    assert "AC-1234-ABCD" in b
    assert "VERIFIED" in b


def test_pro_html():
    b = render_badge("pro", license_id="AC-1234-ABCD", fmt="html")
    assert "agentcop-pro" in b
    assert "AC-1234-ABCD" in b


def test_pro_markdown():
    b = render_badge("pro", fmt="markdown")
    assert "VERIFIED" in b
    assert "![" in b


def test_pro_svg():
    b = render_badge("pro", fmt="svg")
    assert "<svg" in b
    assert "VERIFIED" in b


# ---------------------------------------------------------------------------
# Enterprise
# ---------------------------------------------------------------------------


def test_enterprise_text_no_extras():
    b = render_badge("enterprise", fmt="text")
    assert "ENTERPRISE" in b


def test_enterprise_text_with_license():
    b = render_badge("enterprise", license_id="AC-ENT-1234-ABCD", fmt="text")
    assert "AC-ENT-1234-ABCD" in b


def test_enterprise_text_with_expiry():
    b = render_badge("enterprise", expires_at="2027-12-31T00:00:00Z", fmt="text")
    assert "2027-12-31" in b


def test_enterprise_html():
    b = render_badge(
        "enterprise", license_id="AC-ENT-X", expires_at="2027-01-01T00:00:00Z", fmt="html"
    )
    assert "agentcop-enterprise" in b
    assert "AC-ENT-X" in b


def test_enterprise_markdown():
    b = render_badge("enterprise", fmt="markdown")
    assert "ENTERPRISE" in b
    assert "![" in b


def test_enterprise_svg():
    b = render_badge("enterprise", fmt="svg")
    assert "<svg" in b
    assert "ENTERPRISE" in b


# ---------------------------------------------------------------------------
# Default tier
# ---------------------------------------------------------------------------


def test_none_tier_defaults_to_indie():
    b = render_badge(None, fmt="text")
    assert "Signed by agentcop" in b


def test_invalid_format_raises():
    with pytest.raises(ValueError, match="Unknown format"):
        render_badge("indie", fmt="pdf")
