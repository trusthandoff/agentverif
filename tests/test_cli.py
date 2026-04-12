"""Tests for CLI commands using click's test runner."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from agentverif_sign.cli import main
from agentverif_sign.models import ScanResult


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def fresh_zip(tmp_path: Path) -> Path:
    p = tmp_path / "agent.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("agent.py", "print('hi')\n")
        zf.writestr("config.json", "{}")
    return p


# ---------------------------------------------------------------------------
# sign command
# ---------------------------------------------------------------------------


def _mock_scan_pass():
    return ScanResult(score=90, passed=True, violations=[], tier="indie")


def _mock_scan_fail():
    return ScanResult(score=40, passed=False, violations=[{"rule": "no-secrets"}], tier="indie")


def test_sign_success(runner, fresh_zip):
    with (
        patch("agentverif_sign.scanner.scan_zip", return_value=_mock_scan_pass()),
        patch("agentverif_sign.client.register", side_effect=Exception("offline")),
    ):
        result = runner.invoke(main, ["sign", str(fresh_zip), "--offline"])
    assert result.exit_code == 0
    assert "Signed successfully" in result.output
    assert "License:" in result.output
    assert "verify.agentverif.com" in result.output


def test_sign_scan_failure_exits_1(runner, fresh_zip):
    with patch("agentverif_sign.scanner.scan_zip", return_value=_mock_scan_fail()):
        result = runner.invoke(main, ["sign", str(fresh_zip), "--offline"])
    assert result.exit_code == 1
    assert "Scan failed" in result.output or "Scan failed" in (
        result.output + (result.exception or "")
    )


def test_sign_invalid_zip_exits_1(runner, tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("not a zip")
    result = runner.invoke(main, ["sign", str(bad), "--offline"])
    assert result.exit_code == 1


def test_sign_tier_enterprise(runner, fresh_zip):
    with patch("agentverif_sign.scanner.scan_zip", return_value=_mock_scan_pass()):
        result = runner.invoke(main, ["sign", str(fresh_zip), "--tier", "enterprise", "--offline"])
    assert result.exit_code == 0
    assert "enterprise" in result.output.lower()


def test_sign_injects_signature_json(runner, fresh_zip):
    with patch("agentverif_sign.scanner.scan_zip", return_value=_mock_scan_pass()):
        runner.invoke(main, ["sign", str(fresh_zip), "--offline"])
    with zipfile.ZipFile(str(fresh_zip), "r") as zf:
        assert "SIGNATURE.json" in zf.namelist()


# ---------------------------------------------------------------------------
# verify command
# ---------------------------------------------------------------------------


def _signed_zip(tmp_path: Path, tier: str = "indie") -> Path:
    from agentverif_sign import signer

    p = tmp_path / "s.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("a.py", "x=1")
    scan = ScanResult(score=90, passed=True, tier=tier)
    record = signer.sign_zip(str(p), tier=tier, scan_result=scan)
    signer.inject_signature(str(p), record)
    return p


def test_verify_unsigned_exits_1(runner, fresh_zip):
    result = runner.invoke(main, ["verify", str(fresh_zip), "--offline"])
    assert result.exit_code == 1
    assert "UNSIGNED" in result.output


def test_verify_valid_exits_0(runner, tmp_path):
    p = _signed_zip(tmp_path)
    result = runner.invoke(main, ["verify", str(p), "--offline"])
    assert result.exit_code == 0
    assert "UNREGISTERED" in result.output


def test_verify_modified_exits_1(runner, tmp_path):
    p = _signed_zip(tmp_path)
    with zipfile.ZipFile(str(p), "a") as zf:
        zf.writestr("extra.py", "evil()")
    result = runner.invoke(main, ["verify", str(p), "--offline"])
    assert result.exit_code == 1
    assert "MODIFIED" in result.output


def test_verify_json_output_parseable(runner, tmp_path):
    p = _signed_zip(tmp_path)
    result = runner.invoke(main, ["verify", str(p), "--offline", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "status" in data
    assert "verify_url" in data


def test_verify_shows_verify_url(runner, tmp_path):
    p = _signed_zip(tmp_path)
    result = runner.invoke(main, ["verify", str(p), "--offline"])
    assert "verify.agentverif.com" in result.output


# ---------------------------------------------------------------------------
# revoke command
# ---------------------------------------------------------------------------


def test_revoke_success(runner):
    with patch("agentverif_sign.client.revoke", return_value=True):
        result = runner.invoke(main, ["revoke", "AC-1234-ABCD", "--api-key", "mykey"])
    assert result.exit_code == 0
    assert "revoked" in result.output.lower()


def test_revoke_failure_exits_1(runner):
    with patch("agentverif_sign.client.revoke", side_effect=Exception("forbidden")):
        result = runner.invoke(main, ["revoke", "AC-1234-ABCD", "--api-key", "mykey"])
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# badge command
# ---------------------------------------------------------------------------


def test_badge_text(runner):
    result = runner.invoke(main, ["badge", "AC-1234-ABCD"])
    assert result.exit_code == 0
    assert "agentverif" in result.output.lower()


def test_badge_html(runner):
    result = runner.invoke(main, ["badge", "AC-1234-ABCD", "--format", "html"])
    assert result.exit_code == 0
    assert "<span" in result.output


def test_badge_markdown(runner):
    result = runner.invoke(main, ["badge", "AC-1234-ABCD", "--format", "markdown"])
    assert result.exit_code == 0
    assert "![" in result.output


def test_badge_svg(runner):
    result = runner.invoke(main, ["badge", "AC-1234-ABCD", "--format", "svg"])
    assert result.exit_code == 0
    assert "<svg" in result.output


def test_badge_enterprise_tier(runner):
    result = runner.invoke(
        main,
        [
            "badge",
            "AC-ENT-1234-ABCD",
            "--tier",
            "enterprise",
            "--expires-at",
            "2027-12-31T00:00:00Z",
        ],
    )
    assert result.exit_code == 0
    assert "ENTERPRISE" in result.output
