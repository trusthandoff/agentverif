"""Tests for Docker-readiness and MCP/JSON interface compatibility."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from click.testing import CliRunner

from agentverif_sign import signer
from agentverif_sign.cli import main
from agentverif_sign.models import ScanResult


def _signed_zip(tmp_path: Path) -> Path:
    p = tmp_path / "agent.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("agent.py", "print('docker')\n")
    scan = ScanResult(score=90, passed=True)
    record = signer.sign_zip(str(p), scan_result=scan)
    signer.inject_signature(str(p), record)
    return p


def test_signature_json_is_valid_json(tmp_path: Path):
    p = _signed_zip(tmp_path)
    with zipfile.ZipFile(str(p), "r") as zf:
        raw = zf.read("SIGNATURE.json")
    parsed = json.loads(raw)
    assert isinstance(parsed, dict)


def test_signature_json_human_readable(tmp_path: Path):
    """SIGNATURE.json must be pretty-printed, not a single line blob."""
    p = _signed_zip(tmp_path)
    with zipfile.ZipFile(str(p), "r") as zf:
        raw = zf.read("SIGNATURE.json").decode()
    assert "\n" in raw
    assert "  " in raw  # indented


def test_signature_json_required_fields(tmp_path: Path):
    p = _signed_zip(tmp_path)
    with zipfile.ZipFile(str(p), "r") as zf:
        data = json.loads(zf.read("SIGNATURE.json"))
    required = {
        "schema_version",
        "license_id",
        "tier",
        "issued_at",
        "issuer",
        "file_list",
        "file_count",
        "zip_hash",
        "manifest_hash",
        "scan_passed",
    }
    assert required.issubset(data.keys())


def test_verify_json_flag_mcp_compatible(tmp_path: Path):
    """--json output must be a single parseable JSON object."""
    runner = CliRunner()
    p = _signed_zip(tmp_path)
    result = runner.invoke(main, ["verify", str(p), "--offline", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "status" in data
    assert "license_id" in data
    assert "verify_url" in data


def test_verify_json_unsigned_parseable(tmp_path: Path):
    p = tmp_path / "unsigned.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("a.py", "")
    runner = CliRunner()
    result = runner.invoke(main, ["verify", str(p), "--offline", "--json"])
    data = json.loads(result.output)
    assert data["status"] == "UNSIGNED"


def test_verify_url_in_json_output(tmp_path: Path):
    p = _signed_zip(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["verify", str(p), "--offline", "--json"])
    data = json.loads(result.output)
    assert data.get("verify_url") is not None
    assert "verify.agentverif.com" in data["verify_url"]
