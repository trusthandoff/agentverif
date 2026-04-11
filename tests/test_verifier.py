"""Tests for verifier.py."""

from __future__ import annotations

import zipfile
from pathlib import Path

from agentverif_sign import signer, verifier
from agentverif_sign.models import ScanResult


def _make_signed_zip(tmp_path: Path, tier: str = "indie") -> Path:
    p = tmp_path / f"agent_{tier}.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("agent.py", "print('hi')\n")
    scan = ScanResult(score=90, passed=True, tier=tier)
    record = signer.sign_zip(str(p), tier=tier, scan_result=scan)
    signer.inject_signature(str(p), record)
    return p


# ---------------------------------------------------------------------------
# extract_signature
# ---------------------------------------------------------------------------


def test_extract_signature_returns_record(signed_zip: Path):
    record = verifier.extract_signature(str(signed_zip))
    assert record is not None
    assert record.schema_version == "1.0"


def test_extract_signature_none_when_unsigned(tmp_zip: Path):
    record = verifier.extract_signature(str(tmp_zip))
    assert record is None


def test_extract_signature_none_when_malformed(tmp_path: Path):
    p = tmp_path / "bad.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("SIGNATURE.json", "not json {{{")
    record = verifier.extract_signature(str(p))
    assert record is None


# ---------------------------------------------------------------------------
# verify_zip — offline / local
# ---------------------------------------------------------------------------


def test_verify_zip_unregistered_offline(tmp_path: Path):
    p = _make_signed_zip(tmp_path)
    result = verifier.verify_zip(str(p), offline=True)
    assert result.status == "UNREGISTERED"
    assert result.offline is True


def test_verify_zip_unsigned(tmp_zip: Path):
    result = verifier.verify_zip(str(tmp_zip), offline=True)
    assert result.status == "UNSIGNED"
    assert result.license_id is None
    assert result.badge is None


def test_verify_zip_modified(tmp_path: Path):
    p = _make_signed_zip(tmp_path)
    # Tamper: add a file after signing
    with zipfile.ZipFile(str(p), "a") as zf:
        zf.writestr("malware.py", "import os; os.system('rm -rf /')")
    result = verifier.verify_zip(str(p), offline=True)
    assert result.status == "MODIFIED"


def test_verify_zip_verify_url_present(tmp_path: Path):
    p = _make_signed_zip(tmp_path)
    result = verifier.verify_zip(str(p), offline=True)
    assert result.verify_url is not None
    assert "verify.agentverif.com" in result.verify_url


def test_verify_zip_badge_present_when_valid(tmp_path: Path):
    p = _make_signed_zip(tmp_path)
    result = verifier.verify_zip(str(p), offline=True)
    assert result.badge is not None


def test_verify_zip_no_badge_when_modified(tmp_path: Path):
    p = _make_signed_zip(tmp_path)
    with zipfile.ZipFile(str(p), "a") as zf:
        zf.writestr("extra.txt", "tamper")
    result = verifier.verify_zip(str(p), offline=True)
    assert result.badge is None


def test_verify_zip_tier_preserved(tmp_path: Path):
    p = _make_signed_zip(tmp_path, tier="pro")
    result = verifier.verify_zip(str(p), offline=True)
    assert result.tier == "pro"


def test_verify_zip_registry_unreachable_falls_back(tmp_path: Path):
    p = _make_signed_zip(tmp_path)
    # Use an obviously unreachable URL, should gracefully fall back
    result = verifier.verify_zip(str(p), offline=False, sign_url="http://127.0.0.1:19999")
    assert result.status == "UNREGISTERED"
    assert result.offline is True
