"""Tests for signer.py."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from agentverif_sign import signer
from agentverif_sign.models import ScanResult

# ---------------------------------------------------------------------------
# validate_zip
# ---------------------------------------------------------------------------


def test_validate_zip_valid(tmp_zip: Path):
    signer.validate_zip(str(tmp_zip))  # should not raise


def test_validate_zip_not_found(tmp_path: Path):
    with pytest.raises(ValueError, match="not found"):
        signer.validate_zip(str(tmp_path / "missing.zip"))


def test_validate_zip_empty_file(tmp_path: Path):
    p = tmp_path / "zero.zip"
    p.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        signer.validate_zip(str(p))


def test_validate_zip_not_a_zip(tmp_path: Path):
    p = tmp_path / "fake.zip"
    p.write_bytes(b"this is not a zip")
    with pytest.raises(ValueError, match="valid zip"):
        signer.validate_zip(str(p))


def test_validate_zip_empty_archive(empty_zip: Path):
    with pytest.raises(ValueError, match="no files"):
        signer.validate_zip(str(empty_zip))


# ---------------------------------------------------------------------------
# compute_zip_hash
# ---------------------------------------------------------------------------


def test_compute_zip_hash_format(tmp_zip: Path):
    h = signer.compute_zip_hash(str(tmp_zip))
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64


def test_compute_zip_hash_excludes_signature(tmp_zip: Path):
    h_before = signer.compute_zip_hash(str(tmp_zip), exclude={"SIGNATURE.json"})
    # Add SIGNATURE.json and re-check
    with zipfile.ZipFile(str(tmp_zip), "a") as zf:
        zf.writestr("SIGNATURE.json", '{"test": true}')
    h_after = signer.compute_zip_hash(str(tmp_zip), exclude={"SIGNATURE.json"})
    assert h_before == h_after


def test_compute_zip_hash_changes_on_modification(tmp_path: Path):
    p = tmp_path / "a.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("a.py", "x = 1")
    h1 = signer.compute_zip_hash(str(p))
    with zipfile.ZipFile(p, "a") as zf:
        zf.writestr("b.py", "y = 2")
    h2 = signer.compute_zip_hash(str(p))
    assert h1 != h2


# ---------------------------------------------------------------------------
# compute_manifest_hash
# ---------------------------------------------------------------------------


def test_compute_manifest_hash_format():
    h = signer.compute_manifest_hash(["a.py", "b.json"])
    assert h.startswith("sha256:")


def test_compute_manifest_hash_order_invariant():
    h1 = signer.compute_manifest_hash(["b.json", "a.py"])
    h2 = signer.compute_manifest_hash(["a.py", "b.json"])
    assert h1 == h2


# ---------------------------------------------------------------------------
# sign_zip
# ---------------------------------------------------------------------------


def test_sign_zip_returns_record(tmp_zip: Path):
    scan = ScanResult(score=90, passed=True)
    record = signer.sign_zip(str(tmp_zip), tier="indie", scan_result=scan)
    assert record.tier == "indie"
    assert record.zip_hash.startswith("sha256:")
    assert record.issuer == "agentverif.com"


def test_sign_zip_license_format_indie(tmp_zip: Path):
    record = signer.sign_zip(str(tmp_zip), tier="indie")
    assert record.license_id.startswith("AC-")
    parts = record.license_id.split("-")
    assert len(parts) == 3


def test_sign_zip_license_format_enterprise(tmp_zip: Path):
    record = signer.sign_zip(str(tmp_zip), tier="enterprise")
    assert record.license_id.startswith("AC-ENT-")


def test_sign_zip_scan_passed_true(tmp_zip: Path):
    scan = ScanResult(score=80, passed=True)
    record = signer.sign_zip(str(tmp_zip), scan_result=scan)
    assert record.scan_passed is True


def test_sign_zip_scan_passed_false(tmp_zip: Path):
    scan = ScanResult(score=60, passed=False, violations=[{"rule": "x"}])
    record = signer.sign_zip(str(tmp_zip), scan_result=scan)
    assert record.scan_passed is False


def test_sign_zip_file_list_excludes_signature(tmp_zip: Path):
    with zipfile.ZipFile(str(tmp_zip), "a") as zf:
        zf.writestr("SIGNATURE.json", "{}")
    record = signer.sign_zip(str(tmp_zip))
    assert "SIGNATURE.json" not in record.file_list


# ---------------------------------------------------------------------------
# inject_signature
# ---------------------------------------------------------------------------


def test_inject_signature_adds_to_zip(tmp_zip: Path):
    scan = ScanResult(score=90, passed=True)
    record = signer.sign_zip(str(tmp_zip), scan_result=scan)
    signer.inject_signature(str(tmp_zip), record)
    with zipfile.ZipFile(str(tmp_zip), "r") as zf:
        assert "SIGNATURE.json" in zf.namelist()


def test_inject_signature_valid_json(tmp_zip: Path):
    record = signer.sign_zip(str(tmp_zip))
    signer.inject_signature(str(tmp_zip), record)
    with zipfile.ZipFile(str(tmp_zip), "r") as zf:
        raw = zf.read("SIGNATURE.json")
    parsed = json.loads(raw)
    assert parsed["schema_version"] == "1.0"


def test_inject_signature_replaces_existing(tmp_zip: Path):
    record1 = signer.sign_zip(str(tmp_zip))
    signer.inject_signature(str(tmp_zip), record1)
    record2 = signer.sign_zip(str(tmp_zip))
    signer.inject_signature(str(tmp_zip), record2)
    with zipfile.ZipFile(str(tmp_zip), "r") as zf:
        sigs = [n for n in zf.namelist() if n == "SIGNATURE.json"]
    assert len(sigs) == 1


def test_inject_signature_human_readable(tmp_zip: Path):
    record = signer.sign_zip(str(tmp_zip))
    signer.inject_signature(str(tmp_zip), record)
    with zipfile.ZipFile(str(tmp_zip), "r") as zf:
        raw = zf.read("SIGNATURE.json").decode()
    # Should be pretty-printed (indented)
    assert "\n" in raw
