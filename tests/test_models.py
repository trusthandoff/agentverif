"""Tests for models.py."""
from __future__ import annotations

import json

import pytest

from agentcop_sign.models import SignatureRecord, ScanResult, VerifyResult


# ---------------------------------------------------------------------------
# SignatureRecord
# ---------------------------------------------------------------------------

def _make_record(**overrides) -> SignatureRecord:
    defaults = dict(
        schema_version="1.0",
        license_id="AC-AABB-CCDD",
        tier="indie",
        issued_at="2026-04-10T00:00:00Z",
        expires_at=None,
        issuer="agentcop.live",
        issuer_version="0.1.0",
        file_list=["agent.py"],
        file_count=1,
        zip_hash="sha256:abc",
        manifest_hash="sha256:def",
        scan_passed=True,
        signature=None,
    )
    defaults.update(overrides)
    return SignatureRecord(**defaults)


def test_signature_record_to_dict():
    rec = _make_record()
    d = rec.to_dict()
    assert d["license_id"] == "AC-AABB-CCDD"
    assert d["tier"] == "indie"
    assert d["signature"] is None


def test_signature_record_to_json_is_valid():
    rec = _make_record()
    text = rec.to_json()
    parsed = json.loads(text)
    assert parsed["schema_version"] == "1.0"


def test_signature_record_json_roundtrip():
    rec = _make_record(tier="pro", signature="ed25519:deadbeef")
    recovered = SignatureRecord.from_json(rec.to_json())
    assert recovered == rec


def test_signature_record_from_dict_missing_optional():
    d = _make_record().to_dict()
    del d["expires_at"]
    del d["signature"]
    rec = SignatureRecord.from_dict(d)
    assert rec.expires_at is None
    assert rec.signature is None


def test_signature_record_file_list_preserved():
    rec = _make_record(file_list=["a.py", "b.json", "c.txt"], file_count=3)
    recovered = SignatureRecord.from_json(rec.to_json())
    assert recovered.file_list == ["a.py", "b.json", "c.txt"]


# ---------------------------------------------------------------------------
# VerifyResult
# ---------------------------------------------------------------------------

def test_verify_result_to_dict():
    vr = VerifyResult(
        status="VERIFIED",
        license_id="AC-1234-ABCD",
        tier="pro",
        badge="badge text",
        message="ok",
        offline=False,
        verify_url="https://verify.agentcop.live/AC-1234-ABCD",
    )
    d = vr.to_dict()
    assert d["status"] == "VERIFIED"
    assert d["verify_url"].endswith("AC-1234-ABCD")


def test_verify_result_to_json_parseable():
    vr = VerifyResult(
        status="UNSIGNED",
        license_id=None,
        tier=None,
        badge=None,
        message="no sig",
        offline=True,
        verify_url=None,
    )
    data = json.loads(vr.to_json())
    assert data["status"] == "UNSIGNED"
    assert data["license_id"] is None


def test_verify_result_all_statuses():
    for status in ("VERIFIED", "MODIFIED", "REVOKED", "UNREGISTERED", "UNSIGNED"):
        vr = VerifyResult(status=status, license_id=None, tier=None, badge=None, message="", offline=False)
        assert vr.to_dict()["status"] == status


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------

def test_scan_result_passed():
    sr = ScanResult(score=80, passed=True, violations=[], tier="indie")
    assert sr.passed is True


def test_scan_result_failed():
    sr = ScanResult(score=50, passed=False, violations=[{"rule": "no-secrets"}], tier="indie")
    assert sr.passed is False
    assert len(sr.violations) == 1


def test_scan_result_to_dict():
    sr = ScanResult(score=90, passed=True, violations=[], tier="pro")
    d = sr.to_dict()
    assert d["score"] == 90
    assert d["tier"] == "pro"


def test_scan_result_default_violations():
    sr = ScanResult(score=70, passed=True)
    assert sr.violations == []
