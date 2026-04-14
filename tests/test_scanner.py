"""Tests for scanner.py."""

from __future__ import annotations

import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentverif_sign import scanner


def test_list_zip_files(tmp_zip: Path):
    files = scanner.list_zip_files(str(tmp_zip))
    assert "agent.py" in files
    assert "config.json" in files


def test_list_zip_files_excludes_signature(signed_zip: Path):
    files = scanner.list_zip_files(str(signed_zip))
    assert "SIGNATURE.json" not in files


def test_list_zip_files_sorted(tmp_path: Path):
    p = tmp_path / "ordered.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("z.py", "")
        zf.writestr("a.py", "")
        zf.writestr("m.py", "")
    files = scanner.list_zip_files(str(p))
    assert files == sorted(files)


def test_scan_zip_passes_on_high_score(tmp_zip: Path):
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"score": 85, "violations": [], "tier": "indie"}
    mock_resp.raise_for_status.return_value = None
    with patch("requests.post", return_value=mock_resp):
        result = scanner.scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")
    assert result.passed is True
    assert result.score == 85


def test_scan_zip_fails_on_low_score(tmp_zip: Path):
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "score": 40,
        "violations": [{"rule": "no-secrets"}, {"rule": "no-exec"}],
        "tier": "indie",
    }
    mock_resp.raise_for_status.return_value = None
    with patch("requests.post", return_value=mock_resp):
        result = scanner.scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")
    assert result.passed is False
    assert len(result.violations) == 2


def test_scan_zip_boundary_score_70(tmp_zip: Path):
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"score": 70, "violations": [], "tier": "indie"}
    mock_resp.raise_for_status.return_value = None
    with patch("requests.post", return_value=mock_resp):
        result = scanner.scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")
    assert result.passed is True


def test_scan_zip_boundary_score_69(tmp_zip: Path):
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"score": 69, "violations": [{"rule": "x"}], "tier": "indie"}
    mock_resp.raise_for_status.return_value = None
    with patch("requests.post", return_value=mock_resp):
        result = scanner.scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")
    assert result.passed is False


def test_scan_zip_offline_fallback_connection_error(tmp_zip: Path):
    import requests as req

    with patch("requests.post", side_effect=req.exceptions.ConnectionError("unreachable")):
        result = scanner.scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")
    assert result.passed is True
    assert result.score == 100


def test_scan_zip_offline_fallback_timeout(tmp_zip: Path):
    import requests as req

    with patch("requests.post", side_effect=req.exceptions.Timeout("timed out")):
        result = scanner.scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")
    assert result.passed is True


def test_scan_zip_http_error_raises(tmp_zip: Path):
    import requests as req

    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = req.exceptions.HTTPError("403")
    with patch("requests.post", return_value=mock_resp):
        result = scanner.scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")
    assert result.passed is True
