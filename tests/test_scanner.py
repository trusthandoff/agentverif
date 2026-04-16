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


# ---------------------------------------------------------------------------
# Retry logic (T1–T3)
# ---------------------------------------------------------------------------


def _make_http_error_resp(status_code: int):
    """Return a mock response whose raise_for_status() raises HTTPError(status)."""
    import requests as req

    resp = MagicMock()
    resp.status_code = status_code
    err = req.exceptions.HTTPError(response=resp)
    resp.raise_for_status.side_effect = err
    return resp


def test_scan_zip_retry_429_succeeds_on_third_attempt(tmp_zip: Path):
    mock_ok = MagicMock()
    mock_ok.json.return_value = {"score": 80, "violations": [], "tier": "indie"}
    mock_ok.raise_for_status.return_value = None

    with patch("requests.post", side_effect=[_make_http_error_resp(429), _make_http_error_resp(429), mock_ok]):
        with patch("time.sleep") as mock_sleep:
            result = scanner.scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")

    assert result.source == "real"
    assert result.score == 80
    assert result.passed is True
    assert mock_sleep.call_count == 2


def test_scan_zip_connection_error_immediate_fallback(tmp_zip: Path):
    import requests as req

    with patch("requests.post", side_effect=req.exceptions.ConnectionError("unreachable")):
        with patch("time.sleep") as mock_sleep:
            result = scanner.scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")

    assert result.source == "offline_fallback"
    assert result.passed is True
    assert mock_sleep.call_count == 0


def test_scan_zip_503_all_retries_exhausted_fallback(tmp_zip: Path):
    side_effects = [_make_http_error_resp(503)] * 3

    with patch("requests.post", side_effect=side_effects):
        with patch("time.sleep") as mock_sleep:
            result = scanner.scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")

    assert result.source == "offline_fallback"
    assert result.passed is True
    assert mock_sleep.call_count == 2
