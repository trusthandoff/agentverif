"""Tests for client.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agentverif_sign import client
from agentverif_sign.models import SignatureRecord


def _make_record() -> SignatureRecord:
    return SignatureRecord(
        schema_version="1.0",
        license_id="AC-AABB-CCDD",
        tier="indie",
        issued_at="2026-04-10T00:00:00Z",
        expires_at=None,
        issuer="agentverif.com",
        issuer_version="0.1.0",
        file_list=["agent.py"],
        file_count=1,
        zip_hash="sha256:abc",
        manifest_hash="sha256:def",
        scan_passed=True,
        signature=None,
    )


def _mock_response(json_data: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.status_code = status_code
    resp.raise_for_status.return_value = None
    return resp


# ---------------------------------------------------------------------------
# register
# ---------------------------------------------------------------------------


def test_register_success():
    record = _make_record()
    mock_resp = _mock_response({"license_id": "AC-AABB-CCDD"})
    with patch("requests.request", return_value=mock_resp):
        lid = client.register(record, "https://sign.agentverif.com")
    assert lid == "AC-AABB-CCDD"


def test_register_returns_registry_id():
    record = _make_record()
    mock_resp = _mock_response({"license_id": "AC-SERVER-ASSIGNED"})
    with patch("requests.request", return_value=mock_resp):
        lid = client.register(record, "https://sign.agentverif.com")
    assert lid == "AC-SERVER-ASSIGNED"


def test_register_with_api_key_sends_auth():
    record = _make_record()
    mock_resp = _mock_response({"license_id": "AC-AABB-CCDD"})
    with patch("requests.request", return_value=mock_resp) as mock_req:
        client.register(record, "https://sign.agentverif.com", api_key="secret")
    headers = mock_req.call_args.kwargs.get("headers", {})
    assert "Authorization" in headers
    assert "secret" in headers["Authorization"]


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_verify_success():
    mock_resp = _mock_response(
        {
            "status": "VERIFIED",
            "tier": "pro",
            "message": "valid",
        }
    )
    with patch("requests.request", return_value=mock_resp):
        result = client.verify("AC-1234-ABCD", "sha256:abc", "https://sign.agentverif.com")
    assert result.status == "VERIFIED"
    assert result.tier == "pro"
    assert result.verify_url == "https://verify.agentverif.com/AC-1234-ABCD"


def test_verify_revoked():
    mock_resp = _mock_response({"status": "REVOKED", "tier": "pro", "message": "revoked"})
    with patch("requests.request", return_value=mock_resp):
        result = client.verify("AC-1234-ABCD", "sha256:abc", "https://sign.agentverif.com")
    assert result.status == "REVOKED"


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------


def test_revoke_success():
    mock_resp = _mock_response({"revoked": True})
    with patch("requests.request", return_value=mock_resp):
        ok = client.revoke("AC-1234-ABCD", "mykey", "https://sign.agentverif.com")
    assert ok is True


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------


def test_health_true():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("requests.get", return_value=mock_resp):
        assert client.health("https://sign.agentverif.com") is True


def test_health_false_on_connection_error():
    import requests as req

    with patch("requests.get", side_effect=req.exceptions.ConnectionError()):
        assert client.health("https://sign.agentverif.com") is False


def test_health_false_on_500():
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    with patch("requests.get", return_value=mock_resp):
        assert client.health("https://sign.agentverif.com") is False


# ---------------------------------------------------------------------------
# Retry / offline graceful degradation
# ---------------------------------------------------------------------------


def test_register_retries_on_connection_error():
    import requests as req

    record = _make_record()
    mock_resp = _mock_response({"license_id": "AC-AABB-CCDD"})
    call_count = 0

    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise req.exceptions.ConnectionError("fail")
        return mock_resp

    with patch("requests.request", side_effect=side_effect), patch("time.sleep"):
        lid = client.register(record, "https://sign.agentverif.com")
    assert lid == "AC-AABB-CCDD"
    assert call_count == 2


def test_register_raises_after_max_retries():
    import requests as req

    record = _make_record()
    with (
        patch("requests.request", side_effect=req.exceptions.ConnectionError("always")),
        patch("time.sleep"),
        pytest.raises(req.exceptions.ConnectionError),
    ):
        client.register(record, "https://sign.agentverif.com")
