"""Tests covering all 8 ecosystem fixes.

Each test is independent. Zero broken existing tests.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import sys
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import importlib.util

import pytest

_ROOT = Path(__file__).parent.parent
_API_DIR = str(_ROOT / "api")
_MCP_DIR = str(_ROOT / "mcp")

# mcp/ first so handlers/models resolve from mcp/.
# api/ second for scanner.py (imported by api/server.py internally).
# api/server.py is loaded via importlib to avoid name collision with mcp/server.py.
for _d in (_MCP_DIR, _API_DIR):
    if _d not in sys.path:
        sys.path.append(_d)


def _import_api_server():
    """Load api/server.py by explicit file path; avoids collision with mcp/server.py."""
    key = "_test_api_server"
    if key not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            key, str(_ROOT / "api" / "server.py")
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules[key] = mod
        spec.loader.exec_module(mod)
    return sys.modules[key]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_zip_bytes(content: str = "print('hi')\n") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("agent.py", content)
    buf.seek(0)
    return buf.read()


def _mock_scan_result(
    passed: bool,
    score: int = 85,
    source: str = "real",
    violations: list | None = None,
):
    from agentverif_sign.models import ScanResult

    return ScanResult(
        score=score,
        passed=passed,
        violations=violations or [],
        source=source,
    )


# ---------------------------------------------------------------------------
# FIX 1 — api/server.py: import must succeed without ImportError
# ---------------------------------------------------------------------------


def test_server_py_imports_without_error():
    """api/server.py must import cleanly — no ImportError / ModuleNotFoundError."""
    try:
        mod = _import_api_server()
        assert hasattr(mod, "app")
    except (ImportError, ModuleNotFoundError) as exc:
        pytest.fail(f"server.py import failed: {exc}")


# ---------------------------------------------------------------------------
# FIX 1+2 — server.py source code invariants
# ---------------------------------------------------------------------------


def test_server_py_no_agent_scanner_alias():
    """Scanner import must not use the AgentScanner alias."""
    content = (_ROOT / "api" / "server.py").read_text()
    assert "AgentScanner" not in content


def test_server_py_imports_scanner_directly():
    """server.py must import Scanner by its real name."""
    content = (_ROOT / "api" / "server.py").read_text()
    assert "from scanner import Scanner" in content


def test_server_py_no_message_field_in_violations():
    """f.get('message') must not appear in violations mapping."""
    content = (_ROOT / "api" / "server.py").read_text()
    assert 'f.get("message")' not in content
    assert "f.get('message')" not in content


def test_server_py_violations_include_title():
    """Violations mapping must include 'title' from the scanner."""
    content = (_ROOT / "api" / "server.py").read_text()
    assert '"title"' in content


def test_server_py_violations_include_explanation():
    """Violations mapping must include 'explanation' (the fix text)."""
    content = (_ROOT / "api" / "server.py").read_text()
    assert '"explanation"' in content


def test_server_py_violations_include_cwe():
    """Violations mapping must include 'cwe'."""
    content = (_ROOT / "api" / "server.py").read_text()
    assert '"cwe"' in content


def test_server_py_fix_field_non_empty():
    """The explanation field must fall back to OWASP URL, never empty."""
    content = (_ROOT / "api" / "server.py").read_text()
    assert "owasp.org" in content
    assert '"explanation"' in content


# ---------------------------------------------------------------------------
# FIX 2 — /scan response contains real violation data
# ---------------------------------------------------------------------------


def test_scan_endpoint_returns_200_with_violations():
    """POST /scan returns 200 and violations with title, explanation, cwe."""
    from fastapi.testclient import TestClient

    mod = _import_api_server()
    client = TestClient(mod.app, raise_server_exceptions=False)

    mock_findings = [
        {
            "id": "AGC-001",
            "owasp": "LLM01",
            "cwe": "CWE-20",
            "severity": "critical",
            "title": "Prompt Injection",
            "explanation": "Sanitize all dynamic values before prompt construction.",
            "file": "agent.py",
            "line": 5,
            "code_snippet": "prompt = f'Hello {user_input}'",
            "diff": {"before": "prompt = f'Hello {user_input}'", "after": ""},
        }
    ]
    mock_result = {"score": 50, "findings": mock_findings, "files_analyzed": 1}

    zip_bytes = _make_zip_bytes()
    with patch("scanner.Scanner.scan_zip", return_value=mock_result):
        resp = client.post(
            "/scan",
            files={"file": ("agent.zip", zip_bytes, "application/zip")},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 50
    assert data["passed"] is False
    assert len(data["violations"]) == 1
    v = data["violations"][0]
    assert v["title"] == "Prompt Injection"
    assert v["explanation"] == "Sanitize all dynamic values before prompt construction."
    assert v["cwe"] == "CWE-20"


def test_scan_endpoint_fix_falls_back_to_owasp_url():
    """explanation must be OWASP URL when scanner explanation is empty."""
    from fastapi.testclient import TestClient

    mod = _import_api_server()
    client = TestClient(mod.app, raise_server_exceptions=False)

    mock_findings = [
        {
            "id": "AGC-001",
            "owasp": "LLM02",
            "cwe": "CWE-94",
            "severity": "critical",
            "title": "Dynamic Code Execution",
            "explanation": "",  # empty
            "file": "a.py",
            "line": 1,
            "code_snippet": "eval(x)",
            "diff": {"before": "eval(x)", "after": ""},
        }
    ]
    mock_result = {"score": 75, "findings": mock_findings, "files_analyzed": 1}

    zip_bytes = _make_zip_bytes()
    with patch("scanner.Scanner.scan_zip", return_value=mock_result):
        resp = client.post(
            "/scan",
            files={"file": ("agent.zip", zip_bytes, "application/zip")},
        )

    data = resp.json()
    v = data["violations"][0]
    assert v["explanation"]  # non-empty
    assert "owasp.org" in v["explanation"]


# ---------------------------------------------------------------------------
# FIX 3+4 — ScanResult.source, SignatureRecord.scan_source
# ---------------------------------------------------------------------------


def test_scan_result_source_real_on_success(tmp_zip: Path):
    """ScanResult.source == 'real' when API responds successfully."""
    from agentverif_sign.scanner import scan_zip

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"score": 85, "violations": [], "tier": "indie"}
    mock_resp.raise_for_status.return_value = None
    with patch("requests.post", return_value=mock_resp):
        result = scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")
    assert result.source == "real"


def test_scan_result_source_offline_fallback_on_connection_error(
    tmp_zip: Path, caplog
):
    """ScanResult.source == 'offline_fallback' on ConnectionError; warning logged."""
    import requests as req

    from agentverif_sign.scanner import scan_zip

    with caplog.at_level(logging.WARNING):
        with patch(
            "requests.post", side_effect=req.exceptions.ConnectionError("unreachable")
        ):
            result = scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")

    assert result.source == "offline_fallback"
    assert result.score == 100
    assert result.passed is True
    assert any("offline_fallback" in r.message for r in caplog.records)


def test_scan_result_source_offline_fallback_on_timeout(tmp_zip: Path, caplog):
    """ScanResult.source == 'offline_fallback' on Timeout; warning logged."""
    import requests as req

    from agentverif_sign.scanner import scan_zip

    with caplog.at_level(logging.WARNING):
        with patch(
            "requests.post", side_effect=req.exceptions.Timeout("timed out")
        ):
            result = scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")

    assert result.source == "offline_fallback"
    assert any("offline_fallback" in r.message for r in caplog.records)


def test_scan_result_source_offline_fallback_on_http_error(tmp_zip: Path, caplog):
    """ScanResult.source == 'offline_fallback' on HTTPError; warning logged."""
    import requests as req

    from agentverif_sign.scanner import scan_zip

    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = req.exceptions.HTTPError("403")
    with caplog.at_level(logging.WARNING):
        with patch("requests.post", return_value=mock_resp):
            result = scan_zip(str(tmp_zip), "https://api.agentverif.com/scan")

    assert result.source == "offline_fallback"
    assert any("offline_fallback" in r.message for r in caplog.records)


def test_signature_record_scan_source_real(tmp_zip: Path):
    """SignatureRecord.scan_source == 'real' when scan_result.source == 'real'."""
    from agentverif_sign.models import ScanResult
    from agentverif_sign.signer import sign_zip

    scan = ScanResult(score=90, passed=True, source="real")
    record = sign_zip(str(tmp_zip), tier="indie", scan_result=scan)
    assert record.scan_source == "real"


def test_signature_record_scan_source_offline_fallback(tmp_zip: Path):
    """SignatureRecord.scan_source == 'offline_fallback' from offline scan."""
    from agentverif_sign.models import ScanResult
    from agentverif_sign.signer import sign_zip

    scan = ScanResult(score=100, passed=True, source="offline_fallback")
    record = sign_zip(str(tmp_zip), tier="indie", scan_result=scan)
    assert record.scan_source == "offline_fallback"


def test_signature_record_scan_source_skipped_when_no_scan(tmp_zip: Path):
    """SignatureRecord.scan_source == 'skipped' when scan_result is None."""
    from agentverif_sign.signer import sign_zip

    record = sign_zip(str(tmp_zip), tier="indie", scan_result=None)
    assert record.scan_source == "skipped"


def test_signature_json_contains_scan_source(tmp_zip: Path):
    """SIGNATURE.json must include scan_source field after inject_signature."""
    from agentverif_sign.models import ScanResult
    from agentverif_sign.signer import inject_signature, sign_zip

    scan = ScanResult(score=85, passed=True, source="real")
    record = sign_zip(str(tmp_zip), tier="indie", scan_result=scan)
    inject_signature(str(tmp_zip), record)
    with zipfile.ZipFile(str(tmp_zip), "r") as zf:
        data = json.loads(zf.read("SIGNATURE.json"))
    assert "scan_source" in data
    assert data["scan_source"] == "real"


def test_signature_json_roundtrip_with_scan_source(tmp_zip: Path):
    """from_json(to_json()) must preserve scan_source."""
    from agentverif_sign.models import ScanResult, SignatureRecord
    from agentverif_sign.signer import sign_zip

    scan = ScanResult(score=90, passed=True, source="offline_fallback")
    record = sign_zip(str(tmp_zip), tier="indie", scan_result=scan)
    recovered = SignatureRecord.from_json(record.to_json())
    assert recovered.scan_source == "offline_fallback"


# ---------------------------------------------------------------------------
# FIX 5 — langchain_tool: no inline httpx, uses explanation not message
# ---------------------------------------------------------------------------


def test_langchain_tool_no_inline_httpx_scan():
    """langchain_tool.py must not contain the inline httpx.post scan block."""
    content = (
        _ROOT / "src" / "agentverif_sign" / "langchain_tool.py"
    ).read_text()
    # The old inline scan POSTed directly with httpx inside run_sign
    assert "httpx.post" not in content


def test_langchain_tool_uses_explanation_not_message():
    """langchain_tool.py must use explanation/title for violations, not message."""
    content = (
        _ROOT / "src" / "agentverif_sign" / "langchain_tool.py"
    ).read_text()
    assert 'v.get("message"' not in content
    assert "explanation" in content


def test_langchain_tool_calls_scan_zip(tmp_zip: Path):
    """run_sign must call agentverif_sign.scanner.scan_zip, not httpx directly."""
    from agentverif_sign.langchain_tool import run_sign

    mock_scan = _mock_scan_result(passed=True, score=85)
    with patch("agentverif_sign.scanner.scan_zip", return_value=mock_scan) as mock_sz:
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(
                returncode=0,
                stdout="License: AC-AB12-CD34\nHash: sha256:abc\n",
                stderr="",
            )
            run_sign(str(tmp_zip), tier="indie")
        mock_sz.assert_called_once()


def test_langchain_tool_refused_uses_explanation_text(tmp_zip: Path):
    """run_sign refusal message must contain explanation text, not message field."""
    from agentverif_sign.langchain_tool import run_sign

    violation = {
        "title": "Prompt Injection",
        "explanation": "Sanitize before sending to LLM",
        "message": "WRONG_FIELD_SHOULD_NOT_APPEAR",
    }
    mock_scan = _mock_scan_result(passed=False, score=40, violations=[violation])
    with patch("agentverif_sign.scanner.scan_zip", return_value=mock_scan):
        result = run_sign(str(tmp_zip), tier="indie")
    assert "Sanitize before sending to LLM" in result
    assert "WRONG_FIELD_SHOULD_NOT_APPEAR" not in result


# ---------------------------------------------------------------------------
# FIX 6 — handle_scan_agent
# ---------------------------------------------------------------------------


def _run_handle_scan_agent(zip_url: str, mock_scan_result, http_error=None):
    """Helper: run handle_scan_agent with mocked HTTP + scan."""
    from handlers import handle_scan_agent

    mock_resp = MagicMock()
    mock_resp.content = _make_zip_bytes()
    mock_resp.raise_for_status.return_value = None

    async def _run():
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            if http_error:
                mock_ctx.__aenter__.return_value.get = AsyncMock(
                    side_effect=http_error
                )
            else:
                mock_ctx.__aenter__.return_value.get = AsyncMock(return_value=mock_resp)
            mock_cls.return_value = mock_ctx
            with patch(
                "agentverif_sign.scanner.scan_zip", return_value=mock_scan_result
            ):
                return await handle_scan_agent(zip_url)

    return asyncio.run(_run())


def test_handle_scan_agent_pass_contains_score_and_verdict():
    """PASS result contains score and PASS verdict."""
    result = _run_handle_scan_agent(
        "https://example.com/agent.zip",
        _mock_scan_result(passed=True, score=85),
    )
    assert "85/100" in result
    assert "PASS" in result
    assert "Ready to sign" in result


def test_handle_scan_agent_refused_contains_score_and_violations():
    """REFUSED result contains score, REFUSED verdict, and numbered violations."""
    violations = [
        {
            "title": "Prompt Injection",
            "explanation": "Sanitize inputs",
            "owasp": "LLM01",
            "severity": "critical",
            "file": "agent.py",
            "line": 10,
            "code_snippet": "eval(x)",
        },
        {
            "title": "Hardcoded Secret",
            "explanation": "Use environment variables",
            "owasp": "LLM06",
            "severity": "critical",
            "file": "agent.py",
            "line": 5,
            "code_snippet": "key='abc'",
        },
    ]
    result = _run_handle_scan_agent(
        "https://example.com/agent.zip",
        _mock_scan_result(passed=False, score=50, violations=violations),
    )
    assert "REFUSED" in result
    assert "50/100" in result
    assert "Sanitize inputs" in result
    assert "Use environment variables" in result
    assert "1." in result
    assert "2." in result


def test_handle_scan_agent_offline_fallback_shows_warning():
    """offline_fallback source triggers visible warning in response."""
    result = _run_handle_scan_agent(
        "https://example.com/agent.zip",
        _mock_scan_result(passed=True, score=100, source="offline_fallback"),
    )
    assert "WARNING" in result
    assert "NOT verified" in result


def test_handle_scan_agent_never_raises():
    """handle_scan_agent must return a string even on complete network failure."""
    import httpx

    from handlers import handle_scan_agent

    async def _run():
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.RequestError("boom")
            )
            mock_cls.return_value = mock_ctx
            return await handle_scan_agent("https://example.com/agent.zip")

    result = asyncio.run(_run())
    assert isinstance(result, str)


def test_handle_scan_agent_tempfile_removed_on_scan_exception():
    """Tempfile must be deleted even when scan_zip raises."""
    from handlers import handle_scan_agent

    mock_resp = MagicMock()
    mock_resp.content = _make_zip_bytes()
    mock_resp.raise_for_status.return_value = None

    deleted: list[str] = []
    original_unlink = __import__("os").unlink

    def tracking_unlink(path: str):
        deleted.append(path)
        original_unlink(path)

    async def _run():
        with patch("httpx.AsyncClient") as mock_cls:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value.get = AsyncMock(return_value=mock_resp)
            mock_cls.return_value = mock_ctx
            with patch(
                "agentverif_sign.scanner.scan_zip",
                side_effect=RuntimeError("scan exploded"),
            ):
                with patch("os.unlink", side_effect=tracking_unlink):
                    return await handle_scan_agent("https://example.com/agent.zip")

    result = asyncio.run(_run())
    assert isinstance(result, str)
    # os.unlink was called for cleanup
    assert len(deleted) >= 1


# ---------------------------------------------------------------------------
# FIX 7 — systemd service files contain required env vars
# ---------------------------------------------------------------------------


def test_api_service_has_agentverif_api_key():
    svc = (_ROOT / "systemd" / "agentverif-api.service").read_text()
    assert "AGENTVERIF_API_KEY" in svc


def test_api_service_has_agentverif_scan_url():
    svc = (_ROOT / "systemd" / "agentverif-api.service").read_text()
    assert "AGENTVERIF_SCAN_URL" in svc
    assert "api.agentverif.com/scan" in svc


def test_mcp_service_has_agentverif_scan_url():
    svc = (_ROOT / "mcp" / "agentverif-mcp.service").read_text()
    assert "AGENTVERIF_SCAN_URL" in svc
    assert "api.agentverif.com/scan" in svc


def test_mcp_service_has_agentverif_api_url():
    svc = (_ROOT / "mcp" / "agentverif-mcp.service").read_text()
    assert "AGENTVERIF_API_URL=http://localhost:8090" in svc


# ---------------------------------------------------------------------------
# FIX 8 — scan timeout returns 408, never score=100
# ---------------------------------------------------------------------------


def test_scan_endpoint_timeout_returns_408():
    """POST /scan returns HTTP 408 when scanner exceeds 25s timeout."""
    from fastapi.testclient import TestClient

    mod = _import_api_server()
    client = TestClient(mod.app, raise_server_exceptions=False)
    zip_bytes = _make_zip_bytes()

    with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
        resp = client.post(
            "/scan",
            files={"file": ("agent.zip", zip_bytes, "application/zip")},
        )

    assert resp.status_code == 408
    data = resp.json()
    assert data["passed"] is False
    assert data["score"] is None


def test_scan_endpoint_timeout_never_returns_score_100():
    """Timeout response must not contain score=100 silent pass fallback."""
    from fastapi.testclient import TestClient

    mod = _import_api_server()
    client = TestClient(mod.app, raise_server_exceptions=False)
    zip_bytes = _make_zip_bytes()

    with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
        resp = client.post(
            "/scan",
            files={"file": ("agent.zip", zip_bytes, "application/zip")},
        )
    data = resp.json()
    assert data.get("score") != 100


# ---------------------------------------------------------------------------
# FIX 9 — /register requires Bearer token auth (same as /revoke)
# ---------------------------------------------------------------------------

_VALID_REGISTER_PAYLOAD = {
    "license_id": "AC-AB12-CD34",
    "tier": "indie",
    "zip_hash": "sha256:" + "a" * 64,
    "file_list": ["agent.py"],
    "issued_at": "2026-04-15T00:00:00Z",
}


def test_register_no_auth_returns_401():
    """POST /register without Authorization header must return 401."""
    from fastapi.testclient import TestClient

    mod = _import_api_server()
    client = TestClient(mod.app, raise_server_exceptions=False)
    resp = client.post("/register", json=_VALID_REGISTER_PAYLOAD)
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"


def test_register_wrong_key_returns_401():
    """POST /register with wrong Bearer token must return 401."""
    from fastapi.testclient import TestClient

    mod = _import_api_server()
    client = TestClient(mod.app, raise_server_exceptions=False)
    resp = client.post(
        "/register",
        json=_VALID_REGISTER_PAYLOAD,
        headers={"Authorization": "Bearer wrong-key-totally-fake"},
    )
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"


def test_register_malformed_auth_returns_401():
    """POST /register with malformed auth (no Bearer prefix) must return 401."""
    from fastapi.testclient import TestClient

    mod = _import_api_server()
    client = TestClient(mod.app, raise_server_exceptions=False)
    resp = client.post(
        "/register",
        json=_VALID_REGISTER_PAYLOAD,
        headers={"Authorization": "not-bearer-format"},
    )
    assert resp.status_code == 401


def test_register_correct_key_returns_200():
    """POST /register with correct Bearer token must succeed."""
    from fastapi.testclient import TestClient

    test_key = "test-api-key-for-register"
    mod = _import_api_server()
    with patch.object(mod, "_EXPECTED_KEY", test_key):
        client = TestClient(mod.app, raise_server_exceptions=False)
        resp = client.post(
            "/register",
            json=_VALID_REGISTER_PAYLOAD,
            headers={"Authorization": f"Bearer {test_key}"},
        )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert resp.json().get("license_id") == "AC-AB12-CD34"


def test_scan_endpoint_has_rate_limit_decorator():
    """POST /scan must have a rate limit decorator (10/minute)."""
    content = (_ROOT / "api" / "server.py").read_text()
    lines = content.split("\n")
    for i, line in enumerate(lines):
        if "async def scan_agent" in line:
            context = "\n".join(lines[max(0, i - 4) : i])
            assert "limiter" in context or "limit" in context, (
                f"No @limiter.limit decorator found before scan_agent:\n{context}"
            )
            break
    else:
        pytest.fail("scan_agent function not found in server.py")
