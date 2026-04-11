"""Shared fixtures for agentcop-sign tests."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_zip(tmp_path: Path) -> Path:
    """A valid zip with two files."""
    p = tmp_path / "agent.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("agent.py", "print('hello')\n")
        zf.writestr("config.json", '{"name": "my-agent"}')
    return p


@pytest.fixture
def empty_zip(tmp_path: Path) -> Path:
    """A zip that exists but contains no members."""
    p = tmp_path / "empty.zip"
    with zipfile.ZipFile(p, "w"):
        pass
    return p


@pytest.fixture
def signed_zip(tmp_path: Path) -> Path:
    """A zip that has already been signed."""
    from agentcop_sign.models import ScanResult
    from agentcop_sign.signer import sign_zip, inject_signature

    p = tmp_path / "signed.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("agent.py", "print('signed')\n")
    scan = ScanResult(score=90, passed=True, violations=[], tier="indie")
    record = sign_zip(str(p), tier="indie", scan_result=scan)
    inject_signature(str(p), record)
    return p
