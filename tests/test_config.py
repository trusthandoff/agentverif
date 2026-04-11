"""Tests for config.py."""

from __future__ import annotations

import pytest

from agentverif_sign.config import Config


def test_config_defaults():
    cfg = Config.from_env()
    assert cfg.sign_url == "https://sign.agentverif.com"
    assert cfg.scan_url == "https://api.agentverif.com/scan"
    assert cfg.offline is False


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("AGENTVERIF_API_KEY", "test-key")
    monkeypatch.setenv("AGENTVERIF_SIGN_URL", "https://custom.sign")
    monkeypatch.setenv("AGENTVERIF_SCAN_URL", "https://custom.scan")
    monkeypatch.setenv("AGENTVERIF_OFFLINE", "1")
    cfg = Config.from_env()
    assert cfg.api_key == "test-key"
    assert cfg.sign_url == "https://custom.sign"
    assert cfg.scan_url == "https://custom.scan"
    assert cfg.offline is True


def test_config_api_key_override(monkeypatch):
    monkeypatch.setenv("AGENTVERIF_API_KEY", "env-key")
    cfg = Config.from_env(api_key="cli-key")
    assert cfg.api_key == "cli-key"


def test_config_offline_absent(monkeypatch):
    monkeypatch.delenv("AGENTVERIF_OFFLINE", raising=False)
    cfg = Config.from_env()
    assert cfg.offline is False


def test_config_is_frozen():
    cfg = Config.from_env()
    with pytest.raises((AttributeError, TypeError)):
        cfg.api_key = "changed"  # type: ignore[misc]
