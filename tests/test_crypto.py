"""Tests for crypto.py — Ed25519 abstraction."""
from __future__ import annotations

import pytest

from agentcop_sign import crypto


def test_is_available_returns_bool():
    result = crypto.is_available()
    assert isinstance(result, bool)


@pytest.mark.skipif(not crypto.is_available(), reason="cryptography not installed")
def test_generate_keypair():
    priv, pub = crypto.generate_keypair()
    assert len(priv) == 32
    assert len(pub) == 32


@pytest.mark.skipif(not crypto.is_available(), reason="cryptography not installed")
def test_sign_returns_ed25519_prefix():
    priv, _ = crypto.generate_keypair()
    sig = crypto.sign(b"hello world", priv)
    assert sig.startswith("ed25519:")


@pytest.mark.skipif(not crypto.is_available(), reason="cryptography not installed")
def test_verify_signature_valid():
    priv, pub = crypto.generate_keypair()
    data = b"test payload"
    sig = crypto.sign(data, priv)
    assert crypto.verify_signature(data, sig, pub) is True


@pytest.mark.skipif(not crypto.is_available(), reason="cryptography not installed")
def test_verify_signature_invalid_data():
    priv, pub = crypto.generate_keypair()
    sig = crypto.sign(b"original", priv)
    assert crypto.verify_signature(b"tampered", sig, pub) is False


@pytest.mark.skipif(not crypto.is_available(), reason="cryptography not installed")
def test_verify_signature_bad_prefix():
    _, pub = crypto.generate_keypair()
    assert crypto.verify_signature(b"data", "rsa:deadbeef", pub) is False


def test_generate_keypair_raises_without_crypto(monkeypatch):
    monkeypatch.setattr(crypto, "_CRYPTO_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="agentcop-sign\\[crypto\\]"):
        crypto.generate_keypair()


def test_sign_raises_without_crypto(monkeypatch):
    monkeypatch.setattr(crypto, "_CRYPTO_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="agentcop-sign\\[crypto\\]"):
        crypto.sign(b"data", b"\x00" * 32)
