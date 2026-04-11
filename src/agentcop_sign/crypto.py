"""Ed25519 signing abstraction — cryptography package is optional."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_CRYPTO_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    _CRYPTO_AVAILABLE = True
except ImportError:
    logger.debug("cryptography package not installed; Ed25519 signing unavailable")


def is_available() -> bool:
    """Return True if Ed25519 signing is available."""
    return _CRYPTO_AVAILABLE


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_key_bytes, public_key_bytes) as raw bytes."""
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "Install agentcop-sign[crypto] to use Ed25519 signing: "
            "pip install agentcop-sign[crypto]"
        )
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_bytes, public_bytes


def sign(data: bytes, private_key_bytes: bytes) -> str:
    """Sign data with Ed25519 private key; return 'ed25519:<hex>'."""
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "Install agentcop-sign[crypto] to use Ed25519 signing: "
            "pip install agentcop-sign[crypto]"
        )
    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig = key.sign(data)
    return f"ed25519:{sig.hex()}"


def verify_signature(data: bytes, signature_str: str, public_key_bytes: bytes) -> bool:
    """Verify an 'ed25519:<hex>' signature against data."""
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "Install agentcop-sign[crypto] to use Ed25519 verification: "
            "pip install agentcop-sign[crypto]"
        )
    if not signature_str.startswith("ed25519:"):
        return False
    try:
        sig_bytes = bytes.fromhex(signature_str[len("ed25519:"):])
        key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        key.verify(sig_bytes, data)
        return True
    except Exception:
        return False
