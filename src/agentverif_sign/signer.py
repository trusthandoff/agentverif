"""Signing logic — validates, scans, hashes, and injects SIGNATURE.json."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import secrets
import zipfile
from datetime import UTC, datetime

from agentverif_sign.models import ScanResult, SignatureRecord

logger = logging.getLogger(__name__)

_MAX_ZIP_BYTES = 100 * 1024 * 1024  # 100 MB
_ISSUER = "agentcop.live"
_ISSUER_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_zip(zip_path: str) -> None:
    """Raise ValueError if the zip is invalid, empty, or too large."""
    if not os.path.isfile(zip_path):
        raise ValueError(f"File not found: {zip_path}")
    size = os.path.getsize(zip_path)
    if size == 0:
        raise ValueError("Zip file is empty")
    if size > _MAX_ZIP_BYTES:
        raise ValueError(f"Zip file too large ({size / 1024 / 1024:.1f} MB > 100 MB)")
    if not zipfile.is_zipfile(zip_path):
        raise ValueError(f"Not a valid zip file: {zip_path}")
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
    if not names:
        raise ValueError("Zip file contains no files")


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def compute_zip_hash(zip_path: str, exclude: set[str] | None = None) -> str:
    """Return 'sha256:<hex>' of the zip content, excluding listed members."""
    exclude = exclude or set()
    h = hashlib.sha256()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in sorted(zf.namelist()):
            if name in exclude:
                continue
            h.update(name.encode())
            h.update(zf.read(name))
    return f"sha256:{h.hexdigest()}"


def compute_manifest_hash(file_list: list[str]) -> str:
    """Return 'sha256:<hex>' of the sorted file list."""
    payload = json.dumps(sorted(file_list), separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


# ---------------------------------------------------------------------------
# License ID generation
# ---------------------------------------------------------------------------


def _generate_license_id(tier: str) -> str:
    prefix = "AC-ENT" if tier == "enterprise" else "AC"
    part1 = secrets.token_hex(2).upper()
    part2 = secrets.token_hex(2).upper()
    return f"{prefix}-{part1}-{part2}"


# ---------------------------------------------------------------------------
# SIGNATURE.json injection
# ---------------------------------------------------------------------------


def inject_signature(zip_path: str, record: SignatureRecord) -> None:
    """Add or replace SIGNATURE.json inside the zip in-place."""
    sig_bytes = record.to_json().encode()
    _rewrite_zip(zip_path, "SIGNATURE.json", sig_bytes)


def _rewrite_zip(zip_path: str, filename: str, data: bytes) -> None:
    """Rewrite zip, replacing or adding a member."""
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(zip_path, "r") as src,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst,
    ):
        for item in src.infolist():
            if item.filename == filename:
                continue
            dst.writestr(item, src.read(item.filename))
        dst.writestr(filename, data)
    buf.seek(0)
    with open(zip_path, "wb") as fh:
        fh.write(buf.read())


# ---------------------------------------------------------------------------
# Main sign function
# ---------------------------------------------------------------------------


def sign_zip(
    zip_path: str,
    tier: str = "indie",
    api_key: str | None = None,
    scan_result: ScanResult | None = None,
    private_key_bytes: bytes | None = None,
) -> SignatureRecord:
    """Build and return a SignatureRecord (does NOT inject into zip)."""
    from agentverif_sign.scanner import list_zip_files

    file_list = list_zip_files(zip_path)
    zip_hash = compute_zip_hash(zip_path, exclude={"SIGNATURE.json"})
    manifest_hash = compute_manifest_hash(file_list)
    license_id = _generate_license_id(tier)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    signature: str | None = None
    if tier in ("pro", "enterprise") and private_key_bytes is not None:
        from agentverif_sign import crypto

        payload = f"{license_id}:{zip_hash}:{manifest_hash}".encode()
        signature = crypto.sign(payload, private_key_bytes)

    return SignatureRecord(
        schema_version="1.0",
        license_id=license_id,
        tier=tier,
        issued_at=now,
        expires_at=None,
        issuer=_ISSUER,
        issuer_version=_ISSUER_VERSION,
        file_list=file_list,
        file_count=len(file_list),
        zip_hash=zip_hash,
        manifest_hash=manifest_hash,
        scan_passed=scan_result.passed if scan_result else True,
        signature=signature,
    )
