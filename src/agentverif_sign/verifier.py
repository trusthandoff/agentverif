"""Verification logic — extracts, hashes, checks, optionally queries registry."""

from __future__ import annotations

import json
import logging
import zipfile

from agentverif_sign.models import SignatureRecord, VerifyResult
from agentverif_sign.signer import compute_zip_hash

logger = logging.getLogger(__name__)


def extract_signature(zip_path: str) -> SignatureRecord | None:
    """Return SignatureRecord from zip, or None if not present."""
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            if "SIGNATURE.json" not in zf.namelist():
                return None
            raw = zf.read("SIGNATURE.json").decode()
    except (zipfile.BadZipFile, KeyError, UnicodeDecodeError) as exc:
        logger.debug("Could not read SIGNATURE.json: %s", exc)
        return None
    try:
        return SignatureRecord.from_json(raw)
    except (KeyError, json.JSONDecodeError) as exc:
        logger.debug("Malformed SIGNATURE.json: %s", exc)
        return None


def verify_zip(
    zip_path: str,
    offline: bool = False,
    sign_url: str = "https://api.agentverif.com",
) -> VerifyResult:
    """Verify a signed zip and return a VerifyResult."""
    from agentverif_sign.badges import render_badge

    # Step 1 — extract signature
    record = extract_signature(zip_path)
    if record is None:
        return VerifyResult(
            status="UNSIGNED",
            license_id=None,
            tier=None,
            badge=None,
            message="No agentverif signature found",
            offline=offline,
            verify_url=None,
        )

    # Step 2 & 3 — local hash check
    current_hash = compute_zip_hash(zip_path, exclude={"SIGNATURE.json"})
    if current_hash != record.zip_hash:
        return VerifyResult(
            status="MODIFIED",
            license_id=record.license_id,
            tier=record.tier,
            badge=None,
            message="Package was changed after signing",
            offline=offline,
            verify_url=f"https://verify.agentverif.com/?id={record.license_id}",
        )

    verify_url = f"https://verify.agentverif.com/?id={record.license_id}"

    # Step 4 — registry check (optional)
    if not offline:
        try:
            from agentverif_sign import client

            return client.verify(record.license_id, record.zip_hash, sign_url)
        except Exception as exc:
            logger.warning("Registry unreachable, falling back to offline: %s", exc)
            # Fall through to offline result

    badge = render_badge(record.tier, record.license_id)
    return VerifyResult(
        status="UNREGISTERED",
        license_id=record.license_id,
        tier=record.tier,
        badge=badge,
        message="Signature valid locally; registry not checked",
        offline=True,
        verify_url=verify_url,
    )
