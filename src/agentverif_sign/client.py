"""Backend API client for sign.agentverif.com."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentverif_sign.models import SignatureRecord, VerifyResult

from agentverif_sign.models import VerifyResult

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_MAX_RETRIES = 2
_BACKOFF_BASE = 0.5


def _get_requests():
    try:
        import requests

        return requests
    except ImportError as exc:
        raise RuntimeError(
            "requests is required for registry operations. pip install agentverif-sign"
        ) from exc


def _request_with_retry(method: str, url: str, **kwargs):
    requests = _get_requests()
    kwargs.setdefault("timeout", _TIMEOUT)
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            response = requests.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.ConnectionError as exc:
            last_exc = exc
            logger.debug("Connection error on attempt %d: %s", attempt + 1, exc)
        except requests.exceptions.Timeout as exc:
            last_exc = exc
            logger.debug("Timeout on attempt %d: %s", attempt + 1, exc)
        except requests.exceptions.HTTPError:
            raise
        if attempt < _MAX_RETRIES:
            time.sleep(_BACKOFF_BASE * (2**attempt))
    raise last_exc  # type: ignore[misc]


def register(signature: SignatureRecord, sign_url: str, api_key: str | None = None) -> str:
    """Register a signature on the registry; return license_id."""
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = signature.to_dict()
    response = _request_with_retry(
        "POST",
        f"{sign_url}/register",
        json=payload,
        headers=headers,
    )
    data = response.json()
    return data.get("license_id", signature.license_id)


def verify(license_id: str, zip_hash: str, sign_url: str) -> VerifyResult:
    """Verify a license ID and hash against the registry."""
    from agentverif_sign.badges import render_badge

    response = _request_with_retry(
        "POST",
        f"{sign_url}/verify",
        json={"license_id": license_id, "zip_hash": zip_hash},
    )
    data = response.json()
    status = data.get("status", "UNREGISTERED")
    tier = data.get("tier")
    verify_url = f"https://verify.agentverif.com/{license_id}"
    badge = render_badge(tier, license_id) if tier else None
    return VerifyResult(
        status=status,
        license_id=license_id,
        tier=tier,
        badge=badge,
        message=data.get("message", ""),
        offline=False,
        verify_url=verify_url,
    )


def revoke(license_id: str, api_key: str, sign_url: str) -> bool:
    """Revoke a license. Returns True on success."""
    _request_with_retry(
        "POST",
        f"{sign_url}/revoke",
        json={"license_id": license_id},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return True


def health(sign_url: str) -> bool:
    """Return True if the registry is reachable."""
    requests = _get_requests()
    try:
        resp = requests.get(f"{sign_url}/health", timeout=_TIMEOUT)
        return resp.status_code < 500
    except Exception:
        return False
