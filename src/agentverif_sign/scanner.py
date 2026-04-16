"""agentverif.com scan integration."""

from __future__ import annotations

import logging
import time
import zipfile

from agentverif_sign.models import ScanResult

logger = logging.getLogger(__name__)

_MIN_SCORE = 70
_MAX_RETRIES = 3
_BACKOFF = [1, 2, 4]
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def scan_zip(zip_path: str, scan_url: str) -> ScanResult:
    """POST zip contents to api.agentverif.com/scan and return ScanResult."""
    try:
        import requests
    except ImportError as exc:
        raise RuntimeError(
            "requests is required for scanning. pip install agentverif-sign"
        ) from exc

    logger.debug("Scanning %s via %s", zip_path, scan_url)
    last_exc: Exception | None = None
    attempt = 0
    for attempt in range(_MAX_RETRIES):
        try:
            with open(zip_path, "rb") as fh:
                response = requests.post(
                    scan_url,
                    files={"file": ("agent.zip", fh, "application/zip")},
                    timeout=30,
                )
            response.raise_for_status()
            data = response.json()
            score = int(data.get("score", 0))
            violations = data.get("violations", [])
            tier = data.get("tier", "indie")
            return ScanResult(
                score=score,
                passed=score >= _MIN_SCORE,
                violations=violations,
                tier=tier,
                source="real",
            )
        except requests.exceptions.ConnectionError as exc:
            last_exc = exc
            break
        except requests.exceptions.Timeout as exc:
            last_exc = exc
            break
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status in _RETRYABLE_STATUS and attempt < _MAX_RETRIES - 1:
                logger.warning(
                    "scan API transient error (attempt %d/%d, status=%s) — retrying in %ds",
                    attempt + 1,
                    _MAX_RETRIES,
                    status,
                    _BACKOFF[attempt],
                )
                time.sleep(_BACKOFF[attempt])
                continue
            last_exc = exc
            break

    logger.warning(
        "scan API unreachable after %d attempt(s) (%s) — "
        "SIGNATURE.json will contain scan_source='offline_fallback'. "
        "This package has NOT been scanned.",
        attempt + 1,
        last_exc,
    )
    return ScanResult(score=100, passed=True, violations=[], tier="indie", source="offline_fallback")


def list_zip_files(zip_path: str) -> list[str]:
    """Return sorted list of member filenames in the zip (excluding SIGNATURE.json)."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        return sorted(name for name in zf.namelist() if name != "SIGNATURE.json")
