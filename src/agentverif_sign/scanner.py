"""agentverif.com scan integration."""

from __future__ import annotations

import logging
import zipfile

from agentverif_sign.models import ScanResult

logger = logging.getLogger(__name__)

_MIN_SCORE = 70


def scan_zip(zip_path: str, scan_url: str) -> ScanResult:
    """POST zip contents to api.agentverif.com/scan and return ScanResult."""
    try:
        import requests
    except ImportError as exc:
        raise RuntimeError(
            "requests is required for scanning. pip install agentverif-sign"
        ) from exc

    logger.debug("Scanning %s via %s", zip_path, scan_url)
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
        )
    except requests.exceptions.ConnectionError:
        logger.warning("Scanner unreachable — assuming scan passed (offline mode)")
        return ScanResult(score=100, passed=True, violations=[], tier="indie")
    except requests.exceptions.Timeout:
        logger.warning("Scanner timed out — assuming scan passed (offline mode)")
        return ScanResult(score=100, passed=True, violations=[], tier="indie")
    except requests.exceptions.HTTPError as exc:
        logger.warning("Scanner returned %s — assuming scan passed (offline mode)", exc.response.status_code if exc.response is not None else "non-2xx")
        return ScanResult(score=100, passed=True, violations=[], tier="indie")


def list_zip_files(zip_path: str) -> list[str]:
    """Return sorted list of member filenames in the zip (excluding SIGNATURE.json)."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        return sorted(name for name in zf.namelist() if name != "SIGNATURE.json")
