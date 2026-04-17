"""agentverif API — FastAPI backend, port 8090.

Endpoints:
  POST /register           — register a new signed package
  GET  /verify/{id}        — verify a license by ID
  POST /verify             — verify via JSON body (CLI compat)
  POST /revoke             — revoke a license
  GET  /health             — liveness check
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import os
import re
import sqlite3
import tempfile
import zipfile
from datetime import UTC, datetime
from typing import Annotated

from pathlib import Path as FilePath
from fastapi import FastAPI, Header, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="agentverif API",
    version="0.1.0",
    description="Certificate registry for AI agent packages.",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://agentverif.com",
        "https://www.agentverif.com",
        "https://verify.agentverif.com",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
)

# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response


app.add_middleware(_SecurityHeadersMiddleware)

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DB_PATH = os.getenv("AGENTVERIF_DB", "/root/agentverif/api/agentverif.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _init_db() -> None:
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                license_id      TEXT PRIMARY KEY,
                tier            TEXT NOT NULL,
                zip_hash        TEXT NOT NULL,
                file_list       TEXT NOT NULL DEFAULT '[]',
                file_count      INTEGER NOT NULL DEFAULT 0,
                issued_at       TEXT NOT NULL,
                expires_at      TEXT,
                issuer          TEXT NOT NULL DEFAULT 'agentverif.com',
                issuer_version  TEXT,
                revoked         INTEGER NOT NULL DEFAULT 0,
                revoked_at      TEXT,
                revoked_reason  TEXT,
                registered_at   TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        for _col in (
            "ALTER TABLE licenses ADD COLUMN license_type TEXT NOT NULL DEFAULT 'single_use'",
            "ALTER TABLE licenses ADD COLUMN transferable INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE licenses ADD COLUMN max_activations INTEGER",
            "ALTER TABLE licenses ADD COLUMN activation_count INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE licenses ADD COLUMN buyer_id TEXT",
            "ALTER TABLE licenses ADD COLUMN scan_source TEXT NOT NULL DEFAULT 'real'",
        ):
            with contextlib.suppress(sqlite3.OperationalError):
                conn.execute(_col)
        conn.commit()


_init_db()

_EXPECTED_KEY = os.environ.get("AGENTVERIF_API_KEY", "")
_LICENSE_PATTERN = re.compile(r"^AC-(?:ENT-)?[A-Z0-9]{4}-[A-Z0-9]{4}$")

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

_FileItem = Annotated[str, Field(max_length=500)]


class RegisterRequest(BaseModel):
    # All fields optional so Pydantic never rejects the body before auth runs.
    # Required fields (license_id, tier, zip_hash, issued_at) are validated
    # inside the /register function body AFTER the auth check.
    license_id: str | None = None
    tier: str | None = None
    zip_hash: str | None = None
    file_list: list[_FileItem] = Field(default_factory=list, max_length=1000)
    issued_at: str | None = None
    expires_at: str | None = None
    issuer: str = "agentverif.com"
    issuer_version: str | None = None
    schema_version: str | None = None
    manifest_hash: str | None = None
    scan_passed: bool | None = None
    scan_source: str = "real"
    signature: str | None = None
    license_type: str = "single_use"
    transferable: bool = False
    max_activations: int | None = None
    buyer_id: str | None = None


class RevokeRequest(BaseModel):
    license_id: str = Field(..., max_length=20, pattern=r"^AC-(?:ENT-)?[A-Z0-9]{4}-[A-Z0-9]{4}$")
    reason: str | None = Field(None, max_length=500)


class VerifyBody(BaseModel):
    license_id: str = Field(..., max_length=20, pattern=r"^AC-(?:ENT-)?[A-Z0-9]{4}-[A-Z0-9]{4}$")
    zip_hash: str | None = None
    buyer_id: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _badge(tier: str, license_id: str) -> str:
    if tier == "enterprise":
        return "🔐 agentverif ENTERPRISE CERTIFIED"
    if tier == "pro":
        return f"✅ agentverif VERIFIED | {license_id}"
    return "✅ Signed by agentverif"


def _row_to_verify_response(row: sqlite3.Row, buyer_id: str | None = None) -> dict:
    row_keys = row.keys()
    license_type = row["license_type"] if "license_type" in row_keys else "single_use"
    max_act = row["max_activations"] if "max_activations" in row_keys else None
    act_count = row["activation_count"] if "activation_count" in row_keys else 0
    stored_buyer = row["buyer_id"] if "buyer_id" in row_keys else None
    scan_source = row["scan_source"] if "scan_source" in row_keys else "real"
    expires_at = row["expires_at"]

    # License-type specific status / message
    if license_type == "single_use" and buyer_id and stored_buyer and buyer_id != stored_buyer:
        return {
            "valid": False,
            "status": "REDISTRIBUTION_BLOCKED",
            "license_id": row["license_id"],
            "tier": row["tier"],
            "license_type": license_type,
            "message": "⚠ SINGLE USE LICENSE — redistribution blocked",
            "verify_url": f"https://verify.agentverif.com/?id={row['license_id']}",
        }

    if expires_at:
        try:
            expiry_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if expiry_dt < datetime.now(UTC):
                return {
                    "valid": False,
                    "status": "EXPIRED",
                    "license_id": row["license_id"],
                    "tier": row["tier"],
                    "expires_at": expires_at,
                    "message": "This license has expired. Contact the vendor to renew.",
                    "verify_url": f"https://verify.agentverif.com/?id={row['license_id']}",
                }
        except (ValueError, AttributeError):
            pass  # malformed expires_at — treat as no expiry

    if license_type == "multi_use" and max_act is not None:
        remaining = max_act - (act_count or 0)
        message = f"✅ VERIFIED — {remaining} activations remaining"
    elif license_type == "enterprise_custom":
        message = "✅ VERIFIED — enterprise license"
    else:
        message = "✅ VERIFIED"

    return {
        "valid": True,
        "status": "VERIFIED",
        "license_id": row["license_id"],
        "tier": row["tier"],
        "license_type": license_type,
        "max_activations": max_act,
        "activation_count": act_count,
        "badge": _badge(row["tier"], row["license_id"]),
        "message": message,
        "issued_at": row["issued_at"],
        "expires_at": expires_at,
        "file_count": row["file_count"],
        "issuer": row["issuer"],
        "scan_source": scan_source,
        "verify_url": f"https://verify.agentverif.com/?id={row['license_id']}",
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health", tags=["ops"])
def health() -> dict:
    """Liveness probe."""
    return {
        "status": "ok",
        "service": "agentverif-api",
        "version": "0.1.0",
        "timestamp": _now_utc(),
    }


_OWASP_LLM_REF = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"


@app.post("/scan", tags=["scan"])
@limiter.limit("10/minute")
async def scan_agent(request: Request, file: UploadFile = File(...)):
    from scanner import Scanner

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        scanner = Scanner()
        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: scanner.scan_zip(FilePath(tmp_path))),
                timeout=25.0,
            )
        except zipfile.BadZipFile:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Invalid file — must be a ZIP archive",
                    "passed": False,
                    "score": None,
                },
            )
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=408,
                content={"error": "Scan timeout", "score": None, "passed": False},
            )
        score = result["score"]
        findings = result.get("findings", [])
        violations = [
            {
                "id": f.get("id"),
                "title": f.get("title"),
                "explanation": f.get("explanation") or _OWASP_LLM_REF,
                "cwe": f.get("cwe"),
                "owasp": f.get("owasp"),
                "severity": f.get("severity"),
                "file": f.get("file"),
                "line": f.get("line"),
                "code_snippet": f.get("code_snippet"),
                "diff": f.get("diff"),
            }
            for f in findings
            if f.get("severity") in ("critical", "warning")
        ]
        return {
            "score": score,
            "passed": score >= 70,
            "violations": violations,
            "files_analyzed": result.get("files_analyzed", 0),
            "tier": "indie",
        }
    finally:
        os.unlink(tmp_path)


@app.post("/register", tags=["registry"])
@limiter.limit("10/minute")
def register(
    request: Request,
    req: RegisterRequest,
    authorization: str | None = Header(None),
) -> dict:
    """Internal endpoint — called only after a successful scan+sign.

    Never expose to clients directly. Requires the same Bearer token
    as /revoke. Unauthenticated calls are refused with 401.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="API key required")
    api_key = authorization.removeprefix("Bearer ").strip()
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")
    if not _EXPECTED_KEY or not hmac.compare_digest(
        hashlib.sha256(api_key.encode()).digest(),
        hashlib.sha256(_EXPECTED_KEY.encode()).digest(),
    ):
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Field validation runs after auth so unauthenticated callers always get 401.
    if not req.license_id or not _LICENSE_PATTERN.match(req.license_id):
        raise HTTPException(status_code=422, detail="Invalid license_id format")
    if not req.tier:
        raise HTTPException(status_code=422, detail="Field required: tier")
    if not req.zip_hash:
        raise HTTPException(status_code=422, detail="Field required: zip_hash")
    if not req.issued_at:
        raise HTTPException(status_code=422, detail="Field required: issued_at")

    file_list_json = json.dumps(req.file_list)
    file_count = len(req.file_list)

    with _get_conn() as conn:
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO licenses
                  (license_id, tier, zip_hash, file_list, file_count,
                   issued_at, expires_at, issuer, issuer_version,
                   license_type, transferable, max_activations, buyer_id,
                   scan_source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    req.license_id,
                    req.tier,
                    req.zip_hash,
                    file_list_json,
                    file_count,
                    req.issued_at,
                    req.expires_at,
                    req.issuer,
                    req.issuer_version,
                    req.license_type,
                    int(req.transferable),
                    req.max_activations,
                    req.buyer_id,
                    req.scan_source,
                ),
            )
            conn.commit()
        except sqlite3.Error as exc:
            raise HTTPException(status_code=500, detail=f"Database error: {exc}") from exc

    return {"license_id": req.license_id, "status": "registered"}


@app.get("/verify/{license_id}", tags=["registry"])
@limiter.limit("60/minute")
def verify_get(request: Request, license_id: str) -> dict:
    """Verify a license by ID (used by the web verify page)."""
    license_id = license_id.upper().strip()
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="License not found")

    if row["revoked"]:
        return {
            "valid": False,
            "status": "REVOKED",
            "license_id": license_id,
            "tier": row["tier"],
            "revoked_at": row["revoked_at"],
            "revoked_reason": row["revoked_reason"],
            "message": row["revoked_reason"] or "Certificate revoked by issuer.",
        }

    return _row_to_verify_response(row)


@app.post("/verify", tags=["registry"])
@limiter.limit("60/minute")
def verify_post(request: Request, body: VerifyBody) -> dict:
    """Verify via JSON body — used by the agentverif-sign CLI."""
    license_id = body.license_id.upper().strip()
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="License not found")

    if row["revoked"]:
        return {
            "valid": False,
            "status": "REVOKED",
            "license_id": license_id,
            "tier": row["tier"],
            "revoked_at": row["revoked_at"],
            "revoked_reason": row["revoked_reason"],
            "message": row["revoked_reason"] or "Certificate revoked by issuer.",
        }

    return _row_to_verify_response(row, buyer_id=body.buyer_id)


@app.post("/revoke", tags=["registry"])
@limiter.limit("5/minute")
def revoke(
    request: Request,
    req: RevokeRequest,
    authorization: str | None = Header(None),
) -> dict:
    """Revoke a license certificate."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="API key required")
    api_key = authorization.removeprefix("Bearer ").strip()
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")
    if not _EXPECTED_KEY or not hmac.compare_digest(
        hashlib.sha256(api_key.encode()).digest(),
        hashlib.sha256(_EXPECTED_KEY.encode()).digest(),
    ):
        raise HTTPException(status_code=401, detail="Invalid API key")

    with _get_conn() as conn:
        row = conn.execute(
            "SELECT license_id FROM licenses WHERE license_id = ?",
            (req.license_id.upper(),),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="License not found")

        conn.execute(
            """
            UPDATE licenses
            SET revoked = 1, revoked_at = ?, revoked_reason = ?
            WHERE license_id = ?
            """,
            (_now_utc(), req.reason, req.license_id.upper()),
        )
        conn.commit()

    return {"revoked": True, "license_id": req.license_id.upper()}
