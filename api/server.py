"""agentverif API — FastAPI backend, port 8090.

Endpoints:
  POST /register           — register a new signed package
  GET  /verify/{id}        — verify a license by ID
  POST /verify             — verify via JSON body (CLI compat)
  POST /revoke             — revoke a license
  GET  /health             — liveness check
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="agentverif API",
    version="0.1.0",
    description="Certificate registry for AI agent packages.",
    docs_url="/docs",
    redoc_url=None,
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
    allow_headers=["*"],
)

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
        ):
            with contextlib.suppress(sqlite3.OperationalError):
                conn.execute(_col)
        conn.commit()


_init_db()

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    license_id: str = Field(..., description="License ID, e.g. AV-84F2-91AB")
    tier: str = Field(..., description="indie | pro | enterprise")
    zip_hash: str = Field(..., description="sha256:<hex>")
    file_list: list[str] = Field(default_factory=list)
    issued_at: str = Field(..., description="ISO 8601 UTC timestamp")
    expires_at: str | None = None
    issuer: str = "agentverif.com"
    issuer_version: str | None = None
    # Additional fields the CLI sends; accepted but not all stored
    schema_version: str | None = None
    manifest_hash: str | None = None
    scan_passed: bool | None = None
    signature: str | None = None
    license_type: str = "single_use"
    transferable: bool = False
    max_activations: int | None = None
    buyer_id: str | None = None


class RevokeRequest(BaseModel):
    license_id: str
    api_key: str
    reason: str | None = None


class VerifyBody(BaseModel):
    license_id: str
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
        "expires_at": row["expires_at"],
        "file_count": row["file_count"],
        "issuer": row["issuer"],
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


@app.post("/register", tags=["registry"])
def register(req: RegisterRequest) -> dict:
    """Register a signed package. Called by the agentverif-sign CLI."""
    file_list_json = json.dumps(req.file_list)
    file_count = len(req.file_list)

    with _get_conn() as conn:
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO licenses
                  (license_id, tier, zip_hash, file_list, file_count,
                   issued_at, expires_at, issuer, issuer_version,
                   license_type, transferable, max_activations, buyer_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )
            conn.commit()
        except sqlite3.Error as exc:
            raise HTTPException(status_code=500, detail=f"Database error: {exc}") from exc

    return {"license_id": req.license_id, "status": "registered"}


@app.get("/verify/{license_id}", tags=["registry"])
def verify_get(license_id: str) -> dict:
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
def verify_post(body: VerifyBody) -> dict:
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
def revoke(req: RevokeRequest) -> dict:
    """Revoke a license certificate."""
    # NOTE: In production, validate api_key against a stored hash.
    # For v0.1 we accept any non-empty key; harden before public launch.
    if not req.api_key:
        raise HTTPException(status_code=401, detail="API key required")

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
