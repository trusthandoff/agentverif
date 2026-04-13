"""Pydantic models for agentverif API responses."""

from __future__ import annotations

from pydantic import BaseModel


class ApiVerifyResponse(BaseModel):
    """Response from GET /verify/{license_id} on the agentverif API."""

    valid: bool
    status: str
    license_id: str | None = None
    tier: str | None = None
    badge: str | None = None
    issued_at: str | None = None
    expires_at: str | None = None
    issuer: str | None = None
    verify_url: str | None = None
    revoked_at: str | None = None
    revoked_reason: str | None = None
    message: str | None = None
    license_type: str | None = None
    file_count: int | None = None
    max_activations: int | None = None
    activation_count: int | None = None
