"""Pure dataclasses — no external dependencies."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field


@dataclass
class SignatureRecord:
    schema_version: str
    license_id: str
    tier: str
    issued_at: str
    expires_at: str | None
    issuer: str
    issuer_version: str
    file_list: list[str]
    file_count: int
    zip_hash: str
    manifest_hash: str
    scan_passed: bool
    signature: str | None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> SignatureRecord:
        return cls(
            schema_version=data["schema_version"],
            license_id=data["license_id"],
            tier=data["tier"],
            issued_at=data["issued_at"],
            expires_at=data.get("expires_at"),
            issuer=data["issuer"],
            issuer_version=data["issuer_version"],
            file_list=data["file_list"],
            file_count=data["file_count"],
            zip_hash=data["zip_hash"],
            manifest_hash=data["manifest_hash"],
            scan_passed=data["scan_passed"],
            signature=data.get("signature"),
        )

    @classmethod
    def from_json(cls, text: str) -> SignatureRecord:
        return cls.from_dict(json.loads(text))


@dataclass
class VerifyResult:
    status: str  # VERIFIED | MODIFIED | REVOKED | UNREGISTERED | UNSIGNED
    license_id: str | None
    tier: str | None
    badge: str | None
    message: str
    offline: bool
    verify_url: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class ScanResult:
    score: int
    passed: bool
    violations: list[dict] = field(default_factory=list)
    tier: str = "indie"

    def to_dict(self) -> dict:
        return asdict(self)
