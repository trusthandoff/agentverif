"""Environment-variable driven configuration. No global state."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    api_key: str | None
    sign_url: str
    scan_url: str
    offline: bool

    @classmethod
    def from_env(cls, api_key: str | None = None) -> "Config":
        return cls(
            api_key=api_key or os.environ.get("AGENTCOP_API_KEY"),
            sign_url=os.environ.get(
                "AGENTCOP_SIGN_URL", "https://sign.agentcop.live"
            ),
            scan_url=os.environ.get(
                "AGENTCOP_SCAN_URL", "https://agentcop.live/api/scan"
            ),
            offline=bool(os.environ.get("AGENTCOP_OFFLINE")),
        )
