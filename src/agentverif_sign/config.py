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
    def from_env(cls, api_key: str | None = None) -> Config:
        return cls(
            api_key=api_key or os.environ.get("AGENTVERIF_API_KEY"),
            sign_url=os.environ.get("AGENTVERIF_SIGN_URL", "https://api.agentverif.com"),
            scan_url=os.environ.get("AGENTVERIF_SCAN_URL", "https://api.agentverif.com/scan"),
            offline=bool(os.environ.get("AGENTVERIF_OFFLINE")),
        )
