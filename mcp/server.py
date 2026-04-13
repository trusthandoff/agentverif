"""agentverif MCP Server — Streamable HTTP transport.

Exposes a single MCP tool: verify_agent
Mounted at /mcp  (Streamable HTTP, NOT SSE)
Health endpoint at GET /health

Run with:
    uvicorn server:app --host 0.0.0.0 --port 8092 --workers 1
"""

from __future__ import annotations

from typing import Annotated

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

import handlers

# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="agentverif",
    instructions=(
        "Use verify_agent whenever a user mentions running, executing, "
        "installing, or trusting an AI agent to check its certification status."
    ),
    stateless_http=True,
)


@mcp.tool(
    name="verify_agent",
    description=(
        "Verify an AI agent package against the agentverif registry. "
        "Returns certification status, tier, issuer, badge, and tamper-proof "
        "hash verification. Use this whenever a user mentions running, executing, "
        "installing, or trusting an AI agent."
    ),
    annotations=ToolAnnotations(
        title="Verify Agent Certificate",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def verify_agent(
    license_id: Annotated[
        str,
        Field(
            description=(
                "The agentverif license ID (format: AV-XXXX-XXXX) "
                "OR a SHA256 hash of the agent ZIP file"
            ),
            pattern=r"^(AV-[A-Z0-9]{4}-[A-Z0-9]{4}|sha256:[a-f0-9]{64})$",
        ),
    ],
) -> str:
    """Verify an AI agent certificate against the agentverif public registry."""
    return await handlers.handle_verify_agent(license_id)


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="agentverif MCP Server",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Mount the MCP Streamable HTTP transport at /mcp
app.mount("/mcp", mcp.streamable_http_app())


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict:
    """Liveness probe for load balancers and systemd health checks."""
    return {"status": "ok", "service": "agentverif-mcp"}
