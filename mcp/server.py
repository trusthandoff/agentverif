"""agentverif MCP Server — Streamable HTTP transport.

Exposes a single MCP tool: verify_agent
/mcp  — Streamable HTTP endpoint (NOT SSE)
/health — liveness probe

Run with:
    uvicorn server:app --host 0.0.0.0 --port 8092 --workers 1

Architecture note:
    FastMCP.streamable_http_app() returns a Starlette sub-app whose internal
    route is at /mcp.  Mounting that sub-app at /mcp with FastAPI strips the
    /mcp prefix and leaves the sub-app to route /, which it doesn't know —
    triggering a 307 redirect to /mcp/.

    Fix: build a single top-level Starlette app that owns both /health and
    /mcp as direct routes, and share the session_manager lifespan from the
    FastMCP sub-app.  No Mount, no redirect.
"""

from __future__ import annotations

from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.server.streamable_http import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import Field
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route

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
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
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
            pattern=r"^(A[A-Z]-[A-Z0-9]{4}-[A-Z0-9]{4}|sha256:[a-f0-9]{64})$",
        ),
    ],
) -> str:
    """Verify an AI agent certificate against the agentverif public registry."""
    return await handlers.handle_verify_agent(license_id)


# ---------------------------------------------------------------------------
# Build the top-level ASGI app
#
# Call streamable_http_app() to let FastMCP initialise its session_manager,
# then extract the StreamableHTTPASGIApp endpoint and register it directly at
# /mcp in a new Starlette app.  Sharing the session_manager.run() lifespan
# keeps the task group alive for the duration of the server process.
# ---------------------------------------------------------------------------

_mcp_sub = mcp.streamable_http_app()          # initialises session_manager
_mcp_endpoint = _mcp_sub.routes[0].endpoint   # StreamableHTTPASGIApp instance


async def _health(request):
    return JSONResponse({"status": "ok", "service": "agentverif-mcp"})


app = Starlette(
    routes=[
        Route("/health", _health, methods=["GET"]),
        Route("/mcp", _mcp_endpoint),
    ],
    middleware=[
        Middleware(TrustedHostMiddleware, allowed_hosts=["*"]),
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        ),
    ],
    lifespan=lambda _app: mcp.session_manager.run(),
)
