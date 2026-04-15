"""agentverif MCP Server — Streamable HTTP transport.

Exposes a single MCP tool: verify_agent
/     — primary MCP endpoint (Claude.ai posts here)
/mcp  — alias kept for backward compatibility
/health — liveness probe

OAuth discovery stubs (required by Claude.ai for no-auth servers):
/.well-known/oauth-protected-resource  → 200, authorization_servers=[]
/.well-known/oauth-authorization-server → 404, no_auth_required
/register → 404, no_auth_required

Run with:
    uvicorn server:app --host 0.0.0.0 --port 8092 --workers 1

Architecture note:
    FastMCP.streamable_http_app() returns a Starlette sub-app whose internal
    route is at /mcp.  Mounting that sub-app at /mcp with FastAPI strips the
    /mcp prefix and leaves the sub-app to route /, which it doesn't know —
    triggering a 307 redirect to /mcp/.

    Fix: build a single top-level Starlette app that owns /health, the OAuth
    stubs, and the MCP endpoint at both / and /mcp as direct routes, sharing
    the session_manager lifespan from the FastMCP sub-app.  No Mount, no redirect.
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
                "The agentverif license ID (format: AV-XXXX-XXXX or AC-XXXX-XXXX) "
                "OR a SHA256 hash of the agent ZIP file"
            ),
            pattern=r"^(A[A-Z]-[A-Z0-9]{4}-[A-Z0-9]{4}|sha256:[a-f0-9]{64})$",
        ),
    ],
) -> str:
    """Verify an AI agent certificate against the agentverif public registry."""
    return await handlers.handle_verify_agent(license_id)


@mcp.tool(
    name="scan_agent",
    description=(
        "Scan an AI agent ZIP against OWASP LLM Top 10 before signing. "
        "Accepts a public URL to the ZIP. Returns score, violations with "
        "explanations and actionable fixes. Score below 70 = refused. "
        "Run this BEFORE sign_agent."
    ),
    annotations=ToolAnnotations(
        title="Scan Agent for Security Issues",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
async def scan_agent(
    zip_url: Annotated[
        str,
        Field(description="Public URL to the agent ZIP file to scan"),
    ],
) -> str:
    """Scan an AI agent ZIP against OWASP LLM Top 10 before signing."""
    return await handlers.handle_scan_agent(zip_url)


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


async def _oauth_protected_resource(request):
    return JSONResponse(
        {"resource": "https://mcp.agentverif.com", "authorization_servers": []},
        status_code=200,
    )


async def _oauth_authorization_server(request):
    return JSONResponse({"error": "no_auth_required"}, status_code=404)


async def _register(request):
    return JSONResponse({"error": "no_auth_required"}, status_code=404)


app = Starlette(
    routes=[
        Route("/health", _health, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", _oauth_protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", _oauth_authorization_server, methods=["GET"]),
        Route("/register", _register, methods=["POST"]),
        Route("/mcp", _mcp_endpoint),
        Route("/", _mcp_endpoint),
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
