"""NetCopilot Dashboard — FastAPI application.

Serves pipeline data as REST endpoints and the React static bundle from a single
port: API under /api/*, static SPA at /.

HTTP Basic Auth is enabled when the DASHBOARD_USER env var is set (disabled in
local dev when unset). secrets.compare_digest gives timing-safe comparison.
/health and /api/legend are public; everything else requires auth.

Routers are included per-slice as the dashboard verticals land.
"""

import os
import secrets
import sys
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

from .routes import agent_chat, analyze, devices, findings, legend, reports, routing, runs, runs_trigger, topology

# ── HTTP Basic Auth ───────────────────────────────────────────────────────────

_DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "")
_DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
_AUTH_ENABLED = bool(_DASHBOARD_USER)

_security = HTTPBasic(auto_error=False)


def _require_auth(credentials: HTTPBasicCredentials | None = Depends(_security)):
    """FastAPI dependency: enforce HTTP Basic Auth when enabled.

    - Auth disabled (DASHBOARD_USER unset): pass through.
    - Missing/wrong credentials: 401 with WWW-Authenticate.
    - secrets.compare_digest prevents timing attacks; credentials are never logged.
    """
    if not _AUTH_ENABLED:
        return

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Basic realm=\"NetCopilot\""},
        )

    user_ok = secrets.compare_digest(
        credentials.username.encode("utf-8"), _DASHBOARD_USER.encode("utf-8")
    )
    pass_ok = secrets.compare_digest(
        credentials.password.encode("utf-8"), _DASHBOARD_PASSWORD.encode("utf-8")
    )

    if not (user_ok and pass_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic realm=\"NetCopilot\""},
        )


app = FastAPI(
    title="NetCopilot Dashboard",
    description="Web dashboard for the NetCopilot network context agent",
    version="0.1.0",
)


@app.on_event("startup")
async def _verify_rule_catalog_loaded():
    """Fail-fast at boot if the rule catalog can't be loaded.

    The catalog backs explain_finding / analyze_finding; a missing or empty
    catalog would make every rule lookup return "not found" silently. Better to
    fail loudly at boot than silently at first chat.
    """
    from netcopilot.analysis.remediation_loader import _load_catalog

    catalog = _load_catalog()
    if not catalog:
        msg = (
            "[startup-check] Rule catalog is empty — the remediation loader could "
            "not locate or parse the rule catalog. Refusing to start with a broken "
            "catalog (explain_finding would return 'not found' for every rule)."
        )
        print(msg, file=sys.stderr, flush=True)
        raise RuntimeError(msg)
    print(f"[startup-check] Rule catalog OK: {len(catalog)} rules loaded.",
          file=sys.stderr, flush=True)


# ── Security headers ──────────────────────────────────────────────────────────
# Hardening: clickjacking + MIME sniffing + referrer leak + feature-API lockdown
# + CSP. script-src 'self' blocks inline/3rd-party scripts (Vite bundles to
# same-origin /assets). style-src adds 'unsafe-inline' because Cytoscape.js and
# Tailwind inject inline styles at runtime. img-src 'data:' for Cytoscape SVG
# data-URIs. frame-ancestors 'none' == X-Frame-Options DENY.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


@app.middleware("http")
async def _security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = _CSP
    return response


# ── Auth policy: per-router dependency (not app-level) ────────────────────────
# Per-router dependencies make the public/private split explicit at
# include_router() time. /api/legend + /health are public; everything else
# requires HTTP Basic Auth.
_AUTH = [Depends(_require_auth)]

# Protected routes (auth required). More routers are added per dashboard slice.
app.include_router(runs.router, dependencies=_AUTH)
app.include_router(runs_trigger.router, dependencies=_AUTH)
app.include_router(topology.router, dependencies=_AUTH)
app.include_router(devices.router, dependencies=_AUTH)
app.include_router(routing.router, dependencies=_AUTH)
app.include_router(findings.router, dependencies=_AUTH)
app.include_router(analyze.router, dependencies=_AUTH)
app.include_router(agent_chat.router, dependencies=_AUTH)
app.include_router(reports.router, dependencies=_AUTH)

# Public routes (auth NOT required — static configuration data):
app.include_router(legend.router)


RUNS_DIR = Path(os.environ.get("RUNS_DIR", "runs"))


@app.get("/health")
def health():
    """Health check with Neo4j connectivity status."""
    from netcopilot.graph.client import get_driver, is_available

    result = {
        "runs_dir": str(RUNS_DIR),
        "runs_dir_accessible": RUNS_DIR.is_dir(),
    }
    try:
        if is_available():
            result["status"] = "ok"
            result["neo4j"] = "connected"
            info = get_driver().get_server_info()
            result["version"] = info.agent if info else None
        else:
            result["status"] = "degraded"
            result["neo4j"] = "unavailable"
    except Exception as e:
        result["status"] = "degraded"
        result["neo4j"] = "unavailable"
        result["error"] = str(e)
    return result


# Mount static files AFTER API routes (catch-all for the React SPA).
static_dir = Path(__file__).parent / "static"
if static_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
