# =============================================================================
# NetCopilot — one shared full image for dashboard / MCP / telegram / watcher.
# =============================================================================
# Multi-stage:
#   Stage 1 (node)   — build the React/Vite SPA → dist/
#   Stage 2 (python) — full runtime: pyATS collection + RAG + reports + telegram
#
# All four app services run THIS image with a command override (see
# docker-compose.yml), exactly like the proven source-repo build.
# =============================================================================

# ── Stage 1: build the React frontend ───────────────────────────────────────
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
# Lockfile is committed → npm ci for a reproducible install.
COPY src/netcopilot/dashboard/frontend/package.json src/netcopilot/dashboard/frontend/package-lock.json ./
RUN npm ci
COPY src/netcopilot/dashboard/frontend/ ./
RUN npm run build      # → /app/frontend/dist (vite)

# ── Stage 2: python runtime ─────────────────────────────────────────────────
FROM python:3.11-slim
WORKDIR /app

# System libraries (exact list proven by the source-repo Dockerfile):
#   pango/cairo/gdk-pixbuf/ffi/shared-mime-info → WeasyPrint PDF reports
#   ffmpeg                                       → faster-whisper voice (telegram)
#   openssh-client                               → pyATS/Unicon spawns the system
#     `ssh` client to reach devices; without it every collection silently falls
#     back to NETCONF (the reduced CDP-only graph). Required for "Run Now".
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
        libgdk-pixbuf-xlib-2.0-0 libffi-dev shared-mime-info \
        ffmpeg \
        openssh-client \
    && rm -rf /var/lib/apt/lists/*

# CPU-only torch FIRST (saves ~800 MB vs CUDA wheels; the labs `rag` extra does
# not carry the index hint, so pin it here before the extras pull it in).
RUN pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu "torch>=2.4.0"

# Install the package + all extras (full image per the v1 decision). Copy the
# build inputs first for layer caching, then editable-install so the package
# lives at /app/src and the SPA static/ dir is served from the source tree.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir -e ".[pyats,rag,reports,telegram]"

# Pre-bake the RAG embedding + cross-encoder weights into the image so
# lookup_vendor_docs works offline and is fast on the first query.
RUN python -c "from sentence_transformers import SentenceTransformer, CrossEncoder; \
SentenceTransformer('all-MiniLM-L6-v2'); \
CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')"

# Runtime assets: demo facts (seed rebuilds from these), the minimal seed.json,
# the synthetic inventory template, and the watcher script.
COPY demo ./demo
COPY fixtures ./fixtures
COPY examples ./examples
COPY scripts ./scripts
# Normalize shell-script line endings: a Windows clone (git autocrlf) ships CRLF,
# which breaks bash in the Linux container ("$'\r': command not found"). Strip CR
# so the watcher runs regardless of how the repo was checked out.
RUN find scripts -name '*.sh' -exec sed -i 's/\r$//' {} +

# Built SPA → backend static dir (served at / by FastAPI).
COPY --from=frontend-build /app/frontend/dist ./src/netcopilot/dashboard/backend/static

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    RUNS_DIR=/app/runs

EXPOSE 8080 3002

# Default command = dashboard; mcp/telegram/watcher/seed override it in compose.
CMD ["uvicorn", "netcopilot.dashboard.backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
