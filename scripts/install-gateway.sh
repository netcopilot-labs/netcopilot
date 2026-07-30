#!/usr/bin/env bash
# Optional MCP gateway (gridctl) in front of NetCopilot — opt-in, never part
# of the stack. Installs the latest gridctl release, applies one of the
# example stacks, and VERIFIES the gateway live (fails loudly on a mismatch —
# a future gateway release can't break you silently).
#
#   ./scripts/install-gateway.sh            # personas stack (least privilege)
#   ./scripts/install-gateway.sh full       # full read surface
#
# NetCopilot's MCP endpoint defaults to http://localhost:3002/mcp; override
# with NETCOPILOT_MCP_URL if you changed MCP_PORT.
#
# See docs/deployment/mcp-gateway.md for the pattern and the current limits.
set -euo pipefail

STACK="${1:-personas}"
MCP_URL="${NETCOPILOT_MCP_URL:-http://localhost:3002/mcp}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

case "$STACK" in
  personas) STACK_FILE="$REPO_ROOT/examples/gateway/personas.yaml"; EXPECTED_TOOLS=6 ;;
  full)     STACK_FILE="$REPO_ROOT/examples/gateway/full-read-surface.yaml"; EXPECTED_TOOLS="" ;;
  *) echo "usage: $0 [personas|full]" >&2; exit 2 ;;
esac

# ── 1. NetCopilot must be reachable first ─────────────────────────────────────
# Any HTTP status counts as alive (a bare GET without the MCP handshake is
# expected to be rejected with a 4xx); 000 means no connection at all.
HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$MCP_URL" || true)"
if [ "$HTTP_CODE" = "000" ]; then
  echo "✗ NetCopilot MCP endpoint not reachable at $MCP_URL" >&2
  echo "  Start the stack first (docker compose up) or set NETCOPILOT_MCP_URL." >&2
  exit 1
fi

# ── 2. Install gridctl (latest release, official installer) if missing ───────
if ! command -v gridctl >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/gridctl" ]; then
  echo "→ Installing gridctl (latest release, official installer)…"
  curl -fsSL https://raw.githubusercontent.com/gridctl/gridctl/main/install.sh | sh
fi
GRIDCTL="$(command -v gridctl || echo "$HOME/.local/bin/gridctl")"
echo "→ Using $($GRIDCTL version | head -1) (beta — evolving fast; this script verifies it below)"

# ── 3. Apply the stack (endpoint substituted if overridden) ───────────────────
# The working copy lives at a stable path: `gridctl destroy` needs the same
# stack file later, so it must survive this script.
WORK_STACK="$STACK_FILE"
if [ "$MCP_URL" != "http://localhost:3002/mcp" ]; then
  WORK_STACK="${TMPDIR:-/tmp}/netcopilot-gateway-$STACK.yaml"
  sed "s|http://localhost:3002/mcp|$MCP_URL|g" "$STACK_FILE" > "$WORK_STACK"
fi
"$GRIDCTL" apply "$WORK_STACK"

# ── 4. Verify: the gateway must expose the expected tool surface ──────────────
sleep 2
TOOLS_JSON="$(curl -fsS --max-time 10 http://localhost:8180/api/tools)"
if command -v python3 >/dev/null 2>&1; then
  COUNT="$(printf '%s' "$TOOLS_JSON" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["tools"]))')"
else
  COUNT="?"
  echo "! python3 not found — skipping strict tool-count verification" >&2
fi

if [ -n "$EXPECTED_TOOLS" ] && [ "$COUNT" != "?" ] && [ "$COUNT" -ne "$EXPECTED_TOOLS" ]; then
  echo "✗ VERIFICATION FAILED: expected $EXPECTED_TOOLS tools through the gateway, got $COUNT." >&2
  echo "  A gridctl release may have changed behavior — see docs/deployment/mcp-gateway.md" >&2
  echo "  and tear down with: $GRIDCTL destroy $WORK_STACK" >&2
  exit 1
fi

echo
echo "✓ Gateway verified: $COUNT tool(s) exposed at http://localhost:8180/mcp ($STACK stack)"
echo "  Point any MCP client at that URL. Tool names are namespaced (server__tool)."
echo "  Structured results ({status, verdict}) travel through the gateway on"
echo "  gridctl >= v0.1.0-beta.14 — see docs/deployment/mcp-gateway.md."
echo "  Tear down: $GRIDCTL destroy $WORK_STACK"
