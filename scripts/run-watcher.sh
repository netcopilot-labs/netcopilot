#!/usr/bin/env bash
# run-watcher.sh — execute dashboard-triggered pipeline runs.
#
# The dashboard "Run Now" button never runs collection itself: it writes a
# request flag under runs/.trigger/ (see dashboard/backend/routes/runs_trigger.py).
# This watcher polls for that flag and runs the pipeline wherever it has network
# reach to the devices — keeping the dashboard free of collection dependencies
# (pyATS, SSH creds, etc.).
#
# Start it on a host that can reach your devices, with SSH credentials exported:
#   export NETCOPILOT_SSH_USERNAME=... NETCOPILOT_SSH_PASSWORD=...
#   ./scripts/run-watcher.sh &
#   # or: nohup ./scripts/run-watcher.sh >> /tmp/run-watcher.log 2>&1 &
#
# Configuration (all optional — defaults target the bundled containerlab demo):
#   RUNS_DIR               where run folders are written (default: <repo>/runs)
#   NETCOPILOT_INVENTORY   inventory YAML (default: demo/containerlab/inventory.yaml)
#   NETCOPILOT_SITE        site identifier for multi-site isolation (default: demo)
#   POLL_INTERVAL          seconds between flag checks (default: 15)
#   PYTHON                 python interpreter (default: python3)
#
# The watcher polls runs/.trigger/run_requested. When found it removes the flag,
# appends progress events the dashboard streams over SSE, runs the pipeline, and
# writes run_complete so the dashboard refreshes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load repo-local .env (gitignored) so credentials + Neo4j + overrides are
# picked up automatically — the operator never has to export anything per run.
if [ -f "$PROJECT_ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$PROJECT_ROOT/.env"
  set +a
fi

# The bundled containerlab demo accepts admin/admin (see demo/containerlab).
# Default to it so "Run Now" works out of the box; .env overrides for a real net.
export NETCOPILOT_SSH_USERNAME="${NETCOPILOT_SSH_USERNAME:-admin}"
export NETCOPILOT_SSH_PASSWORD="${NETCOPILOT_SSH_PASSWORD:-admin}"

RUNS_DIR="${RUNS_DIR:-$PROJECT_ROOT/runs}"
TRIGGER_DIR="$RUNS_DIR/.trigger"
FLAG_REQUESTED="$TRIGGER_DIR/run_requested"
FLAG_COMPLETE="$TRIGGER_DIR/run_complete"
PROGRESS_FILE="$TRIGGER_DIR/.progress.jsonl"
RUN_CONFIG="$TRIGGER_DIR/run_config.json"   # dashboard writes which inventory to run

INVENTORY="${NETCOPILOT_INVENTORY:-$PROJECT_ROOT/demo/containerlab/inventory.yaml}"
SITE="${NETCOPILOT_SITE:-demo}"
POLL_INTERVAL="${POLL_INTERVAL:-15}"
PYTHON="${PYTHON:-python3}"

# Run the CLI from the repo with the src/ layout on the path. An installed
# package still resolves; the explicit path makes a bare checkout work too.
export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

# Tell the CLI where to stream live per-stage progress (the dashboard tails it).
export NETCOPILOT_PROGRESS_FILE="$PROGRESS_FILE"

# Graceful SIGTERM/SIGINT handling: remove the request flag so a pending trigger
# is not orphaned across a restart.
_cleanup() {
  echo "[run-watcher] Received signal — cleaning up flag files and exiting"
  rm -f "$FLAG_REQUESTED"
  exit 0
}
trap '_cleanup' TERM INT

echo "[run-watcher] Starting. Watching $FLAG_REQUESTED every ${POLL_INTERVAL}s"
echo "[run-watcher] Project root: $PROJECT_ROOT"
echo "[run-watcher] Inventory:    $INVENTORY"
echo "[run-watcher] Site:         $SITE"

mkdir -p "$TRIGGER_DIR"

while true; do
  if [ -f "$FLAG_REQUESTED" ]; then
    echo "[run-watcher] Run request detected at $(date -u +%FT%TZ)"
    rm -f "$FLAG_REQUESTED"

    cd "$PROJECT_ROOT"
    # Re-source .env per run so credential/token updates (e.g. a regenerated
    # FortiGate key after a lab redeploy) are picked up without a restart.
    if [ -f "$PROJECT_ROOT/.env" ]; then
      set -a
      # shellcheck disable=SC1091
      source "$PROJECT_ROOT/.env"
      set +a
    fi
    # Activate a repo-local venv if present; otherwise use PYTHON as-is.
    # shellcheck disable=SC1091
    source .venv/bin/activate 2>/dev/null || true

    # What did the dashboard ask us to run? run_config.json names an inventory to
    # collect, or the demo to replay offline. Falls back to the env inventory.
    MODE="collect"; RUN_INV="$INVENTORY"; RUN_SITE="$SITE"
    if [ -f "$RUN_CONFIG" ]; then
      MODE=$("$PYTHON" -c "import json;print(json.load(open('$RUN_CONFIG')).get('mode','collect'))" 2>/dev/null || echo collect)
      RUN_INV=$("$PYTHON" -c "import json;print(json.load(open('$RUN_CONFIG')).get('inventory',''))" 2>/dev/null || echo "$INVENTORY")
      RUN_SITE=$("$PYTHON" -c "import json;print(json.load(open('$RUN_CONFIG')).get('site','demo'))" 2>/dev/null || echo "$SITE")
    fi

    # Signal pipeline start to the progress file the dashboard tails.
    echo "{\"ts\":\"$(date -u +%FT%TZ)\",\"stage\":\"watcher_start\",\"message\":\"Pipeline starting...\"}" >> "$PROGRESS_FILE"

    if [ "$MODE" = "demo" ]; then
      echo "[run-watcher] Replaying demo '$RUN_INV' (offline, no devices)"
      RUN_CMD=(env "NETCOPILOT_DEMO_RUN=$RUN_INV" "NETCOPILOT_DEMO_SITE=$RUN_SITE" "$PYTHON" -m netcopilot.demo_seed)
    else
      echo "[run-watcher] Collecting inventory=$RUN_INV site=$RUN_SITE"
      RUN_CMD=("$PYTHON" -m netcopilot.cli run --inventory "$RUN_INV" --site "$RUN_SITE" --runs-dir "$RUNS_DIR")
    fi

    if "${RUN_CMD[@]}"; then
      echo "[run-watcher] Run completed successfully at $(date -u +%FT%TZ)"
    else
      echo "[run-watcher] Run failed at $(date -u +%FT%TZ)" >&2
      echo "{\"ts\":\"$(date -u +%FT%TZ)\",\"stage\":\"error\",\"message\":\"Pipeline failed\"}" >> "$PROGRESS_FILE"
    fi
    rm -f "$RUN_CONFIG"

    # Signal completion regardless of success/failure — the dashboard refreshes.
    date -u +%FT%TZ > "$FLAG_COMPLETE"
    echo "[run-watcher] Completion flag written"
  fi

  # Sleep in the background + wait so a signal interrupts immediately.
  sleep "$POLL_INTERVAL" & wait $!
done
