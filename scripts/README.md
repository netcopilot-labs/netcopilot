# scripts/

Operational helpers that run **outside** the dashboard container.

## run-watcher.sh — make the dashboard "Run Now" button work

The dashboard never runs collection itself. "Run Now" writes a request flag under
`runs/.trigger/`; this **watcher** executes the pipeline wherever it has network
reach to the devices, then signals completion so the dashboard refreshes. This
keeps the dashboard free of collection dependencies (pyATS, SSH credentials,
device reachability).

Without a watcher running, "Run Now" shows
*"Pipeline has not started after 60s. Is the run watcher running?"* — the flag was
written but nothing consumed it.

### Run it as a service (recommended — always on, like production)

```bash
sudo cp scripts/netcopilot-watcher.service /etc/systemd/system/
sudo sed -i "s#__INSTALL_DIR__#$(pwd)#; s#__USER__#$USER#" \
  /etc/systemd/system/netcopilot-watcher.service
sudo systemctl daemon-reload
sudo systemctl enable --now netcopilot-watcher      # starts now + on every boot
journalctl -u netcopilot-watcher -f                 # watch it
```

After that, clicking **Run Now** in the dashboard just works — no per-run setup.

### Or run it in the foreground (dev)

```bash
./scripts/run-watcher.sh
# or detached: nohup ./scripts/run-watcher.sh >> /tmp/run-watcher.log 2>&1 &
```

### Credentials — set once, in `.env` (nothing to export)

The watcher auto-sources the repo-local `.env` (gitignored). The bundled
containerlab demo accepts **admin/admin**, which the watcher assumes by default —
so the demo needs no credentials at all. For a real network, set them once in
`.env` (see `.env.example`): `NETCOPILOT_SSH_USERNAME` / `NETCOPILOT_SSH_PASSWORD`,
optional `NETCOPILOT_FORTIGATE_API_TOKEN`, and `NEO4J_PASSWORD` (must match the
dashboard's). Override `NETCOPILOT_INVENTORY` / `NETCOPILOT_SITE` to target your
own network instead of the demo.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `RUNS_DIR` | `<repo>/runs` | Where run folders are written (must match the dashboard's `RUNS_DIR`) |
| `NETCOPILOT_INVENTORY` | `demo/containerlab/inventory.yaml` | Inventory YAML to collect from |
| `NETCOPILOT_SITE` | `demo` | Site identifier for multi-site isolation |
| `NETCOPILOT_SSH_USERNAME` / `_PASSWORD` | `admin` / `admin` | Device SSH credentials |
| `POLL_INTERVAL` | `15` | Seconds between flag checks |
| `PYTHON` | `python3` | Interpreter (a repo-local `.venv` is auto-activated if present) |

The watcher exports `NETCOPILOT_PROGRESS_FILE` so the CLI streams live per-stage
progress (collect → parse → model → rules → load → done) to the dashboard.
