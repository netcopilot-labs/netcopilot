# NetCopilot — Network Context Agent

> **Status:** v1 in progress. Public API and quickstart are being prepared.

**What it is.** NetCopilot is an open-source **Network Context Agent**: a
deterministic, verifiable model of a multi-vendor network, exposed so any
consumer — a human, an LLM, or another agent — can query it for grounded,
traceable answers.

**Core axiom — context, never actuation.** NetCopilot never acts on the
network. It supplies deterministic truth and context; the consumer (human,
agent, or LLM) is the one that decides and acts. *Deterministic systems
produce truth; AI explains it — never the other way around.* It produces
findings, context, and answers, and stays silent when it has no evidence —
but it never pushes changes to devices.

**Consumed by humans, LLMs, and other agents.** The model is exposed over MCP
so any reasoning agent can call it for grounded context. An agent consuming
NetCopilot as its ground-truth layer is the key proof of the pattern.

## Architecture (spine)

```
Inventory (YAML)
  → Collect (pyATS / NETCONF / RESTCONF · Cisco + Fortinet · extensible)
    → Parse (canonical JSON)
      → Rules & Findings
        → Neo4j (the graph)
          → [ Dashboard · RAG · Telegram ] over
            → MCP Server (the base)
              → LLM (configurable: Claude API / Ollama)
```

## Bring your own network

NetCopilot ships **no network data**. You point it at your own network
(your inventory, your devices) and it builds the context from what it collects.

## Quickstart (Docker — one command)

Requires **Docker** (Docker Desktop on Windows/macOS, with WSL2 on Windows). No
Python, Node, GPU, or lab needed.

> New to Docker or want every step explained? See the full
> **[INSTALLATION.md](INSTALLATION.md)** guide.

```bash
git clone <repo-url> && cd netcopilot
cp .env.example .env                  # set NEO4J_PASSWORD
cp models.example.yaml models.yaml    # your model registry
docker compose up                     # builds the image on first run (~10–15 min)
```

Open **http://localhost:8080** — the dashboard starts **empty** (it ships no
network data). With **`Demo — campus network`** selected in the inventory
dropdown, click **▶ Run Now**: it replays a bundled **synthetic 8-device
capture** (offline, no devices needed) and populates the topology + findings in a
few seconds. Neo4j browser is at **http://localhost:7474**; the MCP server at
**http://localhost:3002/mcp**.

The first build is large (the image bundles collection, RAG, PDF reports and the
Telegram bot). Data persists in named volumes across `docker compose down`; add
`-v` to wipe.

## Bring your own (all optional, all via `.env` + `models.yaml`)

- **Any LLM (chat).** Edit `models.yaml` — local (Ollama/vLLM, on-prem, no
  anonymization) or commercial (Claude / GPT / Gemini, auto-anonymized before any
  data leaves the host). Put the key in `.env` (`ANTHROPIC_API_KEY` etc.); pick a
  cloud-only default by setting `default:` in `models.yaml` or in the dropdown.
  Reach a local LLM from the container via `http://host.docker.internal:<port>/v1`.
  Without a model, everything but chat still works.
- **Your network(s).** Two shapes, pick by scale — both show in the inventory
  dropdown, press **Run Now** to collect:
  - **One network** — drop a flat `inventory/<name>.yaml` (copy
    `examples/inventory.yaml`, replace the devices); credentials come from the
    root `.env`.
  - **Multitenant** — give each tenant a **self-contained folder** with its own
    secrets (add a tenant = drop a folder, nothing shared):
    ```
    inventory/<tenant>/
      lab.yaml          # devices: name, mgmt_ip, os, role, site
      credentials.env   # NETCOPILOT_SSH_USERNAME / _PASSWORD / _ENABLE_PASSWORD
                        # + NETCOPILOT_FORTIGATE_API_TOKEN (gitignored)
    ```
  The collector reaches your devices from the container (pyATS → NETCONF →
  RESTCONF → SSH); sites are isolated in the graph by `site` + `run_id`. `os`
  accepts `ios-xe`/`iosxe`/`ios-xr`/`iosxr`/`fortios` (any case). No hardware?
  `demo/containerlab/` exercises collection end to end.
- **Your documents (RAG).** The vector store ships empty. Drop PDFs in
  `./knowledge_base/`, then ingest:
  ```bash
  docker compose exec dashboard \
    python -m netcopilot.rag.ingest --docs-dir /app/knowledge_base
  ```
- **Your Telegram bot.** Set `TELEGRAM_BOT_TOKEN` (from @BotFather) and
  `TELEGRAM_ALLOWED_USERS` in `.env`, then `docker compose up -d telegram`.
- **Your email (reports).** Set the `SMTP_*` block in `.env` (any SMTP server).
  Reports always generate as PDF; SMTP only adds emailing.

## Removing the demo data (production deployments)

NetCopilot ships with synthetic demo labs (`Demo — campus network`, etc.) so you
can see it working before connecting anything. They contain **no real data**, but
on a production install serving your own network you'll want a clean slate.

**Demo runs you loaded** (anything you populated with ▶ Run Now) — delete each
from the dashboard: click the **🗑** next to the run in the **Run** dropdown. That
removes its graph data **and** its on-disk files. Headless equivalent (graph
data; the `runs/<id>` folder can then be removed from the `runs` volume):

```bash
docker compose exec dashboard python -m netcopilot.cli neo4j runs                       # list loaded runs
docker compose exec dashboard python -m netcopilot.cli neo4j delete <run_id> --site <site>
```

The dashboard starts **empty**, so if you never ran a demo there's nothing here to
delete.

**Demo inventories** (the `Demo — …` entries in the inventory dropdown) are bundled
into the image. To hide them on a production install, set one variable in `.env`
— no rebuild, no file edits:

```dotenv
NETCOPILOT_HIDE_DEMOS=1
```
```bash
docker compose up -d dashboard       # picks up the new env
```

The dropdown then shows only your own inventories from `inventory/`. To remove the
demos from the image **permanently** instead, delete their source directories and
rebuild: `rm -rf demo/campus demo/branch demo/l2-campus && docker compose up -d --build dashboard watcher`.
(`demo/containerlab/` is a collection sandbox, not a dropdown demo — keep it for a
no-hardware way to exercise live collection, or remove it too.)

## Developing (without Docker)

```bash
make install             # pip install -e ".[dev]"
make test                # run the test suite
```

## License

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contributing

A clean collector interface lets you add vendor support without touching the
core. See [CONTRIBUTING.md](CONTRIBUTING.md).
