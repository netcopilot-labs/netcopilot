# NetCopilot — Network Context Intelligence

> Source-of-truth for humans, LLMs, and agents.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.2.0-informational.svg)](https://github.com/netcopilot-labs/netcopilot/releases)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

<p align="center">
  <img src="docs/img/architecture.png" alt="NetCopilot — read-only multi-vendor collection into a deterministic graph model, served over MCP to humans, LLMs, and agents" width="900">
</p>

<p align="center">
  <a href="https://youtu.be/5V_NQJ8VEhY" target="_blank" rel="noopener noreferrer"><b>▶ Watch the demo</b></a>
</p>

**What it is.** NetCopilot is open-source **Network Context Intelligence**: a
deterministic, verifiable model of a multi-vendor network, exposed so any
consumer — a human, an LLM, or another agent — can query it for grounded,
traceable answers.

**Core axiom — context, never actuation.** NetCopilot never acts on the
network. It supplies deterministic truth and context; the consumer (human,
agent, or LLM) is the one that decides and acts. *Deterministic systems
produce truth; AI explains it — never the other way around.* It produces
findings, context, and answers, and stays silent when it has no evidence —
but it never pushes changes to devices. This axiom and the operating
principles behind it are codified in [CONSTITUTION.md](CONSTITUTION.md).

**Consumed by humans, LLMs, and other agents.** The model is exposed over MCP
so any reasoning agent can call it for grounded context. An agent consuming
NetCopilot as its ground-truth layer is the key proof of the pattern.

## What can NetCopilot do?

NetCopilot answers questions about your network from one deterministic,
evidence-backed model — organized by what you're trying to do. *(Or just ask it:
"what can you do?")*

- 🔍 **Explore** — devices, links, topology, per-device detail; VLANs / subnets / OSPF areas / BGP ASNs / IP lookups; HSRP/VRRP gateway groups (which router is the active gateway).
- 🔥 **Troubleshoot** — active findings & compliance violations, why they matter and how to fix them, priority ranking, systemic multi-device issues, **what changed between two runs (drift)**, and **change validation**: a deterministic pass/warn/fail verdict on whether only the intended devices changed (CLI exit codes make it a pipeline gate).
- 🛣 **Trace** — hop-by-hop path tracing, blast radius ("what breaks if X fails"), SPOF / HA status, HSRP/VRRP gateway redundancy, routing tables, OSPF detail.
- 🛡 **Security** — AAA / SSH / SNMP / NTP / logging posture, firewall rules & ACLs, QoS shaping.
- 📚 **Vendor docs** — Cisco IOS-XE / IOS-XR / FortiOS CLI reference + conceptual networking knowledge (works with no network loaded).
- 📊 **Reports** — shift-handover report, investigation case-file; email or PDF.
- 📖 **About** — what NetCopilot is, how the dashboard works.

All exposed over **MCP** — a human, an LLM, or another agent can call any of it.
The server offers two surfaces, chosen at startup with `MCP_SURFACE`:

- **`full` (default)** — every tool, generated from the registry, exactly as
  the internal agent sees them. For clients that want fine-grained
  composition. Cost: the full schema set (~5,500 tokens) enters the client's
  context each turn.
- **`ask`** — a single tool, `ask_netcopilot(question)`, that runs
  NetCopilot's complete internal agent server-side (deterministic routing,
  the whole toolset, the eval-guarded answer quality) and returns the
  grounded answer plus which tools it used. ~100 schema tokens in the
  client's context. Expect 10-60 s per call: a full agent conversation runs
  behind it.

Results carry a machine-readable `status` (and a `verdict` where the
tool computes one) as MCP structured content alongside the text; tool errors map
to MCP-native `isError`. The in-app menu (`list_capabilities`) is always the
current source of truth. Serving several clients? Put an MCP gateway in front
and give each client only the tools its job needs — see
[Deploying behind an MCP gateway](docs/deployment/mcp-gateway.md).

## Architecture

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

This README is the quick entry point; the detail lives in the architecture docs:

- **[System overview](docs/architecture/overview.md)** — the whole platform in one diagram.
- **[Detailed architecture](docs/architecture/README.md)** — the pipeline, the graph + multitenancy, the orchestrator, deployment, and the roadmap.

### Auditable tool routing — the model never picks a device command, and known intents don't even pick the tool

The layer that talks to devices is fully deterministic: per-vendor adapters
(pyATS/Genie, NETCONF, FortiOS REST) decide every command — no LLM anywhere in
collection. The model only reasons over already-collected, structured results.

Tool *selection* is deterministic-first: a versioned catalogue
([`routing.yaml`](src/netcopilot/mcp/routing.yaml)) maps known question
intents to tools, and every decision is emitted as an auditable `routing`
event. For intents with static arguments the orchestrator **calls the routed
tool itself** — selection and invocation with zero model involvement; the
model only narrates the result. Unmatched questions fall back to model choice
over the full registry. Every catalogue entry must cite the **documented
failure** that motivated it — entries without evidence are rejected at load.
Fixing a misroute is a reviewable YAML diff, not prompt surgery;
`scripts/eval/` measures routing accuracy and answer completeness against a
question catalogue, and its failures are what populate the routing table.

> 🧪 **The lab of ideas** — deep-dives into each layer, experiments, and where
> NetCopilot is heading live at **[netcopilot.io](https://netcopilot.io)**.

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
  accepts `ios-xe`/`iosxe`/`ios-xr`/`iosxr`/`fortios` (any case).
- **Your documents (RAG).** The vector store ships empty. Drop PDFs in
  `./knowledge_base/`, then ingest:
  ```bash
  docker compose exec dashboard \
    python -m netcopilot.rag.ingest --docs-dir /app/knowledge_base
  ```
- **Your NetBox (declared state).** NetCopilot reads your NetBox as the L0
  "what the network *should* look like" layer, and — with explicit opt-in —
  can document what it collected back into NetBox through a staged →
  human-approved → audited pipeline (every write is a reviewable candidate;
  nothing is auto-approved, nothing is ever deleted). It documents the full
  physical and logical picture: devices (stacks as virtual chassis, cluster
  members individually), interfaces, transceivers, VLANs, VRFs, prefixes,
  IP addresses assigned to their interfaces, and cables — typed by the
  optics that terminate them, from high-confidence link evidence only.
  Point `NETBOX_URL` + `NETBOX_API_TOKEN` at your instance, or try the
  bundled demo NetBox:
  ```bash
  docker compose --profile netbox up -d          # local NetBox on :8001
  export NETBOX_URL=http://localhost:8001
  export NETBOX_API_TOKEN=0123456789abcdef0123456789abcdef01234567   # demo token, gitleaks:allow
  export NETBOX_WRITE_ENABLED=true               # writes are OFF by default
  netcopilot netbox bootstrap <run_id> --inventory <your lab.yaml>
  netcopilot netbox pending                      # review what would be written
  netcopilot netbox approve --all                # human approval → NetBox populated
  netcopilot netbox history                      # append-only audit log
  ```
  In chat: *"what does NetBox say about core-sw-01?"*, *"what did NetCopilot
  write to NetBox?"*. Writes require `NETBOX_WRITE_ENABLED=true` — without it
  NetCopilot is a pure reader (see `CONSTITUTION.md`, Article I).

  Once NetBox knows your devices, it can also **be the inventory** — no YAML
  file needed. Each NetBox site with devices appears in the dashboard's
  inventory dropdown as `NetBox: <site>`, and the CLI takes a URI:
  ```bash
  netcopilot run --inventory netbox://<site> --site <site>
  ```
  A device is collectable when it is `active` and carries a **primary IPv4**
  (bootstrap stages it from the address collection actually used; for
  NAT'd/out-of-band management, set it by hand once) and a **platform slug**
  NetCopilot recognizes (`cisco-ios-xe`, `cisco-ios-xr`, `fortinet-fortios` —
  bootstrap creates these). Per-device collect hints and credential
  *references* live in the device's config context under a `netcopilot` key —
  secrets stay in your environment, NetBox only holds the `${ENV_VAR}` name:
  ```json
  {"netcopilot": {"api_token": "${FW1_TOKEN}", "ssh_only": true}}
  ```
  YAML inventories keep working exactly as before — NetBox is an additional
  source, not a replacement (see `inventory/README.md`).

  And once NetBox knows your **end devices** — name an IP with a `dns_name`
  or description ("the lobby camera", "the vision mixer") — NetCopilot joins
  that declared meaning with what the network actually observes (ARP, MAC
  tables) into a **service layer**:
  ```bash
  netcopilot netbox services <run_id>       # the join (or one click in the UI)
  ```
  Services then answer everywhere: *"where is the lobby camera?"*
  (`find_service` — device, port, and how confidently: port-precise /
  gateway / approximate / **never seen** — a documented IP the network has
  no trace of is an answer, not an omission), *"what dies if this switch
  fails?"* (`blast_radius` names the services, not just the neighbors),
  `trace_path` takes a service name or end-host IP as its source, and the
  topology gets a **Service view** drawing each located service on the
  device that serves it. Deterministic plumbing below, agent answers above.

  Tag a NetBox prefix **`client-network`** and it joins as a network-shaped
  service: drawn at its real access switch (its VLAN's member ports), with
  the VLAN, port-channels and their member links in the detail panel. In a
  NetBox serving several sites, scope prefixes to their site and each run's
  Service view shows only its own site's services — an unscoped prefix
  honestly joins everywhere.
- **Your VMware (vCenter / ESXi).** Add one inventory row and NetCopilot
  reads the VM inventory read-only — every VM, its host, vNIC MACs, guest
  IPs, health — and the service layer classifies services **virtual vs
  bare-metal deterministically** (an idle VM leaves no ARP/FDB trace; the
  hypervisor still knows it). The service detail shows guest OS, VMware
  Tools state, CPU/mem, the VM's health, and its node's health/capacity.
  ESXi host names never leave your machine — facts carry generic `node-N`
  labels.
  ```yaml
  # inventory row — a vCenter (whole cluster) or a standalone ESXi host
  - {name: vc-01, mgmt_ip: 192.0.2.5, os: vcenter, site: campus}
  ```
  ```bash
  export ESXi_USERNAME='administrator@vsphere.example'   # read-only account
  export ESXi_PASSWORD='...'
  ```
  One batched read-only API call per collection (`PropertyCollector`);
  power/config APIs are never used — enforced by tests.
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
