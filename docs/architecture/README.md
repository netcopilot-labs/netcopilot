# Architecture

NetCopilot is a **Network Context Agent**: it builds a *deterministic, verifiable
model* of a multi-vendor network from read-only collection, stores it as a graph,
and exposes it over **MCP** so any consumer — a human in the dashboard, an LLM, a
chat bot, or another agent — can ask grounded, traceable questions about it.

Two ideas shape everything below:

- **Evidence over inference.** Every node, link, and finding is derived from
  collected device output, not guessed. The model is reproducible: the same
  inputs always produce the same graph.
- **One model, many consumers.** The pipeline produces a single graph; the
  dashboard, the chat agent, RAG, and Telegram are all just *readers* of it over
  one MCP surface.

---

## 1. The pipeline — from devices to a graph

Collection is read-only and runs a strategy chain per device, falling back until
one succeeds. Each stage writes a stable, inspectable artifact, so any run can be
replayed or audited.

```mermaid
flowchart LR
  INV["Inventory<br/>(YAML / folder per tenant)"] --> COL
  subgraph COL["Collect (read-only)"]
    direction TB
    C1["pyATS"] --> C2["NETCONF"] --> C3["RESTCONF"] --> C4["REST (FortiGate)"] --> C5["SSH"]
  end
  COL --> PAR["Parse<br/>canonical JSON facts"]
  PAR --> MOD["Model<br/>link-builder + model-builder"]
  MOD --> RUL["Rules<br/>3-phase engine"]
  RUL --> FND["Findings"]
  MOD --> NEO[("Neo4j<br/>the graph")]
  FND --> NEO
```

| Stage | What it does |
|---|---|
| **Inventory** | Devices to collect (`name`, `mgmt_ip`, `os`, `role`, `site`). One YAML for a single network, or a self-contained folder per tenant (`lab.yaml` + `credentials.env`). |
| **Collect** | Per device, tries `pyATS → NETCONF → RESTCONF → REST → SSH` until one works. Cisco over the SSH/NETCONF stack; FortiGate over its REST API. Strictly read-only — NetCopilot never changes a device. |
| **Parse** | Normalizes raw output into canonical JSON facts, so the layers above don't care which protocol or vendor produced them. |
| **Model** | The link-builder turns per-device facts into a typed, **evidence-backed** topology (see [link-builder.md](link-builder.md)); the model-builder assembles devices, interfaces, VLANs, routing, and shared services. |
| **Rules** | A 3-phase engine (per-device → catalog → cross-device) evaluates the model and emits **Findings** with severities and evidence. |
| **Load** | The model + findings are written to Neo4j as one run, isolated by `site` + `run_id`. |

---

## 2. The graph — one model, isolated per run

Everything downstream reads Neo4j. Each collection is a `Run`; multiple sites and
re-runs coexist, isolated by `site` + `run_id`, so history and multiple tenants
never collide.

```mermaid
flowchart TD
  RUN(["Run<br/>site + run_id"]) --> DEV["Device"]
  DEV --> IFACE["Interface"]
  DEV --> VLAN["VLAN"]
  DEV --> FW["FirewallPolicy"]
  DEV --> ROUTE["Route / VRF"]
  IFACE -- "PHYSICAL_LINK" --> IFACE
  DEV -- "ROUTING_ADJACENCY (OSPF/BGP)" --> DEV
  FND["Finding<br/>severity + evidence"] -. "about" .-> DEV
  FND -. "about" .-> IFACE
```

The graph is the **contract**: tools query it with Cypher, never the devices.
Because the model is deterministic and evidence-backed, an answer can always be
traced back to the device output that produced it.

---

## 3. Consumers & the agent — MCP at the center

The model is exposed as **MCP tools** (get topology, trace a path, list findings,
look up vendor docs, …). The dashboard and Telegram are MCP clients; an LLM turns
a natural-language question into the right tool calls and grounds its answer in
the results.

```mermaid
flowchart TD
  USER["User<br/>(dashboard chat / Telegram)"] --> AGENT
  AGENT["Agent loop"] --> MCP["MCP Server<br/>(tools)"]
  MCP --> NEO[("Neo4j")]
  MCP --> RAG[("RAG<br/>vendor PDFs / ChromaDB")]
  AGENT --> REG["Model registry<br/>(models.yaml)"]
  REG --> LOCAL["Local model<br/>(on-prem, no anonymization)"]
  REG --> CLOUD["Cloud model<br/>(Claude / Gemini / GPT)"]
  AGENT -- "context" --> ANON["Anonymizer"]
  ANON -- "only for cloud" --> CLOUD
```

- **BYO model.** `models.yaml` lists local (vLLM/Ollama) and cloud (Claude /
  Gemini / any OpenAI-compatible) models; keys live in `.env` by name.
- **Privacy boundary.** Local models keep everything on-prem. For a cloud model,
  device names and addresses are run through the **anonymizer** before the request
  leaves the host.
- **RAG.** Vendor PDFs are embedded into ChromaDB; the agent retrieves relevant
  passages to ground answers, alongside the graph.

---

## 4. Deployment — one image, a few services

Everything ships as one Docker image driven by `docker compose`. The dashboard
never collects directly: a **watcher** runs the pipeline wherever it can reach the
devices, decoupling the UI from collection dependencies.

```mermaid
flowchart LR
  subgraph HOST["docker compose"]
    NEO[("neo4j")]
    DASH["dashboard<br/>(FastAPI + React SPA)"]
    MCPS["mcp<br/>(HTTP)"]
    TG["telegram"]
    WATCH["watcher<br/>(runs the pipeline)"]
  end
  DASH --> NEO
  MCPS --> NEO
  TG --> DASH
  WATCH --> NEO
  WATCH -- "read-only collect" --> NET["Your devices"]
  DASH -. "chat" .-> LLM["LLM<br/>(local or cloud)"]
```

| Service | Role |
|---|---|
| **neo4j** | The graph store. |
| **dashboard** | FastAPI backend + React SPA: topology, findings, reports, chat. Triggers runs via a flag file the watcher polls. |
| **mcp** | The MCP server over HTTP, for any external MCP client. |
| **telegram** | Optional bot; same agent, from your phone. |
| **watcher** | Executes collect → parse → model → rules → load when a run is requested. |

---

## 5. Design principles

- **Read-only on the network.** NetCopilot collects and reports; it never changes
  device configuration.
- **Deterministic & reproducible.** Same inputs → same graph; every finding traces
  back to evidence.
- **Multi-vendor, extensible.** Cisco (IOS-XE / IOS-XR) and Fortinet today; the
  strategy chain and parsers are built to add more.
- **Bring your own.** Model, inventory, RAG documents, Telegram bot, and SMTP are
  all yours, configured via `.env` + `models.yaml` — no code changes.
- **MCP-native.** One model, one tool surface; every consumer is a reader.

---

## Per-layer documents

- [The Link Builder](link-builder.md) — how per-device facts become a typed,
  evidence-backed topology (discovery methods, MAC fingerprinting, deduplication,
  classification).
