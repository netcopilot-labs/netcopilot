# NetCopilot — System Overview

NetCopilot is **Network Context Intelligence**: it collects a multi-vendor
network **read-only**, turns it into one deterministic, verifiable **graph** —
the source of truth — and serves that graph over **MCP** to humans, LLMs, and
agents.

```mermaid
flowchart LR
  NET["Your Network<br/>multi-vendor"]:::net
  PIPE["Collect → Parse → Model → Rules"]:::pipe
  GDB[("Graph — source of truth<br/>topology + findings")]:::hub
  RAG[("RAG<br/>vendor docs")]:::store
  MCP["MCP Server<br/>the single doorway (tools)"]:::mcp
  ORCH["Orchestrator<br/>calls an LLM"]:::cons
  CHAT["Dashboard / Telegram"]:::cons
  USER["User"]:::user
  CLIENTS["LLMs / agents / other tools<br/>any MCP client"]:::cons

  NET -->|read-only collect| PIPE --> GDB
  MCP --> GDB
  MCP --> RAG
  ORCH --> MCP
  CLIENTS --> MCP
  USER --> CHAT --> ORCH

  classDef net   fill:#1f2937,stroke:#64748b,color:#e5e7eb
  classDef pipe  fill:#0f3b3a,stroke:#2dd4bf,color:#e6fffb
  classDef hub   fill:#063b36,stroke:#22d3ee,color:#ccfbf1,stroke-width:2px
  classDef store fill:#0f3b3a,stroke:#2dd4bf,color:#e6fffb
  classDef mcp   fill:#1e1b4b,stroke:#a78bfa,color:#ede9fe,stroke-width:2px
  classDef cons  fill:#172554,stroke:#60a5fa,color:#dbeafe
  classDef user  fill:#1f2937,stroke:#94a3b8,color:#e5e7eb
```

## How to read it — three layers and one door

1. **Ingest (read-only, one-way).** `Collect → Parse → Model → Rules` reads your
   multi-vendor network and **never writes back to it**. The pipeline produces
   the topology model *and* the findings.
2. **The source of truth.** Everything lands in one **graph** — topology and
   findings together. Deterministic and reproducible: the same inputs always
   produce the same graph, and every answer traces back to evidence.
3. **The doorway.** The **MCP Server** is the single interface over the graph
   (plus a RAG store of vendor docs). Nothing reaches the model except through it.
4. **Consumers.** Anything that speaks MCP queries the source of truth — the
   built-in chat (Dashboard / Telegram) via an **Orchestrator** that calls an
   LLM, or any external **LLM, agent, or tool** as its own MCP client.

**Principles:** read-only on the network · deterministic & verifiable ·
multi-vendor · MCP-native · bring-your-own model.

> **Extensible by design.** MCP is the extension point — any new context source
> or consumer plugs into the same doorway, with no change to the core.

For the per-layer detail (pipeline, graph data model, orchestration, deployment),
see the [detailed architecture](README.md).
