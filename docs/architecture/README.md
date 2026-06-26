# Architecture

> Stub — the canonical architecture overview is written as the spine lands (F1+).

NetCopilot is a **Network Context Agent**: a deterministic, verifiable model of a
multi-vendor network, exposed over MCP so any consumer — human, LLM, or another
agent — can query it for grounded, traceable answers.

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

Per-layer documents are added as each layer is extracted.

## Per-layer documents

- [The Link Builder](link-builder.md) — how per-device facts become a typed,
  evidence-backed topology (discovery methods, MAC fingerprinting, deduplication,
  classification).
