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

## Quickstart

```bash
cp .env.example .env     # set NEO4J_PASSWORD (and your LLM provider)
docker compose up -d     # starts Neo4j — no manual install
make install             # pip install -e ".[dev]"
make test                # run the test suite
```

The synthetic demo seed and the end-to-end CLI land as the spine is completed.

## License

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contributing

A clean collector interface lets you add vendor support without touching the
core. See [CONTRIBUTING.md](CONTRIBUTING.md).
