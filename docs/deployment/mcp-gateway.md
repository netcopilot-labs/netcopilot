# Multi-client deployments — least privilege in config

NetCopilot's MCP server exposes the **full read surface** — every tool, to any
client that can reach the endpoint. That is the right default for a
single-operator install. The moment several clients (a chat assistant, an
audit bot, a dashboard, another team's agent) share one NetCopilot, three
questions appear that the server deliberately does not answer itself:

- **Who may call what?** The audit bot needs `validate_change` and
  `get_findings`; it has no business generating reports or tracing paths.
- **What do clients configure?** One URL, whatever happens behind it.
- **Where is the audit trail?** One place that sees every tool call.

The answer is an **MCP gateway** in front of NetCopilot, with a per-client
tool allow-list — the same principle as NetCopilot's own constitution
(Art. IV: *least privilege in config, not code*). Any MCP gateway with a tool
allow-list implements this pattern; the examples below use
[gridctl](https://github.com/gridctl/gridctl) (Apache-2.0, one-YAML
configuration), which we validated end-to-end against NetCopilot.

## Quick start (optional, one command)

The gateway is **opt-in and never part of the NetCopilot stack**: gridctl is
a young project evolving quickly (beta releases), so it installs on demand,
next to the stack, not inside it:

```bash
./scripts/install-gateway.sh            # personas stack (see below)
./scripts/install-gateway.sh full       # full read surface
```

The script installs the latest gridctl release (via its official installer),
applies the chosen example stack against your running NetCopilot, and
**verifies the gateway live** — it fails loudly if the tool surface doesn't
match expectations, so a future gateway release can never break you silently.

Your NetCopilot MCP endpoint defaults to `http://localhost:3002/mcp`; if you
changed `MCP_PORT`, set `NETCOPILOT_MCP_URL` accordingly.

## The two example stacks

### Full read surface

[`examples/gateway/full-read-surface.yaml`](../../examples/gateway/full-read-surface.yaml) —
every NetCopilot tool through one gateway endpoint
(`http://localhost:8180/mcp`), namespaced by server name
(`netcopilot__query_topology`, `netcopilot__validate_change`, …).

### Personas — the allow-list at work

[`examples/gateway/personas.yaml`](../../examples/gateway/personas.yaml) —
two clients' views of the **same** NetCopilot:

- **change-audit** — may judge changes and read findings, nothing else:
  `validate_change`, `diff_runs`, `get_findings`.
- **topology-viewer** — structure and paths only:
  `query_topology`, `get_device_detail`, `trace_path`.

The gateway lists exactly six tools (measured):

```
change-audit__diff_runs
change-audit__get_findings
change-audit__validate_change
topology-viewer__get_device_detail
topology-viewer__query_topology
topology-viewer__trace_path
```

An agent wired to the `change-audit` persona can gate a change pipeline — and
*cannot* call anything else, because the tools simply are not there. Narrowing
or widening a persona is a YAML edit (hot-reloaded), not a NetCopilot change.

## Notes & current limits

- **Beta pace.** gridctl releases frequently; the examples here were validated
  against `v0.1.0-beta.13`. The installer's built-in verification re-checks on
  every install — if something moves, you find out immediately, not silently.
- **Namespaced names.** Clients see `server__tool` (e.g.
  `netcopilot__trace_path`). Transparent for LLM clients; relevant if an
  integration hardcodes tool names.
- **Structured results travel through the gateway** since gridctl
  v0.1.0-beta.14 (the upstream fix we contributed,
  [gridctl#849](https://github.com/gridctl/gridctl/pull/849), verified
  end-to-end against NetCopilot 2026-07-30): clients behind the gateway
  receive the text AND the machine-readable `{status, verdict}` structured
  content, identical to a direct connection. Machine consumers of the
  change-validation verdict no longer need to bypass the gateway. On
  gridctl releases older than beta.14 the structured part is dropped;
  upgrade rather than work around.
- **Tool groups** (gridctl beta.15+): an optional `groups:` block serves
  curated tool bundles at per-group endpoints (`/groups/{name}/mcp`) — a
  third curation axis alongside per-server whitelists and client scoping,
  useful for handing one client a deliberately tiny surface.
- **Platforms.** gridctl ships Linux and macOS binaries.

## When to skip the gateway

One operator, one client, trusted host → connect directly to `:3002/mcp`.
The gateway earns its place when clients multiply or when you need the
allow-list/audit posture. NetCopilot itself is identical either way —
read-only, deterministic, and unaware of what sits in front of it.
