# Deploying NetCopilot behind an MCP gateway (least privilege in config)

NetCopilot's MCP server exposes the **full read surface** — every tool, to any
client that can reach the endpoint. That is the right default for a
single-operator install. The moment several clients (a chat assistant, an
audit bot, a dashboard, another team's agent) share one NetCopilot, you want
three things the server deliberately does not do itself:

- **Per-client least privilege** — the audit bot needs `validate_change` and
  `get_findings`; it does not need report generation or path tracing.
- **One client-facing endpoint** — clients configure a single URL, whatever
  happens behind it.
- **One audit point** — a single place that sees every tool call.

An **MCP gateway** provides all three *in config, not code* — the same
principle as NetCopilot's own constitution (Art. IV: least privilege in
config). This guide uses [gridctl](https://github.com/gridctl/gridctl), an
Apache-2.0 MCP gateway configured with one YAML file. Any MCP gateway with a
per-server tool allow-list works the same way; the example stacks translate
directly.

> **Status**: validated against gridctl `v0.1.0-beta.13` (2026-07-04).
> gridctl is a young, fast-moving project — re-run the validation commands
> below after upgrading it, and check the [compatibility](#compatibility)
> section first.

## Install gridctl

```bash
curl -fsSL https://raw.githubusercontent.com/gridctl/gridctl/main/install.sh | sh
```

or download a release binary and verify its checksum:

```bash
gh release download -R gridctl/gridctl -p 'gridctl_*_linux_amd64.tar.gz' -p checksums.txt
sha256sum -c <(grep linux_amd64 checksums.txt) && tar xzf gridctl_*_linux_amd64.tar.gz
```

Homebrew, source builds, and container-runtime notes:
[gridctl installation guide](https://github.com/gridctl/gridctl/blob/main/docs/installation.md).

## Stack 1 — full read surface

[`examples/gateway/full-read-surface.yaml`](../../examples/gateway/full-read-surface.yaml)
fronts a running NetCopilot (`docker compose up`, MCP on `:3002` by default —
edit the `url` if you changed `MCP_PORT`):

```bash
gridctl apply examples/gateway/full-read-surface.yaml
# │ netcopilot │ mcp-server │ external  │ running │
# Gateway running url=http://localhost:8180
```

Point any MCP client at `http://localhost:8180/mcp`. It sees every NetCopilot
tool, namespaced by server name (`netcopilot__query_topology`,
`netcopilot__validate_change`, …).

## Stack 2 — personas (the allow-list at work)

[`examples/gateway/personas.yaml`](../../examples/gateway/personas.yaml)
defines two clients' views of the **same** NetCopilot:

- **change-audit** — may judge changes and read findings, nothing else:
  `validate_change`, `diff_runs`, `get_findings`.
- **topology-viewer** — structure and paths only:
  `query_topology`, `get_device_detail`, `trace_path`.

```bash
gridctl apply examples/gateway/personas.yaml
```

The gateway now lists exactly six tools (measured):

```
change-audit__diff_runs
change-audit__get_findings
change-audit__validate_change
topology-viewer__get_device_detail
topology-viewer__query_topology
topology-viewer__trace_path
```

An agent wired to the `change-audit` persona can gate a change pipeline —
and *cannot* call anything else, because the tools simply are not there.
Narrowing or widening a persona is a YAML edit (gridctl hot-reloads the
allow-list), not a NetCopilot change.

## Validate your deployment

With a stack applied, from the NetCopilot repo:

```bash
python - <<'EOF'
import asyncio
from fastmcp import Client

async def main():
    async with Client("http://localhost:8180/mcp") as c:
        tools = await c.list_tools()
        print(len(tools), "tools through the gateway")
        for t in sorted(tools, key=lambda t: t.name)[:6]:
            print(" ", t.name)

asyncio.run(main())
EOF
```

Expected: `26 tools` for the full stack, `6 tools` for personas. Tear down
with `gridctl destroy <stack.yaml>`.

## Compatibility

Measured against gridctl `v0.1.0-beta.13` fronting NetCopilot v1.3.0
(FastMCP streamable-HTTP):

| Property | Through the gateway |
|---|---|
| Tool discovery + `tools:` allow-list | ✅ exact (26 exposed → 26 listed; 6 allowed → 6 listed) |
| Tool descriptions + parameter schemas | ✅ intact |
| Text content of results | ✅ intact |
| Tool errors (`isError` + message) | ✅ preserved |
| Tool names | ⚠️ namespaced `server__tool` (e.g. `netcopilot__trace_path`) — transparent for LLM clients, relevant if you hardcode tool names |
| **MCP `structuredContent`** | ❌ **dropped** — NetCopilot results carry a machine-readable `{status, verdict}` as structured content; the gateway currently forwards only the text. Reported upstream with a fix: [gridctl#848](https://github.com/gridctl/gridctl/issues/848) / [PR gridctl#849](https://github.com/gridctl/gridctl/pull/849) |

**What the last row means in practice:** LLM/chat clients are unaffected —
they read the text, which is identical. But a *machine* consumer of the
change-validation verdict (e.g. a pipeline parsing `verdict.result` instead
of text) should connect to NetCopilot's MCP endpoint directly until the
gateway forwards structured content — we've verified the linked fix restores
full pass-through, so check whether your gridctl version includes it. The
`netcopilot validate` CLI (exit codes 0/1/2) is unaffected — it never crosses
the gateway.

## When to skip the gateway

One operator, one client, trusted host → connect directly to `:3002/mcp`.
The gateway earns its place when clients multiply or when you need the
allow-list/audit posture. NetCopilot itself is identical either way —
read-only, deterministic, and unaware of what sits in front of it.
