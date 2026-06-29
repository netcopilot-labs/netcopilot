# Contributing to NetCopilot

Thanks for being here. NetCopilot is open-source **Network Context Intelligence**,
released under **Apache 2.0** and built to be extended by the community.
Contributions of every size are welcome — from a typo fix to a whole new vendor.

## How it works

New to contributing? It's simpler than it looks, and you're never on the hook —
a maintainer reviews everything before it lands.

- **Found a bug, have an idea, or a question?** Open an **Issue**. That's the
  place to discuss *before* any code — it saves everyone duplicate work.
- **Want to change something?** Fork the repo, make your change on a branch, and
  open a **Pull Request (PR)**. A maintainer reviews it, suggests changes if
  needed, and merges. Small fixes (typos, docs) can go straight to a PR.
- **Bigger or architectural?** (a new integration, a new context source, anything
  touching the core) — **open an Issue first** so we can agree on the approach
  before you invest your time.

## What's most useful

The platform extends at clean seams, so you rarely need to touch the core:

- **New vendor support** — a collector + parsers for a platform we don't cover yet
  (Juniper, Arista, Nokia, …). The single highest-impact contribution.
- **New context sources** — connectors that feed the model or enrich answers
  (CMDBs like NetBox, observability and telemetry, assurance tools). Sketch it in
  an Issue first.
- **New MCP tools** — new questions the model can answer over MCP.
- **Improvements anywhere** — the dashboard, RAG, parsers, the rules engine.
- **Docs and tests** — always welcome, always valued.

## Ground rules

- **Context, never actuation.** NetCopilot reads and models networks; it never
  pushes changes to devices. Every contribution must preserve this — it's the
  core invariant.
- **No real network data.** No real credentials, internal IPs, hostnames, or
  topology in the repo or in tests — use synthetic fixtures.
- **License + sign-off.** By contributing you agree your work is licensed under
  Apache 2.0. Sign your commits (`git commit -s`, Developer Certificate of Origin).
- **Be kind.** Assume good faith and keep it constructive.

## Getting started

See [INSTALLATION.md](INSTALLATION.md) to run it locally, and the
[architecture overview](docs/architecture/overview.md) to see how the pieces fit.
The collector interface and the canonical JSON contract are the seams most
contributions plug into.

## Project name

"NetCopilot" is the name of this project, authored and owned by Carlos Garcia.
Please don't use the name in ways that imply endorsement of forks or derivatives.
