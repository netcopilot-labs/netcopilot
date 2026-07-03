# NetCopilot Constitution

These are the operating principles every NetCopilot feature, rule, and tool is
judged against. They are not aspirations — a change that violates an article is
rejected, whatever else it offers. Contributions are reviewed against this file.

## Article I — Context, never actuation

NetCopilot reads networks and produces evidence; it never pushes changes to
devices. Collection is read-only on every transport. Any capability that would
actuate — apply config, restart services, modify state — is out of scope by
definition, not by omission.

## Article II — Determinism over cleverness

Deterministic systems produce truth; AI explains it — never the other way
around. Checks, diffs, findings, and verdicts come from deterministic code
whose output is reproducible run over run. The LLM narrates and routes; it is
never the source of a factual claim about the network.

## Article III — Null over guessing

When evidence is missing, NetCopilot says so and stays silent. An honest
"no data collected for this device" beats a plausible fabricated value every
time. Tools name their failure modes explicitly — unavailable, not found,
no data — instead of returning something that merely looks like an answer.

## Article IV — Least privilege in config

What a consumer can reach is declared in explicit configuration — read-only
tool surfaces, allow-lists, scoped credentials — not implied by whichever code
paths happen to exist. Narrowing access must never require a code change.

## Article V — Machine-enforced contracts over prose

A contract that matters is validated by code: schemas, executable rule specs,
tests, golden snapshots. Documentation describes the contract; it never
substitutes for it. Where a description and an enforced check disagree, the
description is the bug.

## Article VI — Every claim traceable to evidence

Each finding and answer traces to collected data — a run, a device, a field.
If a claim cannot cite its source, it does not ship. This applies to the
system's own self-descriptions too: counts and capabilities in docs must match
what the code measurably does.

---

**How this is enforced today:** read-only collection adapters and MCP tools
(Article I); the deterministic rules engine and run-to-run diff (Article II);
explicit unavailable/not-found/no-data tool responses (Article III);
env-driven, least-privilege configuration (Article IV); catalog `eval`
validation, the test suite, and golden snapshots (Articles V–VI).
