# Golden Master — determinism regression net (R1)

A frozen, canonical snapshot of the pure `facts -> (model, findings)` function,
used to prove the BGP+OSPF determinism refactor changes **nothing it didn't mean
to** (Phase 1) and **exactly what it meant to** (Phase 2).

It is a **regression net, not a correctness oracle**: it freezes *current* output,
known bugs included. [`LEDGER.md`](LEDGER.md) records which frozen outputs are
known-wrong Phase-2 targets — and, importantly, which audit findings the demo
snapshot **cannot** prove (so they get targeted tests instead).

## What is committed vs local

| Artifact | Location | Committed? | Why |
|---|---|---|---|
| Expected snapshot | `demo/snapshot.json` | **yes** | secret-free; its git diff *is* the Class-A/B/C delta review |
| Ledger | `LEDGER.md` | **yes** | maps audit → snapshot deltas |
| Demo **facts** (input) | `runs/2026-06-23_09-16-04/` | **no — gitignored** | carry lab config password/secret hashes; never published |
| Real-hardware golden master | `runs/golden/hw/` | **no — gitignored** | real network data; local verification only |

The snapshot is **Neo4j-free** (model dict + findings, both pure functions of the
facts), so it runs with no database. The graph/loader layer keeps its own test
suite (`tests/test_graph_load_*`).

> The committed snapshot is only re-derivable where the (gitignored) source facts
> are present — i.e. locally during the refactor. CI-gated parity would require
> committing scrubbed facts; deferred unless we want it (see LEDGER honest-limit).

## Usage

```bash
# capture / re-capture the expected snapshot (Phase 2: after a deliberate fix)
python scripts/golden_master.py capture \
    --runs-base runs --run 2026-06-23_09-16-04 --out fixtures/golden/demo/snapshot.json

# Phase-1 gate: a refactored build must be identical to the frozen snapshot
python scripts/golden_master.py check \
    --runs-base runs --run 2026-06-23_09-16-04 --against fixtures/golden/demo/snapshot.json

# cheap determinism check: two consecutive builds must be byte-identical
python scripts/golden_master.py selfcheck --runs-base runs --run 2026-06-23_09-16-04
```

Volatile metadata (`detected_at` timestamps) is normalised out — see
`_VOLATILE_KEYS` in `scripts/golden_master.py`.
