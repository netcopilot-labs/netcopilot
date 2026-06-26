# Golden-Master Ledger — R1 BGP + OSPF Determinism Refactor

This ledger is the honest bridge between the **golden master** (a regression net
that freezes *current* output, bugs included) and the **audit** (which says what
is wrong). It records, per audit finding: does it show up in the committed demo
snapshot, what delta the fix will produce, which delta-class it is, and — when
the demo snapshot can't prove it — how it *will* be verified instead.

Read this before accepting any `golden_master.py check` diff.

## Delta classes (the Phase-1 gate)

- **A — zero-delta refactor.** Pure structural move; snapshot must stay
  byte-identical. Any A-diff in Phase 1 = regression, stop.
- **B — convergence delta.** Collapsing two paths that currently *disagree*, or
  pinning a non-deterministic pick. A diff is expected; review, explain, update
  the snapshot, log it here.
- **C — Phase-2 correctness fix.** Deliberate; one entry below; the snapshot
  changes on purpose.

## The honest limit (read this)

The committed demo snapshot (`demo/snapshot.json`) is **multi-VRF but small**, and
it captures only the `facts -> (model, findings)` function — **not** the
dashboard/MCP read paths. Several audit findings therefore **do not appear in it**
and cannot be proven by the demo golden master alone. Those are marked
`verify: …` below and need a targeted test fixture, the (local, gitignored)
real-hardware golden master, or a tool-level test. Silence in the demo snapshot
is **not** proof a bug is gone.

## Findings ledger

| ID | Audit issue | In demo snapshot? | Expected delta | Class | How verified |
|----|-------------|-------------------|----------------|-------|--------------|
| **B4/O-ip** | Shared `iterdir` + collision non-determinism | Not directly (stable on one machine) | none on ref machine; any delta = pinned non-determinism | B | `selfcheck` + Phase-1.1 **order-injection unit test** (reversed/shuffled facts_dirs ⇒ identical model) |
| **O2** | `find_ospf_interface_with_context` / extractors "first match across VRFs" | Not visibly (single match per intf here) | none expected on demo | B | Phase-1.2 unit test: same intf in 2 VRFs ⇒ deterministic, VRF-correct context |
| **B3** | BGP config parsed 3–4× (`routing.py` dup parser missing RR; `link_builder:6316` re-parse) | session_type/RR already correct in model | none in model; **read-path** convergence (routing.py path gains RR fields) | B | dashboard `get_device_bgp` test: Neo4j path == (removed) fallback path |
| **B1** | `session_type` computed in 3 places | values correct (ibgp:3 / ebgp:3) | none in snapshot | A/B | read-path test (stored value read, not recomputed) |
| **B2** | `next_hop_self` / `soft_reconfiguration` hardcoded `False` vs parsed | **absent from model** (not stored) | **adds** `next_hop_self` / `soft_reconfiguration` to BGP adjacencies | **C** | snapshot grows by these keys; values match parsed config |
| **B5** | `bgp_as` from 3 sources | not in this snapshot (read-path/SharedService) | none in snapshot | A/B | read-path test: single source |
| **O1** | Domain rules aggregate across VRFs (router-id dup / ref-bw / spf-timer / single-ABR) | **0 occurrences** (demo doesn't collide across VRF) | none on demo | **C** | **verify:** new multi-VRF unit fixture (same router-id in BLUE + global ⇒ no false dup) — demo can't prove it |
| **O3** | Cross-VRF link → two half-adjacency records | not present (demo config fixed) | none on demo | **C** | **DONE — verified non-issue:** genie's `default` block copies a non-default process's router-id/stats but **0 interfaces/neighbors**; the neighbor-walking extractor never emits a phantom `default`-VRF half-record (demo: 8 OSPF adjacencies, 0 dup `(pair,vrf,area)` keys). Regression test `test_ospf_genie_default_block_copy_no_phantom_adjacency`. |
| **O4** | `get_ospf_detail` area query has no VRF filter | **not in snapshot** (read-time query) | n/a to snapshot | **C** | **verify:** MCP-tool test (area X in 2 VRFs returns VRF-scoped members) |
| **O5** | `OSPF_ADJACENCY_ASYMMETRIC` fires on incomplete (interface-None) data | **2 present** — real vs false TBD | possibly removes false ones | **C** | **verify in Phase 2:** inspect the 2 demo findings; guard on empty interface |
| **O-lbl** | `get_device_detail` OSPF omits `vrf` label | not in snapshot (read-path) | n/a to snapshot | **C** | read-path test: adjacency rows carry `vrf` |

## Open Phase-2 investigation seeded here

- **The 2 `OSPF_ADJACENCY_ASYMMETRIC` in the demo** (one VRF `RED` adjacency is
  single-sided): determine whether these are genuine asymmetries or the O5
  incomplete-data false positive **before** writing the O5 guard, so the guard
  doesn't silence a real finding.

_Snapshot under audit: `demo/snapshot.json` — 8 devices, 17 links, 14
adjacencies, 16 shared-services, 353 findings. Source run (gitignored):
`runs/2026-06-23_09-16-04`._

## Resolution log

### Phase 1.1 — shared determinism core (B4/O-ip) — DONE

`model_builder.py` now sorts `facts_base.iterdir()`. Verified against **both**
golden masters (demo + real-hardware): **zero Class-A regression** — counts
identical. All deltas **Class B (accepted)**:

- **Link / adjacency / finding side-assignment** is now sorted-canonical
  (e.g. `bdr-rtr-01:Gi0/0/0/1--core-sw-01:Gi1/0/1`, was `core-sw-01--bdr-rtr-01`);
  `dev_a/dev_b` MTU values swapped accordingly. Same links, same real MTU
  mismatch — deterministic labels. Demo snapshot updated (126/126 symmetric).
- **OSPF area `spf_runs`** was a single member's counter picked by iteration
  order (10→6/8/16); now pinned deterministically. _Note: `spf_runs` is a
  volatile operational counter; whether it belongs in the model at all is a
  separate question parked for later — not acted on here._
- Real-hardware: arp_subnet evidence strings gained deterministic interface
  resolution.

640 tests green. `selfcheck` green on both. (Formal order-injection unit test —
reversed facts ⇒ identical model — tracked as Phase 1.1b with a small synthetic
collision fixture.)

### Phase 1.2 — course correction (full OSPF collapse abandoned)

The plan's "full single-source collapse" — make `evaluate_bilateral` read the
model adjacency instead of pairing by physical link — is **wrong for the OSPF
mismatch rules**, and 1.2a (`abf9f07`, auth/mtu on the adjacency) was reverted as
its orphaned groundwork.

Why: `evaluate_bilateral` detects mismatches that **prevent** an adjacency
(area / hello / dead / auth). When they mismatch, no neighbor forms, so there is
**no model adjacency to read** — a model-adjacency-based rule would go blind to
exactly what it exists to catch. The two OSPF pairing mechanisms are therefore
**complementary, not redundant** (unlike BGP's duplicate parsers):

- link-based (`build_ospf_link_index`) → "where an adjacency *should* form — are
  the params compatible?" → `evaluate_bilateral`.
- neighbor-table (model adjacencies) → "what *did* form" → `evaluate_adjacency`.

The demo golden master could NOT have caught this (zero area/hello/dead
mismatches to lose) — the ledger's honest-limit, realised.

**Corrected, smaller Phase 1.2:** keep link-based pairing; (1) **O2** — make
`find_ospf_interface_with_context` VRF-deterministic; (2) optional single-*reader*
cleanup so `evaluate_bilateral` reads each side's genie OSPF context once via the
link index rather than re-deriving. Cross-VRF false positive is already fixed by
the VRF guard (`d6424cc`).

**Final conclusion — Phase 1.2 has no structural collapse to do (verified):**

- **O2 is a non-issue.** `find_ospf_interface_with_context` returns "first match,"
  but a physical interface / SVI lives in exactly one VRF/process/area, so the
  canonical name appears in exactly one place — first match *is* the only match,
  already correct and deterministic. The audit's "same interface in two VRFs"
  cannot occur (no interface has two `vrf forwarding`). No fix (no-speculative).
- **No genuine double-read.** `build_ospf_link_index` only presence-checks
  (`"genie_ospf" not in facts[dev]`); the per-interface read lives once in
  `evaluate_bilateral`. Moving it would relocate, not eliminate, a read.

So OSPF Phase-1 is **done with just the 1.1 determinism core**. Unlike BGP, OSPF
has no redundant-reader debt — its two pairing mechanisms are complementary. The
real OSPF issues (**O1, O4, O5**) are all Phase-2 correctness, cataloged above.
Next structural work is **Phase 1.3 (BGP collapse)**, where the genuine duplicate
parsers / dual-path fallback live.

### Phase 1.3 — BGP collapse — DONE

- **B3** (`91b6961`, `576d0e3`): one BGP config parser. link_builder now reads the
  canonical `bgp_config.json` instead of re-parsing running_config (silent
  except:pass removed); the `routing.py` inline duplicate `_parse_bgp_running_config`
  + `_parse_bgp_json` were deleted with the fallback (−534 net lines).
- **B2-fallback** (`576d0e3`): `get_device_bgp` is Neo4j-only; the divergent
  facts-fallback is gone. Clean 404/500/503, no silent fallback. New
  `test_routing_bgp.py` locks the contract. _(B2-correctness — store the real
  `next_hop_self`/`soft_reconfiguration` instead of hardcoded `False` — remains
  Phase 2.)_
- **B1**: `session_type` now computed in exactly one Python site
  (`link_builder.py:6500`); the dashboard re-derivation went with the fallback.
  Frontend only reads it for display.
- **B5**: the `routing.py` genie-fallback source of `bgp_as` is gone; the
  remaining readers consume the BGP SharedService.

Demo + real-hardware golden masters unaffected (BGP collapse is read-path /
zero-delta model). 644 tests green.

---

## ✅ Phase 1 (structural collapse) COMPLETE

| Phase | Outcome |
|---|---|
| 1.1 | Determinism core — `sorted(iterdir)` + order-injection test |
| 1.2 | OSPF — no structural collapse (complementary readers, verified) |
| 1.3 | BGP collapse — one parser, fallback removed, single compute sites |

**Remaining = Phase 2 correctness (deliberate, Class C):** O1 (domain-rule VRF
partition), O4 (`get_ospf_detail` VRF filter), O5 (asymmetric on incomplete data
+ the 2 demo `OSPF_ADJACENCY_ASYMMETRIC`), O-lbl, B2-correctness.

---

## Phase 2 — correctness (Class C)

### O5 — OSPF_ADJACENCY_ASYMMETRIC on incomplete data — DONE

The 2 demo findings (`acc-sw-01↔edge-fw-01`, `core-sw-01↔edge-fw-01`, both
`state=full`) were **false positives**: the FortiGate's OSPF is not collected (no
OSPF REST endpoint), so there is no reverse observation — `interface_b=None`. The
adjacencies are actually healthy. `_check_adjacency_asymmetric` now skips when the
non-reporting side has **no `genie_ospf` collected at all** (collection gap, not a
misconfiguration); a peer that *did* expose OSPF but doesn't see us still fires
(real asymmetry). Threaded `facts` through `evaluate_adjacency`.

Golden master: demo findings **353 → 351**, delta = exactly those 2
`OSPF_ADJACENCY_ASYMMETRIC` removed (`-2 +0`). hw unaffected (no OSPF adjacencies).
644 tests green.

### O1 — OSPF_ROUTER_ID_DUPLICATE keyed by (vrf, router-id) — DONE (corrected)

**First attempt (`cd07f25`) was WRONG and was reverted.** It keyed by `(vrf, rid)`
read **from genie** — but genie stores *every* process's router-id under the
`default` VRF block regardless of the process's real VRF (verified: acc-sw-03's
RED/BLUE rids both appear as `(default, …)`; the real RED/BLUE blocks hold
`rid=None`). So the genie-derived vrf was always `default` → no real partitioning,
and cross-VRF reuse would have **false-positived**. The unit tests passed only
because they used idealised data. Carlos's "missing devices?" question on the OSPF
view surfaced it — the demo couldn't (no reuse to collide).

**Correct fix:** `_check_router_id_duplicate` now reads the **model adjacencies'**
VRF-resolved `router_id_a/b` + `vrf` (the model already maps each process's rid to
its real VRF). Threaded `adjacencies` through `evaluate_domain`. Demo unchanged
(351); unit tests now use real adjacency layout incl. the acc-sw-03 RED/BLUE reuse
case. 649 tests green.

### O1-view — per-VRF OSPF node RID labels — DONE

Same root quirk surfaced in the topology view: `TopologyMap.jsx` built the node
RID map from **all** adjacencies *before* the VRF filter → a multi-VRF device
showed an arbitrary VRF's rid (e.g. core-sw-01 showed `.100` in the RED view, not
its RED `.225`). Moved the RID-map build **after** the VRF filter, so labels match
the viewed VRF. (Frontend builds clean.)

### O1-area — OSPF_AREA_SINGLE_ABR is per-VRF — DONE

`_check_area_single_abr` keyed area→devices by area only, so area N in RED and area
N in BLUE merged (same cross-VRF class). Now keyed by `(vrf, area)`, ABR count is
within the same VRF's backbone, element_id/key_facts carry the VRF, and set picks
are sorted (determinism). Reads the model adjacency vrf — no genie. Demo unchanged
(only backbone areas); unit test covers per-VRF separation. 650 tests green.

### O-domain — ref-bw / SPF-timer consistency per VRF domain — DONE

Closes the last R1 OSPF item. `_check_reference_bandwidth` + `_check_spf_timer_inconsistent`
compared **globally** (ignored `ospf_domains`) and read a single per-device value via
"first instance" dict iteration (quirk-affected, non-deterministic pick). Now they
partition by **OSPF domain = VRF** (derived from the model adjacencies' resolved `vrf`,
via `_ospf_domains_by_vrf`) and read each device's value **for that domain's process**
through new genie-quirk-aware extractors `extract_reference_bandwidth_by_vrf` /
`extract_ospf_spf_timers_by_vrf` (proc→real-VRF from non-default blocks; value read
wherever genie stores it; deterministic sorted iteration). element_id now carries the
VRF (`ospf::ref_bw_inconsistent::<vrf>`).

**Empirically latent — zero golden-master delta:** the demo has no `reference-bandwidth`
configured and uniform SPF timers; the hw run has no OSPF — so neither rule fired before
or after (findings 351 / 204 unchanged). The fix is **pre-emptive correctness** for the
OSS product on multi-VRF networks where per-VRF ref-bw/SPF legitimately differ (the old
global compare would false-positive there). Proven by 4 unit tests the demo can't
exercise: cross-VRF isolation (no false positive), within-domain inconsistency fires,
genie-default-block value attributed to the real VRF, SPF per-domain. 665 unit tests green.

### O4 — get_ospf_detail groups area by VRF (no silent cross-VRF merge) — DONE

`mcp/tools/ospf.py` area-without-device branch keyed the `ospf_area` SharedService
membership + the `r.area` adjacency query by area number only, so area 0 in RED and
area 0 in BLUE collapsed into one merged member list. Now both queries also project
`coalesce(s.vrf,'default')` / `coalesce(r.vrf,'default')` and the output is **grouped
per VRF** (a `VRF <name>:` header appears only when >1 VRF is present, so flat networks
get no new noise). No new `vrf` parameter — the caller shouldn't have to know the VRF
(same "resolve VRF in the read" philosophy as O1). Read-path only → **zero golden-master
delta**. Verified by `tests/test_mcp_tools_vrf.py` (area in 2 VRFs ⇒ two 2-device groups,
never the merged 4; single-VRF ⇒ no header). @cypher-expert: 0 HARD.

### O-lbl — get_device_detail labels OSPF rows with VRF — DONE

`mcp/tools/device.py` OSPF section now projects `r.vrf` and renders `VRF:<name>` on each
adjacency row when non-`default` (mirrors the interface-row convention; no noise on flat
networks). Read-path only → **zero golden-master delta**. Verified by
`tests/test_mcp_tools_vrf.py` (non-default VRF labelled, `default` unlabelled).

### B2-correctness — real next_hop_self / soft_reconfiguration (Class C) — DONE

`get_device_bgp` hardcoded `next_hop_self`/`soft_reconfiguration` to `False`. The values
were already parsed by `bgp_config.py` (→ canonical `bgp_config.json`, the 1.3b read) but
never threaded into the model adjacency. Now end-to-end: `link_builder` enrichment reads
both from `rc_nbr` → added to `_BILATERAL_FIELDS` (auto-generates `_a/_b`) → loader writes
them via `SET r = a` (no Cypher change) → `routing.py` reads `r.next_hop_self_a/b` /
`r.soft_reconfiguration_a/b` per the bilateral side. (Also removed the stale "Fallback:"
docstring on `get_device_bgp` — the fallback went in 1.3.)

**Class-C delta (deliberate, snapshot grew):** the 6 demo BGP adjacencies each gained
`next_hop_self_a/b` + `soft_reconfiguration_a/b` — **purely additive, zero value drift**
(verified key-by-key: `ADDED` = exactly those 4, `REMOVED`/`CHANGED` empty on every edge;
the 8 OSPF adjacencies untouched). Real values now surface, e.g. `bdr-rtr-0X→core-sw-01`
`next_hop_self_a=True` (spoke sets next-hop-self toward the RR; was masked as `False`).
Both golden masters recaptured (demo committed `351`/`14`; hw local/gitignored `204`/`5` —
its 5 BGP adjacencies same purely-additive delta). Verified by
`tests/test_routing_bgp.py::test_get_device_bgp_next_hop_self_from_relationship`.
@cypher-expert: 0 HARD (property names match the `_a/_b` convention, loader-written).

---

## ✅ Phase 2 (correctness) COMPLETE

| ID | Fix | Snapshot |
|---|---|---|
| O5 | asymmetric-adjacency skips uncollected-OSPF peer | demo 353→351 |
| O1 | router-id dup + single-ABR keyed by (vrf,…) from model adjacencies; per-VRF node RID view | unchanged |
| O4 | get_ospf_detail groups area by VRF | zero (read-path) |
| O-lbl | get_device_detail labels OSPF rows with VRF | zero (read-path) |
| B2 | real next_hop_self / soft_reconfiguration | +4 keys × 6 BGP adj (additive) |

### O4b — MEMBER_OF cross-VRF contamination (loader root-cause) — DONE

Surfaced while live-verifying O4: the area membership list showed every device
inflated (e.g. `core-sw-01` ×3, "12 members" for 8 devices). Root cause was **not**
O4 and **not** the model (members are listed once per VRF, verified) — it was the
loader's `_load_shared_services` MEMBER_OF MATCH keying the `ospf_area` node by
`{service_type, identifier, site, run_id}` only. Since area `0.0.0.0` exists once per
VRF (RED/BLUE/default), each member matched **all three** nodes → every VRF group
showed the *union* of all VRFs' members (same cross-VRF class as O4, one layer down).
Fix: thread `vrf` + `process_id` into the member params and add
`WHERE coalesce(s.vrf,'')=coalesce(m.vrf,'') AND coalesce(toString(s.process_id),'')=coalesce(toString(m.process_id),'')`
— non-OSPF services (null on both sides) match the single node unchanged; the WHERE can
only ever narrow, never widen, the match. The sibling OspfLsa→area linking already
disambiguates by `WHERE area.vrf = l._vrf` (no bug). **Neo4j-side only → zero
golden-master delta** (model/findings unchanged; verified green). Post-fix membership
RED=2 / BLUE=3 / default=7, exactly the model. New live regression test
`test_member_of_disambiguates_ospf_area_by_vrf` (23 live loader tests green on :7688).
@cypher-expert: 0 HARD, 1 SOFT (`toString` defensive no-op — process_id is a JSON-key
string; kept as future-proofing).

### O-mem — OSPF area membership genie-quirk (model builder) — DONE

Surfaced when Carlos compared the chat membership to the OSPF topology view: the
**default** VRF area 0.0.0.0 listed `acc-sw-03` + `acc-sw-04`, which are RED/BLUE-only
devices (no default-VRF OSPF). Root cause is the genie quirk one more layer up, in
`_discover_shared_ospf_areas` (the model-builder source of the `members` list — distinct
from O4/O4b, which fixed the read + loader-MATCH): it iterated genie's vrf-blocks
including the polluted **default** block, where genie copies every process (RED proc 10,
BLUE proc 20) regardless of real VRF — so those copies made the device a *default*-area
member. Verified: acc-sw-03 runs only proc 10 (RED) + proc 20 (BLUE), no proc 1.
Fix: collect process ids present in any **non-default** genie block and **skip those
processes' copies inside the default block** (the real block is authoritative for VRF;
the default block is still read for area_type/stats, which genuinely live there per the
same quirk). Genie-only, no config dependency.

**Class-C delta:** demo default area 0.0.0.0 members 7→5 (`acc-sw-03`/`acc-sw-04`
removed); RED (2) / BLUE (3) unchanged; shared_services count unchanged (16); findings
351 unchanged. Now membership matches the topology except `edge-fw-01` (the expected
FortiGate-no-OSPF asymmetry — neighbor-only, never a member). Both golden masters
recaptured (hw has no OSPF areas → unaffected). New regression test
`test_shared_ospf_areas_ignores_genie_default_block_quirk`. 655 unit tests green.

**No OSPF items deferred** — the ref-bw / SPF-timer per-domain comparison (the last
open item) is now fixed (see O-domain above). The R1 determinism debt that blocked
go-live is closed.

---

## Adjacent fix (NOT R1/OSPF/BGP — logged here because it moved the snapshot)

### MAC-FP — phantom duplicate physical cable — DONE

Surfaced when Carlos saw two physical edges to acc-sw-03 in the Physical view. The
MAC-fingerprint feature emitted a `mac_fingerprint_unilateral` link on a port already
confirmed by a `cdp_bilateral` cable (`core-sw-01:Gi1/0/5`), but with an empty far
interface (FDB resolved only the near side) — so its dedup pair-key differed and it
painted a second edge. Fix: new post-dedup pass `suppress_unilateral_cable_on_bilateral_port`
(mirrors `suppress_cdp_portchannel_when_lacp_bilateral`) — one physical port hosts one
cable, so a unilateral cable link whose (canonical) port already terminates a bilateral
cable is dropped. Keyed per-port, not per-pair, so a genuinely distinct cable survives.

**Class-C delta:** demo links **17 → 16** (the one phantom `mac_fingerprint_unilateral`
removed; the real CDP cable `acc-sw-03:Gi1/0/1 ↔ core-sw-01:Gi1/0/5` stays). Findings
unchanged. **hw golden master identical — the real-hardware run has no such collisions, zero blast radius.**
6 unit tests in `test_link_builder_suppress.py`. 661 unit tests green.

### BGP Route-Reflector rules — dormant `NO_CLUSTER_ID` revived — DONE

The "3 dormant RR rules" gap (route-reflector-client / cluster-id never reaching the
rules) was **mostly already closed in labs**: the native parser `bgp_config.py` captures
both, `route_reflector_client` flows to the model adjacency (`route_reflector_client_a/b`),
`load_all_device_facts` exposes `bgp_config` to the rules — so `BGP_ROUTE_REFLECTOR_CLIENT_ASYMMETRIC`
(model adjacency) and `BGP_CLUSTER_ID_DUPLICATE` (`facts["bgp_config"]`) were live and
correctly silent on the demo (well-formed RR, single RR). Only `BGP_ROUTE_REFLECTOR_NO_CLUSTER_ID`
(`bgp_advanced.py`, a per-device BaseRule) was still reading **genie_bgp** for the two
config-only fields → permanently `has_rr_client=False`. Fixed to read `bgp_config.json`
(via `load_device_facts`) like its siblings.

**Class-C delta:** demo findings **351 → 352** — the rule now fires (info) on `core-sw-01`
(RR with 3 clients, no explicit `bgp cluster-id` → falls back to router-id). hw unchanged
(no RR config). 3 unit tests for the revived rule + the 7 pre-existing sibling RR tests.
668 unit tests green. (Source-repo RR-gap memory was stale for labs.)
