# Golden-Master Ledger — R2 Layer-2 + Layer-3 Determinism & Correctness Audit

Sibling of `LEDGER.md` (R1 BGP+OSPF, CLOSED). Same discipline: the honest bridge
between the **golden master** (a regression net that freezes *current* output,
bugs included) and the **audit** (which says what is wrong). Each row records, per
finding: does it show in a committed/local golden snapshot, what delta a fix will
produce, its delta-class, how it is verified, and its status.

Read this before accepting any `golden_master.py check` diff on an L2/L3 change.

## Delta classes (unchanged from R1)

- **A — zero-delta refactor.** Pure structural/determinism move; snapshot must stay
  byte-identical (the determinism *pin* is the point — same facts, same output).
- **B — convergence delta.** Collapsing two paths that currently *disagree*, or
  pinning a non-deterministic pick. Diff expected; review, explain, log.
- **C — correctness fix.** Deliberate; the snapshot changes on purpose.

## Status vocabulary

- **AUDIT-CONFIRMED** — defect reproduced firsthand against real golden data (cited).
- **AUDIT-FLAGGED** — found by the read-only audit with file:line evidence, **not**
  yet reproduced against a golden snapshot (mostly *latent* — needs a synthetic
  fixture to trigger). Confidence noted. Verify before fixing (R1 lesson: an
  "obvious" finding can be wrong — `cd07f25` was reverted).
- **RULED-OUT** — probed and found clean; recorded so the work isn't re-litigated.

## The honest limit (read this)

The committed **demo** snapshot is multi-VRF but small (8 devices); the **hw**
real-hardware snapshot (local, gitignored) is larger but has no OSPF and no
multi-bundle LACP. Many audit findings are **latent** — real in code, but with
**zero occurrences** in either golden run, so the golden master cannot prove them.
Those are `AUDIT-FLAGGED` and need targeted unit fixtures. Silence in a snapshot is
**not** proof a bug is gone. Phase 0 (this session) closed the route-layer coverage
hole; the VRF-SharedService hole (R2-COV-1) is still open.

---

## ✅ R2 CLOSEOUT — status: COMPLETE (selective scope, Carlos-approved)

**Fixed (14, all golden-guarded + tested):** Phase-0 route/RIB golden coverage ·
R2-RT-1/2 (cross-source static dedup) · R2-VRF-1 + R2-COV-1 (VRF single-source +
coverage) · R2-RT-3 (dead-parser delete) · R2-FDB-1/2 (deterministic set picks) ·
R2-VLAN-1 (trunk `add` parser) · R2-CDP-1 (canonical link orientation) ·
**R2-LAG-1** (multi-bundle cable pairing) · **R2-LAG-2** (reused-system_id partner
resolution) · **R2-LAG-5** (enrichment reused-system_id guard) · **R2-SVL-DAD**
(recover DAD link when stack_ports collected) · **R2-MEDIA-1** (copper-dominant
cable_type) — LAG-1/2/5 + SVL-DAD + MEDIA-1 landed 2026-06-24 via synthetic fixtures
+ a fresh hardware re-collection, goldens byte-identical.

**Ruled out (correct as-is — fixing would regress):** R2-STP-1 (address-match is the
right root detection) + the audit's negative results (route-table VRF attribution,
SVI/HSRP/switchport, VRF cross-VRF MEMBER_OF, etc. — see "Ruled out" section).

**Deferred with triggers (latent / cosmetic / needs-bigger-test-network):**
R2-LAG-3 (candidate sort parity, masked downstream) · R2-LAG-4 · R2-FDB-3 ·
R2-TOPO-1 · R2-VLAN-3 · R2-VLAN-1-SVI-helper · R2-VRF-2 · R2-RIB-1 · R2-CDP-status.

**Load-bearing lesson:** the system is **already deterministic** (R1 fixed the real
non-determinism; proven here by a reversed-order rebuild → byte-identical model). The
remaining "determinism" items are *arbitrary-but-fixed tie-breaks*, not randomness —
so chasing them gains nothing, and naive pins **regress** (3 of 5 LAG attempts broke
the hw golden and were reverted). The deferred tail is parked per no-speculative-
improvements, not forgotten. **7 commits on `main`, unpushed** (hold per Carlos).

---

## Audit coverage — 12 domains × 4 axes

Axes: **A** determinism · **B** genie-quirk/VRF attribution · **C** multiple
producers of one fact · **D** read-path correctness. Cells with a finding ID;
`clean` = probed and ruled out.

| Domain (layer) | A | B | C | D |
|---|---|---|---|---|
| VLANs (L2) | R2-TOPO-1¹ | clean | **R2-VLAN-1** | R2-VLAN-3 |
| Switchport/trunk (L2) | clean | clean | (R2-VLAN-1) | clean |
| STP (L2) | clean | clean | R2-STP-1 | clean |
| Port-channels/LACP (L2) | **R2-LAG-1**, R2-LAG-3 | **R2-LAG-2** | R2-LAG-4 | clean (count ruled-out) |
| MAC/FDB (L2) | R2-FDB-1, R2-FDB-2 | R2-FDB-3 | (R2-LAG-4) | R2-FDB-1 |
| CDP/LLDP (L2) | R2-CDP-1 | clean | clean | clean |
| Static routes (L3) | clean | clean | **R2-RT-1**, **R2-RT-2**, R2-RT-3 | clean |
| Connected routes (L3) | clean | clean | clean | clean |
| SVIs/L3 intf (L3) | clean | clean | clean | clean |
| HSRP/VRRP (L3) | clean (guard) | clean (absent) | clean (absent) | clean (absent) |
| VRF (L3) | clean | **R2-VRF-1** | **R2-VRF-1** | R2-VRF-2 |
| RIB aggregation (L3) | clean | R2-RIB-1 | clean | clean |

¹ R2-TOPO-1 is a VLAN-subnet **read-path** determinism item (dashboard topology), filed under VLANs.

---

## Findings ledger

| ID | Issue | In golden? | Expected delta | Class | How verified | Status |
|----|-------|-----------|----------------|-------|--------------|--------|
| **R2-RT-1** | Cisco static routes materialised twice — once from the genie RIB file (`source=dynamic`, real AD) and once from the genie static-config file (`source=static`, ad=0); `_build_route_params` extends `route_params` from both with no cross-source dedup (`loader.py:1695-1718`) | **yes (hw)** | route count drops; duplicate `(device,prefix,vrf,next_hop)` rows merge (keep RIB-installed) | **C** | **CONFIRMED:** `_build_route_params(runs/golden/hw)` → 12 dup keys / 123 routes | ✅ DONE |
| **R2-RT-2** | FortiGate static routes materialised twice — `fortigate_routing.json` (RIB, has `type:static`) + `fortigate_static_route.json` (config); both extend, no dedup (`loader.py:1720-1741`). Also empty-value drift: static parser emits `next_hop=None` for `0.0.0.0` gateway, RIB parser `""` | **yes (hw)** | dup defaults merge (a FW `0.0.0.0/0` appears 5×); pick one empty-value convention | **C** | **CONFIRMED:** same 12-dup run; FW `0.0.0.0/0` ×5 floats preserved | ✅ DONE |
| **R2-RT-3** | Dead duplicate route parsers in the dashboard read path (`routes/routing.py`: `_parse_routing_json`, `_flatten_route`, `_parse_fortigate_static_routes`, `_parse_fortigate_routing`) — zero callers, diverge from the loader (`proto_fallback`/`active` defaults differ). Latent R1 anti-pattern (a second parser waiting to be wired up and re-diverge) | no (dead) | delete dead code; no output delta | **C** | **CONFIRMED dead:** zero endpoint/test callers (re-verified); live endpoint reads `:Route` from Neo4j | ✅ DONE |
| **R2-VRF-1** | VRF double-source drift: `interface.vrf` is parsed from running-config (`model_builder.py:1760`, parses IOS-XR `vrf clab-mgmt` correctly) while the VRF SharedService is built from `genie_vrf.json` (`loader.py:3072`), which returns **empty** for IOS-XR → drops `clab-mgmt`. The two "what VRFs exist / who's in them" views contradict | **yes (demo)** | VRF SharedService gains the config-sourced VRFs (e.g. `clab-mgmt` on the XR routers) | **C** | **CONFIRMED:** demo `interface.vrf={RED,BLUE,Mgmt-vrf,clab-mgmt}`; vrf SharedService in model = `[]` | ✅ DONE |
| **R2-COV-1** | The VRF SharedService graph is **loader-only** (not in `build_model.shared_services` — types present are `bgp_asn/ospf_area/subnet/vlan`), so the golden master cannot see VRF-membership changes → R2-VRF-1 is regression-invisible | n/a (gap) | extend the harness (or rely on live-loader tests) before fixing R2-VRF-1 | — | **CONFIRMED:** `shared_service` types lack `vrf` | ✅ DONE |
| **R2-VLAN-1** | Trunk-allowed-VLAN + SVI parsing duplicated across 3-4 sites that drift: `vlan_no_interfaces._get_trunk_vlans_from_config` (`:53`) misses `switchport trunk allowed vlan add` continuation lines that `model_builder._parse_switchport_from_config` (`:1540`) handles; SVI-id extraction duplicated 4× with `Vl`/`Vlan` prefix inconsistency | no-latent | rule reads the model's `trunk_vlans` (single producer); converge SVI helper | C + B | 4 unit tests (latent); model parser matched | ✅ DONE (trunk); SVI-helper deferred |
| **R2-STP-1** | `_check_stp_root_conflict` sets `is_root = (address == root_address)` (`interface_rules.py:585`), ignoring that genie `bridge_priority` may differ from `designated_root_priority` (verified on demo: 32768 vs 32778) → may call a non-root device "root" | **yes (demo)** — would move STP_ROOT×4 | possibly removes/relabels some STP_ROOT findings | **C** | address-match IS correct root detection; priority-tighten would suppress 2 real demo conflicts (regression) | ❎ RULED-OUT |
| **R2-VLAN-3** | `devices.get_device_vlans` attaches every unfiltered-trunk port to **every** VLAN in the device DB at read time (`devices.py:768`) — over-attaches on a large inherited VLAN DB; diverges from stored membership | no-readpath | decide read semantics; tool/route test | C | read-path semantics decision | ⏸️ DEFERRED |
| **R2-TOPO-1** | Dashboard topology gateway display iterates a **set** of next-hop IPs and `break`s on first in-subnet match (`topology.py:1141`) → non-deterministic `gateway_ip`/`gateway_device` when >1 next-hop is in a VLAN subnet | no-readpath | sort/lowest-IP pick; stable display | **A** | read-path determinism (system already deterministic) | ⏸️ DEFERRED |
| **R2-LAG-1** | LACP bilateral promotion pairs by `(local_device,remote_device)` only, ignoring which member cable (`link_builder.py:1112-1135`) → on a pair with ≥2 port-channels it can fuse two different cables into one link, picked by list order | no-latent | correct member pairing; one link per cable | **A** | **FIXED** — reverse-match now prefers the candidate whose local port == the far port `c` already resolved via `partner_port_num` (no-op on single-bundle pairs → goldens byte-identical); synthetic ≥2-PO fixture proves correct + order-independent pairing | ✅ DONE |
| **R2-LAG-2** | LACP partner MAC table (`_build_mac_lookup`, `link_builder.py:803+`) is last-writer-wins on a shared/reused MAC — the exact R1 IOL-MAC hazard that the fingerprint sibling `_build_hw_mac_to_device_index` (`:1412`) already guards against with a set | no-latent | hardened MAC resolution (set + explicit collision rule) | **B** | **FIXED** — `_resolve_lacp_partner` disambiguates a >1-owner system_id by LACP symmetry (the twin that points back), else falls back to the flat table (never worse; set-based → order-independent). Fires only on a reused system_id → goldens byte-identical; synthetic 4-device twin fixture proves both cables resolve to the correct twin | ✅ DONE |
| **R2-LAG-3** | `discover_lacp_links` does not sort its returned candidates (CDP/LLDP do) (`link_builder.py:1145-1154`) — masked downstream by a link_id re-sort, but an order-coupled tie-break input | no-latent | sort parity with CDP/LLDP | **A** | reordering regressed hw via dedup tie-break; see Lesson | ⏸️ DEFERRED |
| **R2-LAG-4** | LAG membership read from two source files by three readers: model from `genie.lag`, link_builder fallback `parsed_lag`, cross-device rule `_check_lag_members` from **only** `parsed_lag` (`interface_rules.py:450`) → rule can disagree with the modeled LAG | no-readpath/latent | rule reads the model's LAG source | C | latent; trigger: parsed_lag≢genie.lag on a real device | ⏸️ DEFERRED |
| **R2-LAG-5** | The `_build_mac_lookup` LACP cross-reference *enrichment* (`link_builder.py:838+`) trusted `table.get(a_mac)==device_b` where the bridge `a_mac` is a **reused system_id** — last-writer-wins routes it to the wrong twin, driving the 1:1 symmetry inference to fabricate that twin's unrelated (e.g. uncollected) partner as A → phantom link | AUDIT-CONFIRMED — reproduced on a clean twin+uncollected-neighbour fixture, 3/6 orderings | **FIXED** — exclude reused system_ids (>1 owner) from the symmetry evidence; legitimate fills bridge on a UNIQUE identity MAC so they're untouched (regression test added), goldens byte-identical (no reused system_id on either) | B | ✅ DONE |
| **R2-SVL-DAD** | `discover_stack_interconnect_links` C9500 SVL branch is either/or: when `stack_ports` is collected it uses ONLY stack_ports (`show stackwise-virtual link` — SVL data-plane fibers only) and never consults config, so the **DAD link** (config-only, `dual-active-detection`) is **dropped**. DAD presence flipped on collection completeness (golden lacked stack_ports → kept DAD via config fallback; a fresh collection captured stack_ports → lost DAD) | hardware-confirmed (a fresh collection that captured stack_ports dropped the DAD fiber on both C9500 SVL pairs) | **FIXED** — after the stack_ports loop, merge in any config SVL/DAD port ABSENT from stack_ports (recovers DAD, no SVL dup). Golden has empty stack_ports → config-fallback path unchanged → byte-identical | **C** | ✅ DONE |
| **R2-MEDIA-1** | `cable_type` (`topology.py:290`) took ONE arbitrary endpoint (`l1_local or l1_remote`), so a FortiGate `serdes-sfp` SFP mis-asserted as `fiber` (model_builder defaults any FG transceiver to fiber) masked the **authoritative copper** of the peer's fixed RJ45 port → firewall↔switch links shown fiber when physically copper | hardware-confirmed (firewall↔switch links shown half-fiber; the switch ports are Catalyst fixed copper RJ45) | **FIXED** — copper-dominant rule: any copper endpoint ⇒ rj45; fiber only with a fiber endpoint and no copper end. Deterministic physical law, transceiver-DB-free; read-path only → goldens untouched. Genuine 25G firewall uplinks stay fiber | **C** | ✅ DONE |
| **R2-FDB-1** | `discover_fdb_firewall_links` assigns **all** discovered switch↔FW cables to one arbitrary firewall via `next(iter(firewall_ids))` set-pick (`link_builder.py:2756`) — wrong with ≥2 firewalls | no-latent (single FW demo) | per-cable FW attribution | **A** | zero-delta both goldens | ✅ DONE |
| **R2-FDB-2** | FDB L2 remote-port resolution iterates a **set** of MACs and `break`s on first (`link_builder.py:1629-1638`), and `_fdb_physical_port_for_mac` returns first port in dict order (`:1493`) → set-iteration-dependent remote port on a reused MAC | no-latent | sort MAC iteration; deterministic port | **A** | zero-delta both goldens | ✅ DONE |
| **R2-FDB-3** | FortiGate hardware port map keys on the **last 2 bytes** of the MAC (`int(hex[-4:],16)`, `link_builder.py:2393`) — truncation collision, last-wins | no-latent | full-MAC key | **B** | latent Class-B; trigger: ≥2 FW ports colliding on low-16-bits | ⏸️ DEFERRED |
| **R2-CDP-1** | Bilateral CDP/LLDP link **side-assignment** (`local_device_id`/`remote_device_id`, hence Neo4j edge direction and the `l2.local`/`l2.remote` blocks) is set by iteration order, not canonicalised (`link_builder.py:415-477`, dedup winner `:3966`). Deterministic run-to-run (sorted facts) but **not canonical** — flips if a device is renamed/added | yes (demo, but pinned) | canonicalise side by sorted `(device:intf)`; snapshot orientation may flip once | A/B | pure relabel, golden-verified; live-verified | ✅ DONE |
| **R2-VRF-2** | `shared_services` IP-lookup matches subnets ignoring VRF (`shared_services.py:271`) — overlapping RED/BLUE subnets cross-attribute an IP to the wrong VRF's interface | no-latent | filter/group candidates by VRF | C | tool-design, latent; trigger: overlapping VRF subnets queried | ⏸️ DEFERRED |
| **R2-RIB-1** | Per-peer BGP routes + full-table synthesis hardcode `vrf="default"` (`loader.py:2113,2193`) → non-default-VRF BGP routes mis-attributed | no-latent (no `genie_bgp_routes_*` in either golden) | carry the real VRF | C | latent, no golden coverage; trigger: VRF-aware per-peer BGP collection | ⏸️ DEFERRED |

### Additional latent determinism items (low priority, bundle)

Agent-flagged set-pick / dict-order winners with no golden occurrence, grouped for
one hardening pass if Phase B reaches them: LACP cross-ref enrichment mutating its
table mid-iteration (`link_builder.py:862-907`); PO partner-MAC "first member"
(`:2639,2694,2764`); FortiGate `ha_offset`/`data_vdom` tie-picks (`:2352,2645`);
dedup partial-index last-wins (`:3826`); `redundancy.py` `ha_affinity_risk`
overwrite + arbitrary member (`:142-150`). All Class A, all `no-latent`.

---

## Ruled out (recorded so it isn't re-litigated)

- **Route-table VRF attribution (the prime suspect) is CLEAN.** genie keys route
  *tables* by real VRF; the "default-block-lies" quirk is an OSPF/BGP-**process**
  phenomenon, not a routing-table one. Verified against RED/BLUE + the hw VRFs.
- **Connected-route synthesis** — single producer, sorted, VRF-correct.
- **SVI / L3-interface attribution** — IP/prefix/VRF per-interface, correct, single producer.
- **HSRP/VRRP** — not modeled (absent); virtual-MAC→device inference is explicitly
  guarded (`link_builder.py:1559`). No defect today (re-opens if FHRP is modeled).
- **VRF determinism + cross-VRF MEMBER_OF** — VRF SharedService `identifier` is the
  globally-unique VRF name, so R1's OSPF-area cross-VRF MERGE bug cannot recur here.
- **Switchport mode read path** — straight Neo4j passthrough, single producer.
- **MAC-fingerprint Phase-1 core** — R1-hardened (sorted, single-owner guard, multi-access skip).
- **`redundancy.py` LAG cable count** — undirected match but grouped by ordered pair; not double-counting.

---

## Sizing (Phase-A deliverable — input to the fix-scope decision)

**Go-live-critical (demo/hw-visible or firsthand-confirmed): 3 fixes + 1 harness gap + 1 cleanup**
- R2-RT-1 + R2-RT-2 → one cross-source route-dedup fix (Class C, hw-visible).
- R2-VRF-1 → reconcile VRF SharedService to a single source (Class C, demo-visible),
  **gated by R2-COV-1** (extend the harness to cover the VRF SharedService first).
- R2-RT-3 → delete the dead dashboard route parsers (Class C, no delta).

**Correctness, latent (need a fixture to trigger; real but not biting either golden): ~3**
- R2-VLAN-1 (trunk `add` parser), R2-STP-1 (root definition), R2-VRF-2 (VRF-aware IP lookup).

**Determinism hardening, latent (Class A/B, ~10 items): R2-LAG-1..4, R2-FDB-1..3, R2-CDP-1, R2-TOPO-1 + the bundle.**
Mostly invisible on the current networks; matter for arbitrary topologies (multi-bundle
LACP, ≥2 firewalls, reused MACs). Candidate for a prioritised follow-up, **not all v1-blocking**.

**Recommendation:** fix the go-live-critical 5 now (tight, verifiable, mostly golden-caught);
of the latent set, prioritise the ones most likely on a real customer network
(R2-LAG-1/2 multi-bundle + IOL-MAC, R2-FDB-1 multi-firewall, R2-CDP-1 canonical side)
and defer the long tail to a documented follow-up with the trigger condition recorded.
Carlos approves the fix scope before Phase B begins.

---

## ⚠️ Lesson — latent LACP determinism pins are NOT safe (hw-regression, golden-caught)

The first determinism batch tried five "obvious" one-line pins. **Three regressed the
real-hardware golden** and were reverted; **two were safe**:

- **R2-LAG-1/2/3 — REVERTED (deferred).** The LACP discovery path
  (`_build_mac_lookup` last-wins → partner resolution → `reverse_matches[0]` bilateral
  pairing → unsorted candidate order → order-sensitive dedup tie-break) is **order-
  coupled but load-bearing on real hardware**. Each naive pin (setdefault / sort
  reverse-matches / sort candidates) re-resolved a partner MAC or re-paired a bundle
  member, **dropping LACP corroboration on 14 hw CDP cables** (`[model.links] -8 +8`,
  lost `lacp:` evidence on the XR HundredGigE bundles). last-wins / first-match are
  currently *correct* by luck of iteration order; a proper fix is **source-aware MAC
  resolution** (resolve a partner `system_id` to the device whose system_id it is) +
  a fixed dedup tie-break, validated against a **≥2-PO test topology**. Deferred — the
  in-code NOTEs in `link_builder.py` record why. **Trigger to revisit:** a holistic
  LACP-determinism task with a multi-bundle fixture.
- This is the no-speculative-improvements line in action: latent determinism with no
  demo/hw occurrence, where the attempted fix *creates* a regression. The golden
  master earned its keep.

## Resolution log

### R2-CDP-1 — canonical link orientation — DONE

Bilateral link side-assignment (`local_device_id`/`remote_device_id`, hence the
Neo4j edge direction and `l2.local`/`l2.remote`) followed whichever dedup candidate
won — deterministic but **arbitrary**. Now oriented **canonically** in
`deduplicate_links`: the lexicographically-smaller `(device, normalized-interface)`
endpoint is `local`, matching the already-sorted `link_id`. Dedup has already merged
the group, so this only **labels** the merged link (cannot change which candidates
merged — unlike the LAG side-effects). Downstream l2/l3 enrichment keys off
`local_device_id`, so it inherits the orientation.

**Pure relabel (Class B), verified zero corruption:** link set unchanged (16 demo /
61 hw), `link_id` stable, **`status` byte-identical**, and `local`↔`remote` +
`l2.local`↔`l2.remote` + FortiGate HA `member_id`s swap **together** (0 dirty, 0
status changes across all 77 links). 1 demo link + 20 hw links reoriented (e.g. demo
`acc-sw-03:Vl20 — core-sw-01:Gi1/0/5` now local=`acc-sw-03`). Both goldens recaptured
+ selfcheck deterministic; unit test `test_dedup_canonical_orientation_local_is_smaller_device`;
704 tests green. Live-verified by Carlos.

**To keep `status` byte-stable**, it is computed from the winner's *original*
endpoints — because of:

### R2-CDP-status (NEW, found during R2-CDP-1) — DEFERRED

`calculate_link_status(local_iface, remote_iface)` is **not orientation-independent**
— flipping ends changed `status` on 4 hw links (mixed up/down ends). A link's
up/down status is a property of the link, not of which end is "local", so this is a
latent correctness smell. **Not introduced by R2-CDP-1** (R2-CDP-1 sidesteps it by
computing status from the original orientation). Deferred — make
`calculate_link_status` symmetric + verify against both goldens. **Trigger:** a link
with genuinely-asymmetric end states whose displayed status is wrong.

### R2-VLAN-1 — trunk allowed-VLAN `add` continuations — DONE (trunk half)

`vlan_no_interfaces._get_trunk_vlans_from_config` used `re.search` (FIRST match
only), so a trunk's `switchport trunk allowed vlan add <list>` continuation lines
were dropped → carried-VLAN set under-counted → a VLAN carried only via an `add`
line could be false-flagged `VLAN_NO_INTERFACES`. Now uses `re.findall` over all
allowed-vlan lines, strips the `add ` keyword, and unions — **mirroring the model's
`_parse_switchport_from_config` (`model_builder.py:1540-1548`)** so the two producers
no longer diverge. **Latent — both goldens unchanged** (neither demo nor hw has an
orphan VLAN carried only by an `add` line), so proven by 4 unit tests in
`test_rules_vlan_no_interfaces.py` (add-union, unfiltered→None, no-trunk→empty,
mixed-trunk→None). 704 tests green.

**Deferred (SVI-helper half):** the audit also noted SVI-id extraction (`intf_name[4:]`)
duplicated in 4 sites with a `Vl`/`Vlan` prefix inconsistency. **No failing case** —
genie_interface keys are always the full `Vlan<N>` form, so the rules' `Vlan`-only
check is correct where they read genie. Consolidation is cosmetic; deferred
(no-speculative). Trigger: a source that emits the `Vl` short form into a rule path.

### R2-FDB-1 + R2-FDB-2 — deterministic FDB/firewall picks — DONE

Two **safe** determinism pins (zero-delta on both goldens — deterministic where the
code previously took an arbitrary set element, with no load-bearing pick to break):
`discover_fdb_firewall_links` now picks `sorted(firewall_ids)[0]` instead of
`next(iter(...))` (R2-FDB-1); the FDB L2 remote-port lookup iterates
`sorted(local_port_macs)` instead of an unordered set (R2-FDB-2). Both demo + hw
golden masters byte-identical; 700 tests green. (The deeper correctness halves —
per-cable multi-firewall attribution, reused-MAC remote-port disambiguation — remain
latent items, same family as R2-LAG, deferred with the multi-X-topology trigger.)


### R2-RT-1 + R2-RT-2 — cross-source static-route double-count — DONE

A configured-and-installed static route was materialised as **two** `:Route` nodes
— once from the RIB file (`source="dynamic"`, real AD) and once from the
static-config file (`source="static"`, ad=0) — so the dashboard Routing tab showed
the same static twice. New pure pass `_dedupe_cross_source_static_routes` in
`_build_route_params` (`loader.py`): when a `source="static"` route shares the full
identity `(device, prefix, vrf, protocol, next_hop, interface)` with a
`source="dynamic"` route, the config copy is dropped (RIB-installed wins). `interface`
is in the identity, so genuinely distinct interface / SD-WAN routes that share a
prefix are **not** merged; config-only statics (uninstalled / floating blackhole
defaults) have no RIB twin and are preserved. The `static_route_inactive` rule reads
the raw genie file independently → unaffected.

**Class-C delta:** hw golden routes **123 → 112** (11 cross-source duplicates
removed; a FortiGate's 5 distinct floating blackhole defaults correctly preserved).
Demo golden **unchanged** (171 — the demo has no static-config files, so the dedup
is a no-op there). Proven by 2 unit tests (`test_graph_load_routes.py`) the demo
snapshot can't exercise: cross-source collapse + RIB-wins, and no-op without a
collision. 699 tests green (live loader suite included).

### R2-COV-1 + R2-VRF-1 — VRF SharedService coverage + single-source membership — DONE

**Coverage (R2-COV-1):** the VRF SharedService graph was loader-only (not in
`build_model`), so the golden master couldn't see it. Extracted a pure
`_build_vrf_members(run_dir, interfaces)` from `_load_vrfs` (Neo4j-free) and added a
`vrfs` section to the golden snapshot (sets → sorted lists). Same pattern as the
Phase-0 route extraction. Demo now snapshots **5** VRFs, hw **4** — additive; the
Cypher write in `_load_vrfs` is unchanged.

**Fix (R2-VRF-1):** membership was sourced from `genie_vrf.json` only, which returns
**empty** for IOS-XR → XR VRFs were dropped from the graph while `interface.vrf`
(running-config-parsed) carried them. `_build_vrf_members` now **unions**
`genie_vrf.json` ∪ `interface.vrf` (the authoritative per-interface field) ∪
`default` (RIB-present). The two views of "what VRFs exist / who's in them" now agree.

**Class-C delta (additive coverage captured at the corrected state):** demo VRF
membership gains `clab-mgmt = {the 3 IOS-XR routers}` (genie-only would have been 4
VRFs without it); the hw run is **unchanged by the union** (its `genie_vrf.json`
populates — the fix only adds where genie drops, no over-reach). Because the `vrfs`
section was newly added, the golden baseline is the corrected state; the fix's effect
over the old genie-only behaviour is proven by `test_build_vrf_members_unions_interface_vrf`
(empty genie_vrf + interface.vrf ⇒ VRF present; platform `__` skipped; `default` via
RIB, not doubled) and the genie-only-vs-union diff reported at fix time. 700 tests green.

### R2-RT-3 — dead duplicate route parsers in the dashboard read path — DONE

`routes/routing.py` carried a complete *second* implementation of the route parsers
(`_parse_routing_json`, `_flatten_route`, `_parse_fortigate_static_routes`,
`_parse_fortigate_routing`, plus `_FG_TYPE_MAP`/`_FG_CODE_MAP` and a `_fg_dst_to_cidr`
wrapper) that duplicated the loader and **diverged** from it (e.g. `active` default
`False` vs the loader's `True`, `proto_fallback="unknown"` vs `"?"`). Verified dead:
zero endpoint/test callers — the live `/api/device/{hostname}/routing` endpoint reads
`:Route` nodes from Neo4j. Removed all ~190 lines. Kept `_PROTO_CODE_MAP` (used by the
live endpoint) and the real `policy_resolver.fg_dst_to_cidr` (the wrapper's delegate,
still tested by `test_policy_resolver`). Zero functional delta (read-path dead code;
golden masters untouched by construction). 700 tests green.
