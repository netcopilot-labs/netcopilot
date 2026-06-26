# Golden-Master Ledger — Security/Firewall Determinism & Correctness Audit

Sibling of `LEDGER-R2-L2L3.md` (R2 L2/L3, CLOSED) and `LEDGER.md` (R1 BGP+OSPF,
CLOSED). Same discipline: the honest bridge between the **golden master** (a
regression net that freezes *current* output, bugs included) and the **audit**
(which says what is wrong). Each row records, per finding: does it show in a
committed/local golden snapshot, what delta a fix produces, its delta-class, how
it is verified, and its status.

Read this before accepting any `golden_master.py check` diff on a security change.

## Delta classes (unchanged from R1/R2)

- **A — zero-delta refactor.** Pure structural/determinism move; snapshot must stay
  byte-identical (the determinism *pin* is the point — same facts, same output).
- **B — convergence delta.** Collapsing two paths that currently *disagree*, or
  pinning a non-deterministic pick. Diff expected; review, explain, log.
- **C — correctness fix.** Deliberate; the snapshot changes on purpose.

## Status vocabulary

- **AUDIT-CONFIRMED** — defect reproduced firsthand against real golden/fact data (cited).
- **AUDIT-FLAGGED** — found by the read-only audit with file:line evidence, **not**
  yet reproduced against a golden snapshot (mostly *latent* — needs a synthetic
  fixture to trigger). Confidence noted. Verify before fixing (R1/R2 lesson: an
  "obvious" finding can be wrong — `cd07f25` / 3 LAG reverts).
- **RULED-OUT** — probed and found clean; recorded so the work isn't re-litigated.

## The honest limit (read this)

Both goldens exercise the security layer: the committed **demo** snapshot has a
FortiGate (`edge-fw-01`, full `fortigate_*` fact set) + Cisco `security_config.json`
on every switch/router; the local gitignored **hw** snapshot has a real FortiGate +
Cisco. So the **rules→findings** layer (`cis_fg_*`, `config_netconf_acl`) is
genuinely golden-covered — a strong net. **But the resolution + load read-path is
not:** `policy_resolver.py` and the loader's `:FirewallPolicy` / `:SecurityConfig`
Neo4j nodes feed the **MCP tools + dashboard**, which `build_model` + `run_rules`
(what the snapshot captures) never touch. Read-path (axis-D) items are therefore
**weak-net** — verified by code-reading + fixture, not by the golden master.

Also **neither golden run collected `genie_acl.json`** — so every Cisco-ACL finding
(SF-ORDER-1, SF-ACE-1, SF-POLICYID-1) is golden-invisible and proven only by unit
fixture. Silence in a snapshot is **not** proof a bug is gone.

---

## ✅ SECFW CLOSEOUT — status: COMPLETE (focused scope, Carlos-approved)

**Fixed (6, golden-guarded, full suite 692 passed):**
**SF-ORDER-1** (ACL nodes carry `seq` = ACE order → deterministic
`get_firewall_policies`) · **SF-SEV-1** (`config_netconf_acl` docstring `medium`→`low`,
doc-only) · **SF-SVC-1** (SCTP-only services keep their ports) · **SF-ACE-1**
(multi-network ACEs keep all networks, sorted — was lossy + dict-order-dependent) ·
**SF-DENY-1** (FortiGate implicit deny-all now shown in `get_firewall_policies`) ·
**SF-ADMIN-THRESH-1** (flag the all-super-admin case — no least-privilege account).
Five are zero-delta on both goldens; **SF-ADMIN-THRESH-1 is the one deliberate
class-C delta** (demo 352→353: `edge-fw-01/.../no-least-privilege-admin`; hw
unchanged — 8 admins/7 super, not all-super). Demo snapshot re-captured.

**Headline — the layer is healthier than R2/R1 were.** The three highest-risk traps
are **clean** (see Ruled-out): the FortiGate `"enable"/"disable"` truthiness trap is
avoided everywhere; the MCP read-path has zero typo'd-label / silent-empty Cypher
bugs (every property read matches what the loader writes); the genie `accept`/`permit`
ACL quirk is handled.

**Deferred with triggers (latent / weak-net):** SF-DET-1, SF-GRP-1, SF-POSTURE-1,
SF-FIRMWARE-1, SF-HAMON-1, SF-ACTION-1, SF-QORIGIN-1, SF-POLICYID-1, SF-NAME-1. All
have **zero occurrences** in either golden — the latent tail R2 taught us to defer
rather than chase (naive pins gain nothing and can regress).

**Deferred — the one AUDIT-CONFIRMED-on-production capture gap (not latent):**
**SF-ISDB-1** — FortiGate **Internet Service Database** references
(`internet-service-name`/`-custom`/`-group` + `-src-`) are read **nowhere** in `src/`,
so an ISDB policy's destination/source is stored empty and `path_tracer` reports
"no matching firewall policy found" for it (a silent failure). Confirmed on the
production (hw-golden) FortiGate (a Tor/Malicious-block ISDB policy with empty
`dstaddr`). Full CIDR resolution has **no forward REST path** — only `diagnose
internet-service id` over SSH (global VDOM), and the production FortiGate's SSH is
**MFA-gated**, hard to obtain. **Deferred 2026-06-25** with a complete, resumable design in the plan file
`~/.claude/plans/magical-dreaming-truffle.md` (Phase 1 = REST-only names + silent-fail
fix, no SSH needed; Phase 2 = opt-in SSH CIDR resolution). **Trigger:** FortiGate
SSH/MFA creds obtained → Phase 2; OR a decision to ship Phase 1 alone.

**Ruled out on the deep dig:** **SF-FLATTEN-1** (the SecurityConfig loader flattens
only `admin`/`password_policy`/`ntp`/`snmp`/`ha`; none carry nested dicts — the
nested-dict profile files are read by rules, never flattened, so no security data is
lost on Cisco *or* FortiGate). **SF-FW-1** (the absence-over-report is *correct*
fail-closed CIS behaviour, and the element_id collision is impossible — FortiGate
enforces unique object names per type/VDOM). SF-DET-1 stays deferred with a sharpened
rationale: dict-**insertion** order = deterministic *within* a run (unlike R2-FDB's
genuine set nondeterminism), so it can only bite on collector output-order drift — no
documented drift, so pinning it is speculative.

**Load-bearing lesson (carried from R1/R2):** the system is **already deterministic**
(R1 fixed the real non-determinism). The remaining "determinism" items are
arbitrary-but-fixed tie-breaks whose only risk is *collector output-order drift*;
without a documented drift they are not worth a pin.

---

## Audit coverage — 9 domains × 4 axes

Axes: **A** determinism · **B** parse/source-quirk correctness (FortiGate JSON
shape, default-when-absent) · **C** multiple producers of one fact · **D** read-path
correctness. Cells carry a finding ID; `clean` = probed and ruled out. **Bold** =
fixed.

| Domain (surface) | A | B | C | D |
|---|---|---|---|---|
| FW policies (FortiGate) | SF-DET-1 | SF-ACTION-1 | SF-QORIGIN-1 | **SF-DENY-1** ✅ |
| Zones / interface-zone | clean | clean | clean | clean |
| Address objects & groups | SF-NAME-1 | clean | SF-GRP-1 | clean |
| Services & service-groups | clean | **SF-SVC-1** ✅ | (SF-QORIGIN-1) | clean |
| Security profiles (AV/IPS/DNS/app/SSL) | SF-DET-1 | clean | clean | ~~SF-FW-1~~ |
| Admin / hardening / local-in / firmware | clean | clean | clean | SF-FIRMWARE-1, **SF-ADMIN-THRESH-1** ✅ |
| HA admin | clean | SF-HAMON-1 | clean | clean |
| Cisco ACL | **SF-ORDER-1** ✅, **SF-ACE-1** ✅ | clean (accept/permit) | **SF-SEV-1** ✅ | SF-POLICYID-1 |
| Cisco SecurityConfig & posture | clean | clean | SF-POSTURE-1 | ~~SF-FLATTEN-1~~, SF-POSTURE-1 |

---

## Findings ledger

| ID | Issue | In golden? | Expected delta | Class | How verified | Status |
|----|-------|-----------|----------------|-------|--------------|--------|
| **SF-ORDER-1** | `get_firewall_policies` ends `ORDER BY p.device, p.seq` (`firewall.py:61`), but the loader writes `seq` **only on FortiGate nodes** (`loader.py:2701 seq=idx`); Cisco-ACL nodes (`:2742`) wrote `policyid` and **no `seq`** → ACL `:FirewallPolicy` nodes have `seq=NULL`, so the all-NULL secondary key leaves ACE rows in Neo4j scan order, which the tool then renders positionally. Sibling `security_policies.py:118` already orders ACLs correctly (`p.name, p.policyid`) | **no** (no `genie_acl.json` in either golden) | ACL nodes gain `seq=ACE-seq`; ordering becomes defined. Zero output delta on current goldens | **A** | **FIXED** — write `seq: ace.get("seq",0)` on ACL nodes (`loader.py:2746`), mirroring the FortiGate block. Synthetic 3-ACE out-of-order fixture proves row `seq` follows ACE seq + `ORDER BY seq` is stable; both goldens byte-identical | ✅ DONE |
| **SF-SEV-1** | `config_netconf_acl.py` module docstring header says `Severity: medium` (`:10`) while the authoritative class attr is `severity = "low"` (`:28`) — two sources of the rule's intended severity disagree | yes (if `NETCONF_NO_ACL` fires) but **doc-only** | none — code already emits `low`; docstring corrected to match | **A** | **FIXED** — docstring `medium`→`low` (Carlos: code is authoritative). Zero output delta; both goldens byte-identical | ✅ DONE |
| SF-DET-1 | Unsorted multi-finding / evidence-list order inherits the collector's `results` list order: `cis_fg_firewall.py:149` (`seen_names.items()`), `:155` (`policyids`), `cis_fg_security_profiles.py:206` (`unlogged_filter_ids`), `cis_fg_ssl_inspection.py:53` (`no_inspection_ids`) | no-latent (no dup names / no unlogged filters in current data) | sort the lists; golden diff only if collector order ever drifts | **A** | **DEEP-DIG: stays deferred (deliberately).** This is dict-**insertion** order = deterministic *within* a run (NOT R2-FDB-style set nondeterminism). It can only bite on collector output-order drift across runs — no documented drift, so a pin is speculative. Golden-covered → a real drift would surface as a diff anyway | ⏸️ DEFERRED (trigger: collector emits policies/filters in a different order across runs) |
| **SF-SVC-1** | `build_service_resolver` (`policy_resolver.py:173+`) read only `tcp-portrange`/`udp-portrange`; a `TCP/UDP/SCTP` service whose ports live **only** in `sctp-portrange` fell through to `resolver[name]=name` → the resolved `:FirewallPolicy.service` showed the bare object name, no ports | no (the real 88-entry service file has **zero** SCTP-only services; reproduced by synthetic fixture) | resolved service strings gain SCTP ports | **C** | **FIXED** — mirror the tcp/udp handling for `sctp-portrange` (`policy_resolver.py:183`). Synthetic DIAMETER/M3UA fixture proves SCTP ports kept; both goldens byte-identical (no SCTP svc to change) | ✅ DONE |
| SF-GRP-1 | `_expand_group` (`policy_resolver.py:136-147`) cuts off recursion at `depth>3` returning `resolver.get(name,name)` — a 4+-level nested address-group silently emits the child group's **name** instead of its members. Also the whole group flattens to a comma-joined string (irreversible: "A,B" ≡ a member literally named "A, B") | no-latent (real addrgrp data is 1 level deep) | deep groups expand fully; lossy flatten gets a structured form or a truncation marker | **C** | AUDIT-FLAGGED, 80%. Recursion is depth-bounded (no infinite-loop risk — confirmed) | ⏸️ DEFERRED (trigger: 4+-level nested address-group, or a member name with a comma) |
| **SF-ACE-1** | Cisco ACE source/dest picked via `next(iter(dict.keys()))` (`policy_resolver.py:259,263`) — for an ACE matching >1 source/dest network, only the first by genie dict-order was kept (lossy + order-dependent); feeds `:FirewallPolicy.srcaddr/dstaddr` | no (no `genie_acl.json` in either golden; reproduced by synthetic fixture) | multi-network ACEs keep all networks, deterministic | **A**/D | **FIXED** — `", ".join(sorted(src_net.keys()))` for src + dst. Synthetic 3-source/2-dest ACE fixture proves all networks kept + sorted; single-network ACEs unchanged → both goldens byte-identical | ✅ DONE |
| **SF-DENY-1** | `get_firewall_policies` per-device summary (`firewall.py:118-119`) counted only explicit policy `action`; FortiGate's **implicit deny-all** (not a row in `results`) was never represented, so a default-deny box read `(N permit, 0 deny)` — misleading to an operator | no (read-path; not in snapshot) | summary surfaces the implicit deny-all | B/D | **FIXED** (Carlos: add the note) — summary line now `… + implicit deny-all`; detail view appends `[DENY] implicit deny-all (default …)` for FortiGate devices. Read-path → goldens untouched; live ACL test still green | ✅ DONE |
| SF-POSTURE-1 | `get_security_posture` (`security.py:69-78`) tries `_posture_from_neo4j` then falls back to a disk parse — **two producers** of the same posture output with non-identical field coverage/ordering (Neo4j path `sorted(svc_keys)`, disk path raw dict order) | no (read-path; both producers off-snapshot) | converge the two producers' format, or drop the disk fallback | B/D | AUDIT-FLAGGED, 80%. No-silent-fallback-adjacent (a documented fallback that can diverge) | ⏸️ DEFERRED (trigger: same device queried on a SecurityConfig-less run) |
| SF-FIRMWARE-1 | `CIS_FG_2_1_6` (`cis_fg_network.py:138-147`) re-opens `fortigate_system_status.json` to read `version`/`build` from the JSON **top level**, with a bare `import json` in the loop and `except Exception: pass` | yes (rule fires; correct — fields are top-level) | none — cosmetic | D | **DEEP-DIG: downgraded.** The swallowed path is effectively **unreachable** — `load_fg_json` already parsed the same file one line above and the rule `continue`s if it isn't a dict, so the second open can't realistically fail. The `except: pass` masks nothing real (not the no-silent-fallback target). Churning a golden-covered rule for cosmetics = speculative | ⏸️ DEFERRED (cosmetic; fix only if the double-open is refactored away for another reason) |
| SF-HAMON-1 | `CIS_FG_2_5_2` (`cis_fg_network.py:225`) reads HA `monitor` as a scalar (`str(ha.get("monitor","")).strip()`); some FortiOS returns `monitor` as a **list** → `str([...])` is truthy → the "no interfaces monitored" finding silently never fires | no-latent (the golden FortiGate is `standalone`, short-circuits before this) | list-shaped `monitor` handled | B | AUDIT-FLAGGED, 60% | ⏸️ DEFERRED (trigger: an HA-active FortiGate whose `monitor` deserializes as a list) |
| SF-ACTION-1 | `:FirewallPolicy.action` loaded verbatim (`loader.py:2704`); a policy missing `action` stores `""`, which the rules treat as neither `"accept"` (`cis_fg_firewall.py:81`) nor `"deny"` (`:185`) → both the accept-all and explicit-deny checks **silently skip** it | no-latent (real FortiGate always emits `action`) | absent action surfaced, not skipped | B | AUDIT-CONFIRMED (logic) / latent, 85% | ⏸️ DEFERRED (trigger: a policy JSON missing `action`) |
| SF-QORIGIN-1 | All resolvers key on `obj.get("name")` and look policies up by `name` (`policy_resolver.py:69,129,169,206`; `loader.py:2680`), ignoring FortiGate's authoritative `q_origin_key`; after a rename where `name`≠`q_origin_key`, a reference resolves to the raw unresolved string via the `.get(name,name)` fallback — silently, no marker | no-latent (`name==q_origin_key` in all real data) | reference by `q_origin_key`; mark unresolved misses | C | AUDIT-FLAGGED, 55% | ⏸️ DEFERRED (trigger: a config where `name`≠`q_origin_key`) |
| SF-POLICYID-1 | ACL-derived `:FirewallPolicy.policyid` = the ACE `seq` (`loader.py:2742`), so two ACLs on one device with overlapping seq numbers produce colliding `policyid` (disambiguated only by `name`); semantics differ from FortiGate's real `policyid` | no (no `genie_acl.json`) | stable per-ACE identity across ACLs | D | AUDIT-FLAGGED, 70%. (SF-ORDER-1 added `seq` for ordering; identity uniqueness is separate) | ⏸️ DEFERRED (trigger: two ACLs on one device with overlapping seq) |
| SF-NAME-1 | `build_address_resolver` (`policy_resolver.py:61-104`) seeds `{"all":"0.0.0.0/0"}` then iterates addresses **last-wins** and VIPs **first-wins** — an address/VIP name collision, or a custom `all`, resolves by an undocumented, order-dependent tie-break | no-latent (no name collisions; custom `all` has the same value → no visible delta) | document/pin the precedence | **A** | AUDIT-FLAGGED, 70% — arbitrary-but-fixed (R2 "don't chase" category) | ⏸️ DEFERRED (trigger: an address-object/VIP name collision) |
| SF-ADMIN-THRESH-1 | `CIS_FG_2_4_3` (`cis_fg_admin.py:84-90`) flags super-admin only when `count>1`; a device whose **only** admin is super_admin (no least-privilege account at all — the classic CIS gap) produces zero findings | yes (rule runs; one super_admin in real data → no finding) | depends on intended CIS semantics | D | AUDIT-FLAGGED, 70% — **intent call**, not a clear bug | ⏸️ DEFERRED (needs CIS-intent decision) |
| SF-FW-1 | Several security-profile checks fire on **key absence** (`!= "enable"`/`!= "block"`, `cis_fg_security_profiles.py:246,282,319`); element_id keys on profile `name` (`:163` etc.) | yes (rules fire; correct on current data) | none | D | **DEEP-DIG: RULED-OUT.** The absence-over-report is the *correct* fail-closed CIS posture (absent `block`/`enable` = not configured = a real gap), not a bug. The element_id collision is **impossible** — FortiGate enforces unique object names per type/VDOM, so two profiles can't share a name on one device. On real data nothing changes | ❎ RULED-OUT |
| SF-FLATTEN-1 | `_flatten_security_section` (`loader.py:2983`) drops nested dicts with no marker (`# Skip nested dicts`) | n/a | none | D | **DEEP-DIG: RULED-OUT (both sides).** The SecurityConfig loader flattens only 5 FortiGate files (`admin`/`password_policy`/`ntp`/`snmp`/`ha`, `loader.py:3035-3040`) + Cisco `security_config.json` — none carry security-relevant nested dicts. The nested-dict files (antivirus/dnsfilter/accprofile/interface/web_ui_state) are read **directly by the rules**, never flattened into a node. Cisco's only nested dict is `_parser_coverage` metadata (`_`-skipped). No security data lost | ❎ RULED-OUT |
| **SF-ISDB-1** | FortiGate **ISDB** policy refs (`internet-service-name`/`-custom`/`-group` + `-src-`) read **nowhere** in `src/` → ISDB policy dst/src stored empty; `path_tracer` (`path_tracer.py:205`) silently returns "no matching policy". Named address-object resolution is otherwise solid (48/56 production policies → matchable CIDRs) | **AUDIT-CONFIRMED on the production FortiGate** (a Tor/Malicious-block ISDB policy, empty `dstaddr`) — not in either golden (loader-only, weak-net) | P1: ISDB names captured + silent-fail fixed (golden-safe). P2: ISDB→CIDR, path-trace IP-match | C / no-silent-fallback | **DEFERRED 2026-06-25** — full CIDR resolution needs `diagnose internet-service id` over **MFA-gated SSH** to the prod FortiGate (no forward REST). Complete resumable design in `~/.claude/plans/magical-dreaming-truffle.md` | ⏸️ DEFERRED (trigger: FortiGate SSH/MFA creds, or ship Phase 1 alone) |

---

## Ruled out (recorded so it isn't re-litigated)

- **The FortiGate `"enable"/"disable"` truthiness trap is avoided everywhere.** All
  9 `cis_fg_*` files use explicit `== "enable"` / `== "disable"` string equality —
  **zero** instances of `if x:` on the `"disable"` string (which would be truthy →
  silent wrong finding). This was the #1 pre-audit worry.
- **The MCP read-path is clean — no silent-empty Cypher.** Every property and label
  the security/firewall tools read (`firewall.py`, `security.py`,
  `security_policies.py`) matches what `loader.py` writes; the `policy_type AS type`
  and `acl_type IS NOT NULL` bridges are correct; `_query_acls` filters ACLs
  correctly; banner/SNMP/TACACS flattened-key reads all line up. No typo'd labels,
  no missing projections, no unbounded traversals (fleet-bounded, `LIMIT 1` on
  resolves).
- **The genie ACL `accept`/`permit` quirk is handled** (`policy_resolver.py:238`,
  both map to `permit`).
- **`find_fortigate_devices` is `sorted()`** (`cis_fg_helpers.py:52`) → device-level
  finding order is deterministic.
- **Address-group recursion is depth-bounded** (`policy_resolver.py:137`) and
  service-group expansion is a single non-recursive pass → no infinite-loop risk.
- **`security.py` TACACS-server rendering is `sorted()`** (`:598`) → no
  set-iteration nondeterminism in the network overview.
- **`_flatten_security_section` on Cisco data** drops only `_parser_coverage`
  metadata — no security data lost (SF-FLATTEN-1, Cisco side).

---

_Method: audit-first across 9 domains × 4 axes · golden-master-guarded
(`scripts/golden_master.py`: demo `--runs-base /tmp/labs-runs --run
2026-06-23_09-16-04`; hw `--runs-base runs/golden --run hw`) · synthetic-test-first
· validate full suite. Next audit layer: **L1 / physical** — see
`docs/release/` and the L1 hardware-truth protocol._
