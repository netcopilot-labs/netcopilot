# campus-ha — NetCopilot coverage evidence

What NetCopilot sees (and misses) when the campus-ha overlay is live on the base
lab. Measured from a real collected run (7 IOS devices + FortiGate) loaded into
Neo4j, then inspected in `model/network_model.json` and `findings/findings.json`.
This is the evidence gate for the protocol-coverage roadmap: each row is a
documented failing (or passing) case, not an assertion.

## Scorecard

Updated after **Sprint 20 (FHRP first-class)** closed the HSRP/VRRP gaps. The
`⟶ s20` rows moved from Dark/Absent to Full.

| Feature (configured & converged live) | Collected? | Modeled? | Rule / finding? | Verdict |
|---|---|---|---|---|
| **Multi-area OSPF** (core = ABR, area 0.0.0.1) | ✅ `genie_ospf` | ✅ adjacency carries `area=0.0.0.1` | ✅ `OSPF_AREA_SINGLE_ABR` fires | **FULL — works end to end** |
| **HSRP** (Vl60, core active, VIP .129) | ✅ `genie_hsrp` | ✅ `fhrp_group` SharedService (members, state, active_device) | ✅ `HSRP_AUTH_MISSING` / `HSRP_TRACKING_MISSING` fire (9 HSRP rules executable) | **FULL — closed by s20** |
| **VRRP** (Vl61, core master, VIP .145) | ✅ `genie_vrrp` (`show vrrp all` parse-fallback) | ✅ `fhrp_group` SharedService | ✅ 5 VRRP rules executable | **FULL — closed by s20** |
| **LAG / port-channel** (Po1 LACP) | ✅ `genie_lag` | ✅ first-class bundle on the Po Interface node (protocol, oper_status, per-member LACP state incl. bundled/partner_id) | ✅ 8 LAG rules executable (`lag_health.py`); LACP_ERRORS honestly manual_review | **FULL — closed by s22** |
| **dot1x** (authenticator on acc-sw-03 Gi1/0/2) | ✅ `genie_dot1x` | ❌ 0 dot1x keys in model | ❌ (only generic BPDU-guard / port-security L2SEC findings) | **DARK — collected, never consumed (slice C)** |
| **ECMP** (2 equal-cost paths to anycast /32) | ✅ `genie_routing` | ❌ model has no routing table (`routes` absent); anycast appears only as a shared `/32` subnet with two owners | ❌ | **DARK — no RIB / multipath modeling (deferred, ADR-0023)** |

## What this proves for the roadmap

- **The "dark layer" is real and reproducible.** HSRP and dot1x are collected on
  every run and thrown away at the model boundary; VRRP has no collector keyword
  at all; ECMP has no routing-table representation to hang multipath on. A user
  asking "who is my active gateway?" or "are both uplinks forwarding?" gets
  nothing today, even though the facts are on disk.
- **LAG is half-done.** The member→bundle mapping exists on the physical
  interfaces, but there is no `Port-channel` object to select, and no LAG-health
  rule fires — so "show me this bundle" has no answer.
- **Multi-area OSPF already works end to end** — collected, modeled, and a rule
  (`OSPF_AREA_SINGLE_ABR`) fires correctly. This is the shape every other row
  should reach.

## Priority implications (evidence-driven)

1. **Consume the dark FHRP + dot1x facts** (HSRP first — data already present;
   VRRP needs a collector keyword added). Highest leverage: no new collection,
   pure model + rules + view work.
2. **Promote LAG to a first-class object** (bundle node + LAG-health rule).
3. **ECMP** is the largest: it needs routing-table modeling before multipath can
   be represented — bigger than the others, correctly lower priority.

## Reproduce

```
python demo/campus-ha/apply-overlays.py            # push overlay (admin/admin)
python -m netcopilot.cli run --inventory demo/containerlab/inventory.yaml \
       --site demo --runs-dir /tmp/labs-runs        # collect + model + load
```

Facts, model, and manifest in this directory are the captured artifacts of that
run. Baseline running-configs were saved before the overlay for reversibility.
