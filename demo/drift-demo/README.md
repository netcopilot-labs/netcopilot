# Drift demo — synthetic before/after pair

A curated two-run pair of the synthetic site **`demo-drift`** used to demo and
regression-test the run-to-run diff ("drift") feature. Both runs are **100%
synthetic** — RFC 5737 documentation IPs (`192.0.2/198.51.100/203.0.113`) and
made-up hostnames. No production data.

Unlike the other demos (`campus`, `l2-campus`) which ship genie `facts/` and
rebuild the model, this pair is **model-only**: each run carries
`model/network_model.json` + `findings/findings.json` directly (the loader reads
a model without facts; route/security enrichment is simply skipped). So these
JSON files are the committed source — do not gitignore them.

## The two runs

| Run | dir | run_id (when loaded) |
|-----|-----|----------------------|
| before | `before/` | `2026-07-01_09-00-00` |
| after  | `after/`  | `2026-07-01_10-00-00` |

## Curated changes (before → after)

Chosen to exercise every change type × tier the drift engine classifies:

| Change | Where | Tier |
|--------|-------|------|
| Device `acc-sw-02` decommissioned | devices | **removed** (ghost node) |
| Link `core-sw-01:Gi0/2--acc-sw-02:Gi0/1` lost | links | **removed** (ghost edge) |
| Interface `acc-sw-02:Gi0/1` gone | interfaces | **removed** |
| Finding `VLAN_MISMATCH::acc-sw-02` cleared | findings | **removed** |
| New link `core-sw-01:Gi0/3--acc-sw-01:Gi0/2` | links | **added** |
| New interface `acc-sw-01:Gi0/2` | interfaces | **added** |
| New OSPF LSA `198.51.100.50` (route advertised) | ospf_lsdb | **added** (route) |
| Finding `ACL_PERMIT_ANY::acc-sw-01` raised | findings | **added** (ACL) |
| `acc-sw-01:Gi0/1` oper_status up → down | interfaces | **changed** |
| VLAN 10 name `USERS` → `USERS-A` | shared_services | **changed** |
| L2 domain `vlan10-dom0` membership drops `acc-sw-02` | l2_domains | **changed** |
| `core-sw-01:Gi0/1` `prefixes_received` 100 → 105 | interfaces | **info** |
| `core-sw-01:Gi0/5` `arp_count` 40 → 42 | interfaces | **info** |
| `core-sw-01` `dhcp_leases` 12 → 15 | devices | **info** |
| BGP session `up_down` 2d21h → 3d05h (+ msg counters) | adjacencies | **info** (uptime; counters are volatile-ignored) |

Note: routes and ACLs are not first-class model entities — they surface in the
diff as an OSPF LSA (route) and a finding (ACL), which is how NetCopilot
represents them.

## Regenerating / loading

- **Golden regression:** `tests/test_drift_golden.py` diffs this pair and
  compares to `fixtures/golden/drift-demo.json`. If you intentionally change the
  pair, regenerate that golden.
- **Load into a running dashboard:** `python -m netcopilot.drift_demo_seed`
  (stages both runs into `RUNS_DIR` and loads them into Neo4j as site
  `demo-drift`). Then in the dashboard: Audit tab → **⇄ Diff**.
