# NetCopilot demo data

A small synthetic network — **no real device data, RFC 5737 documentation IPs
only** — so you can exercise NetCopilot on a fresh clone without collecting from
any real network.

`seed.json` is a 5-device topology: a core router, a distribution switch, two
access switches, and an edge firewall, with OSPF + an eBGP internet edge and a
handful of findings across severities (critical → cis).

## Load it

```bash
# Point at your Neo4j (defaults to bolt://localhost:7687)
python -c "from netcopilot.graph.loader import load_seed; print(load_seed('demo/seed.json'))"
```

Then build + serve the dashboard:

```bash
cd src/netcopilot/dashboard/frontend && npm install && npm run build
rm -rf ../backend/static && cp -r dist ../backend/static
cd /path/to/repo && uvicorn netcopilot.dashboard.backend.main:app --port 8000
# open http://localhost:8000  (run "demo")
```

## What this demonstrates

- The **agent chat** + all 24 MCP tools against the demo run (ask "what are the
  critical findings?", "what happens if edge-fw-01 fails?").
- The **Audit / findings** view (4 findings, severity filters, cross-device tags).
- The **BGP topology view** (the eBGP edge) and per-device detail.

## Fuller demo (collected run)

`load_seed` is a lightweight loader — it populates devices, links, adjacencies
and findings, but not the per-interface link metadata the **Physical topology
view** renders from. For a full all-views demo, ingest a real *collected run*
(`netcopilot run …` over your own lab, or the Containerlab demo lab) so
`load_model` writes the complete graph. That richer demo data is generated
separately (see the Containerlab demo lab).
