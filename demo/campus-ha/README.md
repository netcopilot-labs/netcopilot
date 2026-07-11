# campus-ha — FHRP + LAG + multi-area OSPF + ECMP + dot1x

A protocol-coverage scenario layered on the base [containerlab](../containerlab)
network. It exists to exercise NetCopilot against network features the base
`campus` demo never shows, and to surface where NetCopilot's model, rules, and
views do not yet consume them.

> Everything here is synthetic — RFC 5737 addresses, RFC 5398 ASNs, generic
> device names. No real network, device, IP, or credential appears.

## What it adds on top of the base lab

| Feature | Where | How |
|---|---|---|
| **HSRP** (v2) | `Vlan60` across core-sw-01 ↔ acc-sw-03 | VIP `198.51.100.129`; core active (prio 120, preempt), acc-sw-03 standby |
| **VRRP** | `Vlan61` across core-sw-01 ↔ acc-sw-03 | VIP `198.51.100.145`; core master (prio 120), acc-sw-03 backup |
| **LAG / LACP** | `Port-channel1` on the core ↔ acc-sw-03 trunk | Single-member bundle (2-member needs a second physical link = topology change) |
| **Multi-area OSPF** | VRF BLUE, core-sw-01 as ABR | acc-sw-04 moved fully into **area 1**; core keeps area 0 toward acc-sw-03 |
| **ECMP** | core-sw-01 RIB | bdr-rtr-01 **and** bdr-rtr-02 originate the same anycast `/32` (`198.51.100.200`) into OSPF area 0 |
| **dot1x** | acc-sw-03 `Gi1/0/2` | Authenticator + RADIUS config (config-only; no supplicant yet) |

The new campus VLANs (60/61) ride the **existing** core ↔ acc-sw-03 802.1Q
trunk, so no containerlab topology change is required — the whole scenario is a
config overlay on the 7 running devices, applied over the management network.

## Apply

The per-device config deltas are in [`overlays/`](overlays/). They are applied
on top of a running base lab (see `../containerlab`). Baseline running-configs
should be captured first so the scenario is reversible.

```
# from a host with management reachability to the devices:
python demo/campus-ha/apply-overlays.py      # pushes overlays/*.txt (admin/admin)
```

Then collect a run and load it the usual way:

```
python -m netcopilot run --inventory demo/containerlab/inventory.yaml --site demo
```

## Known scenario limits (documented, not defects)

- **LAG is single-member.** A real 2-member bundle needs a second physical link
  between core-sw-01 and acc-sw-03 (a `topology.clab.yml` edit + redeploy).
- **dot1x is config-only.** Real authentication needs a supplicant container.
- **FortiGate is untouched** in this scenario (fragile single eval license — never
  rebuilt).
