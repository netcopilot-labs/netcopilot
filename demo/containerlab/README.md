# Containerlab demo network

A small but realistic ISP-edge / campus network for producing a **full
NetCopilot collected-run** — the kind that populates every dashboard view
(Physical, MGMT, L2/L3, OSPF, BGP) plus findings.

The committed lightweight `demo/seed.json` (loaded via `load_seed`) is enough
to exercise the agent and most tools, but it has no per-interface link
metadata, so it cannot populate the **Physical** topology view. A real
collected run from this lab fills that gap.

> **Everything here is synthetic.** All addresses are RFC 5737 documentation
> ranges, all ASNs are RFC 5398 documentation ASNs, and device names are
> generic. No real network, device, IP, or credential appears in this lab.

## Topology

```
        isp-01(AS64497)   isp-02(AS64498)   isp-03(AS64499)     ← fictional ISPs (IOS-XE)
             │ eBGP            │ eBGP            │ eBGP
         bdr-rtr-01       bdr-rtr-02       bdr-rtr-03           ← border routers (IOS-XR), AS 64496
             └──────┬──────────┼─────────────────┘
                    │   iBGP (core-sw-01 = route-reflector)
                core-sw-01 ─────────────────── edge-fw-01       ← core L3 switch (RR) + FortiGate
              VRF │      │ VRF              │ OSPF
          acc-sw-03   acc-sw-04         acc-sw-01               ← access switches (Cat9kv)
           (OSPF)      (OSPF)            (OSPF)
```

The FortiGate eval license allows 3 interfaces (mgmt + 2 data), so the firewall
fronts a single access switch (`acc-sw-01`); `acc-sw-03/04` hang off the core.

| Node | Role | NOS | Containerlab kind |
|---|---|---|---|
| `bdr-rtr-01/02/03` | Border routers — eBGP to an ISP, iBGP client of the RR | IOS-XR | `cisco_xrv9k` |
| `isp-01/02/03` | Three fictional ISPs — eBGP peers, **not collected** (external) | IOS-XR | `cisco_xrd` |
| `core-sw-01` | Core L3 switch + iBGP route-reflector | IOS-XE | `cisco_cat9kv` |
| `acc-sw-01` | Access behind the firewall (OSPF) | IOS-XE | `cisco_cat9kv` |
| `acc-sw-03` | Access on the core — **dual-VRF** (RED + BLUE) over a trunk, OSPF per VRF | IOS-XE | `cisco_cat9kv` |
| `acc-sw-04` | Access on the core — single VRF (BLUE), OSPF | IOS-XE | `cisco_cat9kv` |
| `edge-fw-01` | Firewall between core and access | FortiOS 7.4.12 | `fortinet_fortigate` |

Addressing: mgmt `192.0.2.0/24`, internal links `198.51.100.0/24`, ISP-facing
eBGP `203.0.113.0/24`. AS 64496 internal; ISPs 64497/64498/64499.

The ISPs run in the lab so the eBGP sessions establish, but they are **excluded
from the NetCopilot inventory** (`inventory.yaml`) — they are upstream providers
we don't manage. NetCopilot therefore models them as **external eBGP peers**:
they appear in the BGP view as `AS 64497/64498/64499` and are absent from the
physical topology, exactly as a real upstream would be.

## Prerequisites

- A Linux host with **Docker**, **Containerlab**, and **KVM** (`/dev/kvm`).
  The VM-based nodes (xrv9k, cat9kv, FortiGate) need nested virtualization —
  use a bare-metal or KVM-capable instance, not a standard shared cloud VM.
  (The XRd ISP nodes are native containers and need no KVM.)
- For the `cisco_xrd` nodes, raise the host inotify limits before deploy:
  `sudo sysctl -w fs.inotify.max_user_instances=64000 fs.inotify.max_user_watches=64000`
- The vendor images are **not** shipped here (licensing). You build the
  Containerlab/vrnetlab containers yourself from images you obtain from Cisco
  (or the CML refplat) and Fortinet:

  | Image you provide | Built container (referenced by `topology.clab.yml`) |
  |---|---|
  | IOS-XR XRv9k qcow2 | `vrnetlab/cisco_xrv9k:<ver>` |
  | Catalyst 9000v qcow2 | `vrnetlab/cisco_cat9kv:<ver>` |
  | XRd control-plane tar.gz | `ios-xrd-control-plane:<ver>` (native container — `docker load`, no vrnetlab build, no KVM) |
  | FortiGate-VM KVM qcow2 | `vrnetlab/vr-fortios:<ver>` |

  Build them with [hellt/vrnetlab](https://github.com/hellt/vrnetlab) (`make
  docker-image` per platform dir). Bleeding-edge NOS versions need a recent
  vrnetlab; build its base image first with `./build-base-image.sh <ver>` if
  the pinned `ghcr.io/srl-labs/vrnetlab-base` tag isn't published yet.

## Deploy

Nodes boot **config-less**, then take their routing config post-boot over the
management network:

```bash
sudo containerlab deploy -t topology.clab.yml
# wait until the nodes are healthy (xrv9k is the slow one, ~10-15 min on 4 vCPU)

python3 -m venv venv && . venv/bin/activate && pip install netmiko
./apply-configs.py            # pushes configs/*.cfg to all 12 nodes
# allow ~60 s for OSPF/BGP to converge
```

Why post-boot rather than Containerlab `startup-config`: the serial-console
startup-config push is unreliable on these heavy images — it drops the scrapli
session on **xrv9k** under concurrent boot load and **truncates** on cat9kv (the
routing section is silently dropped). Booting config-less keeps clab's
management/SSH setup intact on every node, and `apply-configs.py` adds the
routing config additively. After it runs, all 12 devices accept **admin/admin**.

Notes:
- IOS-XR (`xrv9k`) first boot is slow (SELinux relabel + reboot); it needs
  ≥4 vCPU (`QEMU_SMP` is set to 4 in the topology) — it will not finish booting
  on the default 2.
- This lab uses IOS-XR **7.11.1**, not 26.1.1: the 26.1.1 image is too new for
  current vrnetlab and hard-hangs at boot (guest-kernel incompatibility); 7.11.1
  boots cleanly.
- FortiGate boots in ~90 s and runs **unlicensed (evaluation mode)**, which is
  fully sufficient for configuration and collection. FortiGate collection uses a
  REST API token — create one on `edge-fw-01` and set
  `NETCOPILOT_FORTIGATE_API_TOKEN`.

## Run NetCopilot against the lab

The node mgmt IPs live on the Containerlab bridge (`192.0.2.0/24`). Run
NetCopilot from the lab host, or from a remote host with a route to that
subnet:

```bash
export NETCOPILOT_SSH_USERNAME=admin
export NETCOPILOT_SSH_PASSWORD=admin
export NETCOPILOT_FORTIGATE_API_TOKEN=<token created on edge-fw-01>
export NEO4J_PASSWORD=<your-neo4j-password>

docker compose up -d neo4j           # from the repo root
python -m netcopilot run --inventory inventory.yaml --site demo
```

Then serve the dashboard and open the `demo` run — the Physical view is now
populated from real per-interface link metadata, alongside the MGMT, L2/L3,
OSPF, and BGP views and the findings.

## Teardown

```bash
sudo containerlab destroy -t topology.clab.yml --cleanup
```
