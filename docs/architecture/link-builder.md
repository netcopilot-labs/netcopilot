# The Link Builder — turning per-device facts into a typed, evidence-backed topology

The link builder is the heart of NetCopilot's **model** layer. It takes the
canonical per-device facts produced by the parser and reconstructs the network's
**topology**: which devices are connected, over which interfaces, by what kind of
link, and — crucially — *with what evidence and how much confidence*.

```
Inventory → Collect → Parse → [ MODEL: link builder ] → Load (Neo4j) → Rules → Clients
```

Source: [`src/netcopilot/model/link_builder.py`](../../src/netcopilot/model/link_builder.py),
orchestrated by [`src/netcopilot/model/model_builder.py`](../../src/netcopilot/model/model_builder.py).

---

## 1. The problem

A device doesn't know the topology. It knows *fragments*: a CDP table, an LLDP
table, an ARP cache, a MAC/FDB table, LACP partner IDs, the hardware MAC of each
of its interfaces. Some fragments are strong evidence of a cable (CDP says "my
Gi1/0/4 hears dist-sw on its Gi1/0/3"); others are weak inference ("these two
interfaces share a /30, so they're *probably* adjacent").

The link builder's job is to fuse all of those fragments — across **every**
device, across **multiple vendors** (Cisco IOS-XE, IOS-XR, FortiGate) — into one
deduplicated set of links, each carrying:

- the two endpoints (`device:interface` on both sides),
- a **discovery method** (how it was found),
- a **confidence** level,
- a **link type** (physical cable, management, L3-reachability, …),
- and an **evidence** trail back to the raw facts.

Three design principles govern the whole module:

- **Deterministic** — same facts always produce the same model (results are sorted).
- **Traceable** — every link records evidence strings pointing at its source.
- **Explicit** — missing data means *skip*, never *guess*.

---

## 2. The unit of discovery: `LinkCandidate`

Every discovery method emits zero or more `LinkCandidate` objects — an
*intermediate* result, before deduplication:

```python
@dataclass
class LinkCandidate:
    local_device:  str
    local_interface: str | None            # original name, for display
    local_interface_canonical: str | None  # lowercase canonical, for matching
    remote_device: str
    remote_interface: str | None
    remote_interface_canonical: str | None
    discovery_method: str                  # "cdp_bilateral", "arp_subnet", …
    confidence: str                        # very_high … very_low
    evidence: list[str]                    # ["cdp:A→B", "cdp:B→A"]
    peer_collected: bool                   # was the remote device collected?
```

Interface names are normalised at three levels (see
[`interface_normalizer.py`](../../src/netcopilot/model/interface_normalizer.py)):
the **original** form (`HundredGigE0/0/1/0`) for display, a **short** form
(`Hu0/0/1/0`) for the model, and a **canonical** lowercase form
(`hundredgige0/0/1/0`) used to match the same interface seen by different
sources. `canonicalize()` is what lets a CDP "Gig 1/0/3" and a config
"GigabitEthernet1/0/3" be recognised as one interface.

---

## 3. The evidence ladder

Discovery methods are ordered by *strength of evidence*. They run in sequence in
`model_builder` and all feed one candidate pool that is then deduplicated.

| Discovery method | Reads | What it proves | Confidence | Link type |
|---|---|---|---|---|
| `discover_cdp_links` | CDP neighbor table | Both ends name each other → a cable | `very_high` (bilateral) / `high` (unilateral) | physical |
| `discover_lldp_links` | `genie_lldp.json` | Same, vendor-neutral | `very_high` / `high` | physical |
| `discover_lacp_links` | `genie_lag.json` + global MAC lookup | LACP partner MAC + port → a bundle member cable | `high` / `medium` | physical |
| `discover_stack_interconnect_links` | `stack_ports` / SVL config | StackWise / SVL / HA interconnect (self-referential) | `very_high` / `high` | stack_interconnect |
| `discover_fdb_firewall_links` | ARP → FDB → LACP fingerprint (FortiGate) | Switch port ↔ firewall member port | `high` | physical / management |
| **`discover_mac_fingerprint_links`** | **ARP + per-interface hardware MACs (+ FDB)** | **A's port is wired to B's port — no protocol needed** | **`very_high` / `high`** | **physical** |
| `discover_mgmt_fdb_member_links` | cluster member BIA + mgmt-VLAN FDB | OOB management cable to a stack standby member | `high` | management |
| `discover_arp_subnet_links` | `genie_arp.json` + subnet index | Two interfaces share a subnet and ARP each other → *probably* adjacent | `medium` | l3_reachability |
| `discover_mac_subnet_links` | `genie_fdb.json` + MAC index | A MAC learned on a physical port, owner shares a subnet | `low` | l3_reachability |
| `discover_subnet_only_links` | subnet index only | Same small subnet, nothing else | `very_low` | subnet_association |

The dividing line is **proof vs. inference**. CDP/LLDP/LACP/stack/FDB/MAC-
fingerprint are *cable-confirmed* (`_CABLE_METHODS`) → they become `physical`.
ARP/MAC/subnet are *L3 inferences* → they become `l3_reachability` and are hidden
from the dashboard's physical view.

---

## 4. MAC fingerprinting — physical cabling without a discovery protocol

CDP and LLDP make topology easy. But they can be disabled, unsupported, or absent
across a vendor boundary — and then the classic builder falls back to
`arp_subnet`, which can only *infer* adjacency from shared subnets and is hidden
from the physical view. `discover_mac_fingerprint_links` closes that gap by using
a fact that is *always* true and *always* collected: **every interface has a
globally-unique burned-in hardware MAC**.

### The principle

If device **A**'s ARP entry for a peer IP returns a MAC, and that MAC is the
*hardware address* of device **B**'s interface `X`, then A's port is physically
wired to `B:X`. No protocol required — a MAC is a hardware fingerprint.

### The global hardware-MAC index

`_build_hw_mac_to_device_index()` builds `normalized_mac → {(host, interface), …}`
from every interface's burned-in MAC, across vendors:

- Cisco: `genie_interface.json[intf].phys_address`,
- FortiGate: `fortigate_monitor_interface.json results[port].mac`.

MACs are normalised format-agnostically (`_normalize_mac` strips `.:-`), so Cisco
`aac1.ab9f.f7a9` and FortiGate `aa:c1:ab:9f:f7:a9` unify. The index keeps **all**
interfaces a MAC maps to — this matters because some virtual platforms reuse one
burned-in MAC across several of their own ports.

### Phase 1 — L3 routed ports

For each ARP entry `(host, local_intf, peer_ip, peer_mac)`:

1. Resolve `peer_mac` through the index to the owning **device** (require exactly
   one — this drops shared virtual MACs like HSRP/VRRP/HA, which aren't real
   interface MACs and so aren't in the index anyway).
2. The **local** port is A's own ARP interface — authoritative.
3. If B's ARP independently resolves back to A, the link is **bilateral**
   (`very_high`), and the **remote** port is taken from *B's own ARP interface*
   toward A — **never** from the index.

That last rule is the subtle one. On a switch that reuses one MAC across ports,
`peer_mac → index → remote_port` is ambiguous *for the port* (but never for the
*device*). Reading the remote port from the remote's own ARP sidesteps the
ambiguity entirely. When only one side resolves (e.g. the peer has no ARP), the
link is **unilateral** (`high`) and the remote port is taken from the index only
if it's unambiguous.

### Phase 2 — L2 switchports

When A's ARP interface is an SVI (a virtual `Vlan…`), the physical port is one
hop away in the **FDB**: look up `peer_mac` in A's MAC table to find the physical
port it was learned on, then find *that* port's hardware MAC in B's FDB to get
B's physical port. This needs an FDB on both ends (IOS-XE switches), and no-ops
gracefully where there isn't one.

### Guardrails (why it doesn't invent cables)

- **Single owning device** — a MAC that maps to more than one device is ambiguous → skipped.
- **Multi-access segments** — if one local interface resolves *more than one*
  distinct remote device, it's a shared segment (a management LAN, an IXP), not a
  point-to-point cable → skipped, left to `arp_subnet`.
- **LAG aggregates** — `Port-channel` / `Bundle-Ether` are skipped; LACP owns
  their member cables.
- **Virtual interfaces** — excluded from the L3 path (they belong to Phase 2 or
  to L3-reachability).

The net effect: the method emits a `physical` link only when it has two-sided (or
unambiguous one-sided) hardware proof of a point-to-point cable. On a CDP/LLDP-rich
network it typically produces nothing new — the cable is already known — and is a
safe no-op; on a protocol-less routed network it reconstructs the backbone.

---

## 5. Deduplication — one cable, one link

All candidates from all methods land in one pool, then `deduplicate_links()`
collapses them:

1. **Pair key** — each candidate gets a canonical key from its *sorted* endpoint
   pair (`device:canonical_interface` on both sides). Candidates for the same
   interface pair — regardless of direction or which method found them — share a key.
2. **Winner** — within a key group, the highest `CONFIDENCE_RANK` candidate wins
   and becomes the link's `discovery_method` / `confidence`.
3. **Evidence accumulates** — every candidate's evidence strings are merged onto
   the surviving link, so the trail back to the raw facts is preserved even for
   the methods that "lost".
4. **Bilateral promotion** — methods in `_BILATERAL_METHODS` mark the link as
   confirmed from both directions.

This is why a routed cable found by *both* `arp_subnet` (medium) and
`mac_fingerprint_bilateral` (very_high) becomes one `physical` link — the
fingerprint wins, the ARP evidence rides along. It's also why the fingerprint is
*additive* and never duplicates a CDP cable: same interface pair → same key → merge.

---

## 6. Classification — from candidate to link type

After dedup and L2/L3 enrichment, `classify_link_type()` assigns the final
`link_type` in strict priority order (first match wins):

| Priority | Condition | link_type |
|---|---|---|
| 0 | confirmed cable on a non-management access VLAN | physical |
| 1 | touches a `mgmt_switch` (sub-rules for OOB / mgmt-VLAN / inband) | management / infrastructure / physical |
| 2 | endpoint is a management interface or on a management subnet | management / l3_reachability |
| 3 | `discovery_method == "subnet_only"` | subnet_association |
| 4 | **either endpoint is a virtual interface** (Loopback, SVI, BVI, Tunnel, NVE, FortiGate numeric) | l3_reachability |
| 5 | everything else (a confirmed cable on physical ports) | physical |

Priority 4 is the gate that keeps inference out of the physical view: a link
anchored on an SVI is L3-reachability even if its method is a cable method — which
is exactly why the MAC fingerprint's L3 path only ever anchors on *physical*
routed interfaces.

The link type then maps 1:1 to a Neo4j relationship in
[`graph/schema.py`](../../src/netcopilot/graph/schema.py) `LINK_RELATIONSHIP_MAP`:

```
physical            → :PHYSICAL_CABLE
management          → :MGMT_LINK
infrastructure      → :INFRASTRUCTURE_LINK
l3_reachability     → :L3_REACHABILITY
subnet_association  → :INFERRED_LINK
stack_interconnect  → :STACK_LINK
```

---

## 7. How it reaches the dashboard

The dashboard's **Physical** view
([`routes/topology.py`](../../src/netcopilot/dashboard/backend/routes/topology.py))
deliberately shows only *proven* cables. It queries `:PHYSICAL_CABLE` +
`:INFRASTRUCTURE_LINK` and then filters to `confidence ∈ {high, very_high}`:

```python
VIEW_REL_TYPES["physical"] = ["PHYSICAL_CABLE", "INFRASTRUCTURE_LINK"]
_PHYSICAL_CONF = {"high", "very_high"}
```

So a link only appears as a physical cable if it was discovered by a cable method
with high confidence. Inferred `:L3_REACHABILITY` links are visible in the **All**
view but never masquerade as cables. This is why, on a network with no CDP/LLDP,
the physical view is empty *until* MAC fingerprinting promotes the routed links
from inferred `l3_reachability` to proven `physical`.

For clustered devices (stacks, SVL, FortiGate HA), links carry
`source_member_id` / `target_member_id` so the renderer can anchor a cable to the
correct member of a compound node rather than the cluster box.

---

## 8. Confidence and priority reference

```python
CONFIDENCE_RANK = {              # dedup winner selection (higher wins)
    "very_high": 5, "high": 4, "medium": 3, "low": 2, "very_low": 1,
}

DISCOVERY_PRIORITY = {           # render styling / cable-vs-L3 ranking (lower = stronger)
    "cdp_bilateral": 1,
    "lldp_bilateral": 2, "stack_interconnect": 2, "mac_fingerprint_bilateral": 2,
    "cdp_unilateral": 3,
    "lldp_unilateral": 4, "mac_fingerprint_unilateral": 4,
    "lacp_bilateral": 5, "fdb_firewall": 5,
    "lacp_unilateral": 6,
    "arp_subnet": 7, "mac_subnet": 9, "subnet_only": 11,
}
```

A `discovery_priority < 7` marks a link as cable-grade; `>= 7` marks it as L3/
inferred. The MAC-fingerprint methods sit at 2 and 4 — peers of LLDP — because a
two-sided hardware-MAC match is as strong as a two-sided protocol exchange.

---

## 9. Summary

The link builder is a layered evidence engine. It gathers every fragment a device
exposes, ranks them by how strongly they prove a cable, deduplicates them into one
link per connection with the strongest method winning and all evidence retained,
and classifies each into a typed Neo4j relationship. The result is a topology that
is honest about what it *knows* (a CDP-confirmed or MAC-fingerprinted cable) versus
what it *infers* (a shared-subnet adjacency) — and that can reconstruct the
physical layer even when no discovery protocol is available to ask.
