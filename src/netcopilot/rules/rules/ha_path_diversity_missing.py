"""
HA Path Diversity Missing Rule — Detect FortiGate HA members with no path diversity.

In a FortiGate HA pair, each member should ideally cable to different
upstream devices for path diversity. If both active and passive members
connect to the exact same set of upstream switches, a single upstream
failure can take down both HA members' connectivity.

Detection Logic:
    For each FortiGate HA device (os_family=fortios, cluster_declared_size>=2):
        Collect links with ha_member attribution ("active"/"passive")
        Group by ha_member → set of peer devices per member
        If active_peers == passive_peers (identical upstream sets): finding
        If no attributed links: skip (insufficient data)

Related ADRs:
    - Stack & HA Compound Node Visualization
"""

from typing import Any

from netcopilot.rules.base_rule import BaseRule
from netcopilot.rules.finding import Finding


class HaPathDiversityMissingRule(BaseRule):
    """Detect FortiGate HA pairs with no upstream path diversity."""

    rule_id = "HA_PATH_DIVERSITY_MISSING"
    severity = "high"
    title = "HA Path Diversity Missing"
    description = "Both FortiGate HA members cable to the same upstream device(s)"

    def evaluate(
        self,
        model: dict[str, Any],
        context: dict[str, Any],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Build set of FortiGate HA device hostnames
        ha_devices = set()
        for device in model.get("devices", []):
            os_family = (device.get("os_family") or "").lower()
            cluster_size = device.get("cluster_declared_size") or 0
            if os_family == "fortios" and cluster_size >= 2:
                ha_devices.add(device.get("hostname", ""))

        if not ha_devices:
            return findings

        # Build set of stacked device hostnames (cluster_declared_size >= 2)
        # Stacks inherently provide member-level redundancy, so connecting
        # both HA members to the same stack is valid path diversity.
        stacked_devices = set()
        for device in model.get("devices", []):
            cluster_size = device.get("cluster_declared_size") or 0
            if cluster_size >= 2:
                stacked_devices.add(device.get("hostname", ""))

        # For each HA device, collect attributed links
        for hostname in ha_devices:
            peers_by_member: dict[str, set[str]] = {}
            # Track (peer_device, peer_member_id) tuples per HA member
            peer_members_by_ha: dict[str, set[tuple[str, int | None]]] = {}

            for link in model.get("links", []):
                ha_member = link.get("ha_member")
                if not ha_member:
                    continue

                local_dev = link.get("local_device_id", "")
                remote_dev = link.get("remote_device_id", "")

                # Find links where this HA device is an endpoint
                # peer_mid = the stack member ID on the peer side (not HA side)
                if local_dev == hostname:
                    peer = remote_dev
                    peer_mid = link.get("target_member_id")
                elif remote_dev == hostname:
                    peer = local_dev
                    peer_mid = link.get("source_member_id")
                else:
                    continue

                peers_by_member.setdefault(ha_member, set()).add(peer)
                peer_members_by_ha.setdefault(ha_member, set()).add(
                    (peer, peer_mid)
                )

            # Need both active and passive to compare
            active_peers = peers_by_member.get("active", set())
            passive_peers = peers_by_member.get("passive", set())

            if not active_peers or not passive_peers:
                # Insufficient data — skip
                continue

            # No path diversity if both members connect to identical upstream sets
            if active_peers == passive_peers:
                shared = active_peers & passive_peers

                # For stacked peers, check member-level diversity:
                # each HA member must reach multiple stack members of each peer.
                # E.g., Active→SAP:M1+M2, Passive→SAP:M1+M2 = good (any member
                # failure still leaves a path). But Active→SAP:M1, Passive→SAP:M2
                # = bad (each HA member has a single point of failure).
                if shared and shared <= stacked_devices:
                    has_member_diversity = True
                    for ha_role in ("active", "passive"):
                        peer_tuples = peer_members_by_ha.get(ha_role, set())
                        for peer_dev in shared:
                            # Count distinct stack members this HA member reaches
                            mids = {
                                mid for dev, mid in peer_tuples
                                if dev == peer_dev and mid is not None
                            }
                            if len(mids) < 2:
                                has_member_diversity = False
                                break
                        if not has_member_diversity:
                            break
                    if has_member_diversity:
                        continue

                finding = Finding.create(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    element_type="device",
                    element_id=hostname,
                    message=(
                        f"FortiGate HA device has no upstream "
                        f"path diversity. Both active and passive members "
                        f"connect to the same device(s): "
                        f"{', '.join(sorted(active_peers))}. A single upstream "
                        f"failure could affect both HA members."
                    ),
                    key_facts={
                        "hostname": hostname,
                        "active_peers": sorted(active_peers),
                        "passive_peers": sorted(passive_peers),
                        "shared_peers": sorted(shared),
                    },
                    recommendation=(
                        "Consider cabling each FortiGate HA member to multiple "
                        "members of each upstream stack for path diversity. "
                        "This ensures that if one stack member fails, each HA "
                        "member still has an alternate path."
                    ),
                )
                findings.append(finding)

        return findings
