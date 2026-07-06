"""Bootstrap candidate generator (s11, ADR-0013).

Reads a YAML inventory + a collected run's facts + existing NetBox
state (via :class:`NetBoxAdapter`) and stages :NetBoxPendingWrite
candidates for everything NetCopilot can derive deterministically:

    * devices         (from YAML inventory)
    * manufacturers   (derived from device.os: iosxr/iosxe → Cisco,
                       fortios → Fortinet)
    * platforms       (one per distinct device.os)
    * sites           (from YAML device.site field)
    * interfaces      (from runs/<run_id>/facts/<device>/genie_interface.json)

VLAN candidates are deferred to the IPAM sprint (per-device-per-VLAN
dedup needs the operator-review pass first).

Idempotent: re-running against unchanged inputs produces zero new
candidates. Dedup uses ``(source, object_type, payload_name)`` against
both existing :NetBoxPendingWrite rows AND existing NetBox state.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from netcopilot.declared_state import get_source
from netcopilot.inventory.base import normalize_os
from netcopilot.declared_state.staging import stage_candidate

log = logging.getLogger(__name__)


# ── OS → Manufacturer / Platform mapping ─────────────────────────────────────
#
# The inventory's ``os:`` field is the source of truth. NetBox separates
# manufacturer (vendor) from platform (driver/family). Both are derived
# deterministically below.

_OS_TO_MANUFACTURER = {
    "ios-xr": "Cisco",
    "ios-xe": "Cisco",
    "fortios": "Fortinet",
}

# Platform slug + display name. NetBox best-practice is a stable slug.
OS_TO_PLATFORM = {
    "ios-xr": ("cisco-ios-xr", "Cisco IOS-XR"),
    "ios-xe": ("cisco-ios-xe", "Cisco IOS-XE"),
    "fortios": ("fortinet-fortios", "Fortinet FortiOS"),
}

# Cluster modeling decision (ADR-0013):
#   * os=fortios + YAML cluster.size > 1  → NetBox dcim.Cluster (HA pair)
#   * os=iosxr/iosxe + YAML cluster.size > 1 → NetBox custom_fields on Device
#     (stack_cluster + stack_size); no separate dcim.Cluster object.
# Stacks could be modeled as dcim.VirtualChassis but that forces per-physical-
# member Device records, breaking 1:1 diff parity with NetCopilot's Neo4j
# :Device. Superseded by the per-physical-device model below.

_HA_PAIR_OS = {"fortios"}


# ── Result container ─────────────────────────────────────────────────────────


@dataclass
class BootstrapResult:
    """Summary of a bootstrap run.

    Counts are by object_type. ``new`` is candidates staged this run;
    ``skipped`` is the no-op count (idempotency proof — already in pending
    or already in NetBox).
    """
    new: dict[str, int] = field(default_factory=dict)
    skipped: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    #: Total candidates in the queue awaiting approval after this run — the
    #: actionable STATE (gaps between the network and NetBox), not just what
    #: this click staged. Set by ``run()``.
    pending_total: int = 0

    @property
    def total_new(self) -> int:
        return sum(self.new.values())

    @property
    def total_skipped(self) -> int:
        return sum(self.skipped.values())

    def format_summary(self) -> str:
        # Line 1 — what THIS run did.
        if self.total_new == 0:
            head = "No new candidates — every object in this run is already documented or staged."
        else:
            parts = ", ".join(
                f"{n} {t}" + ("s" if n != 1 else "") for t, n in sorted(self.new.items()) if n
            )
            head = f"Staged {self.total_new} new candidate(s) ({parts})."
        # Line 2 — the actionable STATE. The pending queue IS the gap between
        # the network and NetBox: freshly bootstrapped, or things deleted from
        # NetBox that the network still has. Surfacing it here is the whole
        # point — "0 new" with a non-empty queue must not read as "all done".
        if self.pending_total > 0:
            state = (
                f"→ {self.pending_total} candidate(s) awaiting your approval in the "
                f"Reconcile tab — NetBox is missing them."
            )
        else:
            state = "→ NetBox is in sync with this run — nothing to approve."
        warnings_line = (
            f"{len(self.warnings)} warning(s) — some candidates could not be staged (see logs)."
            if self.warnings else ""
        )
        return "\n".join(line for line in [head, state, warnings_line] if line)


def _runs_dir() -> Path:
    """Resolve the runs base dir at call time (RUNS_DIR env, default ./runs)."""
    return Path(os.environ.get("RUNS_DIR", "runs"))


# ── Main entry point ─────────────────────────────────────────────────────────


def run(run_id: str, inventory_path: str | Path) -> BootstrapResult:
    """Bootstrap NetBox candidate generation from an inventory + collected run.

    Args:
        run_id: Run directory name (under ``RUNS_DIR``) to source interfaces,
            cluster members, and transceivers from. Required — no magic
            "latest run" discovery; the caller (CLI / route) resolves it.
        inventory_path: Path to the inventory ``lab.yaml`` the run was
            collected from.

    Returns:
        :class:`BootstrapResult` with per-object_type new/skipped counts
        and any warnings collected during the run.
    """
    log.info("Bootstrap starting from inventory=%s run_id=%s", inventory_path, run_id)

    yaml_adapter = get_source("yaml", inventory_path=inventory_path)
    yaml_devices = yaml_adapter.get_devices()

    # NetBox state (for idempotency dedup). The adapter is queried on every
    # run so re-runs after real writes still dedup.
    netbox_adapter = None
    try:
        netbox_adapter = get_source("netbox")
        netbox_devices = {d["name"] for d in netbox_adapter.get_devices()}
        netbox_sites = {s["slug"] for s in netbox_adapter.get_sites()}
        netbox_clusters = {c["name"] for c in netbox_adapter.get_clusters()}
        # s13 fix: these were pending-only deduped, so re-running bootstrap
        # against a populated NetBox re-staged every already-documented
        # object (harmless — approve auto-resolves — but pure queue noise).
        netbox_manufacturers = {m["name"] for m in netbox_adapter.get_manufacturers()}
        netbox_platforms = {p["slug"] for p in netbox_adapter.get_platforms()}
        netbox_vcs = {v["name"] for v in netbox_adapter.get_virtual_chassis()}
    except Exception as exc:
        log.warning("NetBoxAdapter unavailable, dedup will use staged-only: %s", exc)
        netbox_adapter = None
        netbox_devices = set()
        netbox_sites = set()
        netbox_clusters = set()
        netbox_manufacturers = set()
        netbox_platforms = set()
        netbox_vcs = set()

    result = BootstrapResult()

    # provision NetBox-side prerequisites (ClusterType +
    # device custom_fields + DeviceRoles + Manufacturers). Outside the
    # staging queue because these are plumbing, not operator-decision
    # content. Failure here aborts bootstrap with a clear error before
    # any candidate is staged.
    if netbox_adapter is not None:
        try:
            infra = netbox_adapter.ensure_infrastructure()
            log.info("NetBox infrastructure ensured: %s", infra)
        except Exception as exc:
            raise RuntimeError(
                f"Bootstrap aborted: NetBox infrastructure provisioning failed. {exc}\n"
                "Check that NETBOX_API_TOKEN has write permission for "
                "virtualization.cluster_types, extras.custom_fields, "
                "dcim.device_roles, and dcim.manufacturers."
            ) from exc

        # Auto-provision DeviceType records — one per unique chassis model
        # discovered in the run's device_facts.json. NetBox 4.6
        # requires Device.device_type as an FK; bootstrap stages devices
        # with device_type=<numeric id> so the approve path doesn't need
        # to resolve at write time. Per-physical-device model: now walks cluster_members too
        # so per-physical-member chassis (rare hardware-refresh case) is
        # covered.
        _device_type_id_by_slug = _provision_device_types(
            yaml_devices, run_id, netbox_adapter, result,
        )
    else:
        _device_type_id_by_slug = {}

    # Existing :NetBoxPendingWrite state — dedup key is (object_type, name).
    pending_index = _index_existing_pending()

    # ── Sites ────────────────────────────────────────────────────────────────
    _bootstrap_sites(yaml_devices, netbox_sites, pending_index, result)

    # ── Clusters (FortiGate HA only) ─────────────────────────────────────────
    _bootstrap_clusters(yaml_devices, netbox_clusters, pending_index, result)

    # ── VirtualChassis (Cisco stacks only) ───────────────────────────────────
    _bootstrap_virtual_chassis(yaml_devices, run_id, pending_index, result, netbox_vcs=netbox_vcs)

    # ── Manufacturers ────────────────────────────────────────────────────────
    _bootstrap_manufacturers(yaml_devices, pending_index, result, netbox_manufacturers=netbox_manufacturers)

    # ── Platforms ────────────────────────────────────────────────────────────
    _bootstrap_platforms(yaml_devices, pending_index, result, netbox_platforms=netbox_platforms)

    # ── Devices (Per-physical-device model: per-physical-member expansion for stacks + HA) ─────
    _bootstrap_devices(
        yaml_devices, netbox_devices, pending_index, result,
        run_id=run_id,
        device_type_id_by_slug=_device_type_id_by_slug,
    )

    # ── Interfaces (Per-physical-device model: attributed per-member for stacks) ───────────────
    _bootstrap_interfaces(yaml_devices, run_id, pending_index, result, netbox_adapter=netbox_adapter)

    # ── Inventory items (transceivers / SFPs) ────────────────────────────────
    # Cisco: parsed from raw/<host>/show_inventory.txt via the existing
    #   _parse_inventory_transceivers() helper in model_builder.
    # Fortinet: parsed from facts/<host>/fortigate_interface_transceivers.json.
    # Per-physical-device model: SFPs attributed per-member via _attribute_interface_to_position.
    _bootstrap_inventory_items(yaml_devices, run_id, pending_index, result, netbox_adapter=netbox_adapter)

    # ── IPAM + cables (s14, ADR-0016) — sourced from the run's MODEL ─────────
    # VLANs, interface IPs and links are model-layer products (link_builder);
    # re-deriving them from raw facts would duplicate the model's job.
    model = _load_model_for_bootstrap(run_id, result)
    if model is not None:
        _bootstrap_ipam(yaml_devices, model, run_id, pending_index, result,
                        netbox_adapter=netbox_adapter)
        _bootstrap_cables(yaml_devices, model, run_id, pending_index, result,
                          netbox_adapter=netbox_adapter)

    # The actionable state: how many candidates now await approval (the gap
    # between the network and NetBox). Counted from Neo4j so it reflects
    # candidates staged before this run too, not just this run's `new`.
    try:
        from netcopilot.declared_state.staging import list_pending
        result.pending_total = len(list_pending())
    except Exception as exc:  # Neo4j hiccup shouldn't fail a completed bootstrap
        log.warning("Could not count pending candidates for the summary: %s", exc)

    log.info(
        "Bootstrap done. new=%s skipped=%s pending_total=%d warnings=%d",
        result.new, result.skipped, result.pending_total, len(result.warnings),
    )
    return result


# ── Per-object-type bootstrappers ────────────────────────────────────────────


def _bootstrap_sites(yaml_devices, netbox_sites, pending_index, result):
    seen_slugs: set[str] = set()
    for dev in yaml_devices:
        site = dev.get("site")
        if not site:
            continue
        slug = str(site)
        if slug in seen_slugs:
            continue
        seen_slugs.add(slug)

        # NetBox slug convention: lowercase. Display name preserves YAML case.
        site_slug = slug.lower()
        if site_slug in netbox_sites or _already_pending(pending_index, "site", site_slug):
            result.skipped["site"] = result.skipped.get("site", 0) + 1
            continue

        stage_candidate(
            source="bootstrap",
            object_type="site",
            payload={"slug": site_slug, "name": slug},
            reason=f"derived from YAML inventory device.site={slug!r}",
        )
        result.new["site"] = result.new.get("site", 0) + 1


def _bootstrap_manufacturers(yaml_devices, pending_index, result, *, netbox_manufacturers=frozenset()):
    seen: set[str] = set()
    for dev in yaml_devices:
        os_name = normalize_os(dev.get("os") or "")
        manufacturer = _OS_TO_MANUFACTURER.get(os_name)
        if not manufacturer:
            result.warnings.append(
                f"device {dev.get('name')!r}: os={os_name!r} has no manufacturer mapping"
            )
            continue
        if manufacturer in seen:
            continue
        seen.add(manufacturer)

        if manufacturer in netbox_manufacturers or _already_pending(pending_index, "manufacturer", manufacturer):
            result.skipped["manufacturer"] = result.skipped.get("manufacturer", 0) + 1
            continue

        slug = manufacturer.lower()
        stage_candidate(
            source="bootstrap",
            object_type="manufacturer",
            payload={"slug": slug, "name": manufacturer},
            reason=f"derived from YAML inventory device.os field",
        )
        result.new["manufacturer"] = result.new.get("manufacturer", 0) + 1


def _bootstrap_platforms(yaml_devices, pending_index, result, *, netbox_platforms=frozenset()):
    seen: set[str] = set()
    for dev in yaml_devices:
        os_name = normalize_os(dev.get("os") or "")
        platform = OS_TO_PLATFORM.get(os_name)
        if not platform:
            continue
        slug, display_name = platform
        if slug in seen:
            continue
        seen.add(slug)

        if slug in netbox_platforms or _already_pending(pending_index, "platform", slug):
            result.skipped["platform"] = result.skipped.get("platform", 0) + 1
            continue

        manufacturer_slug = (_OS_TO_MANUFACTURER.get(os_name) or "").lower() or None
        platform_payload: dict[str, Any] = {
            "slug": slug,
            "name": display_name,
        }
        if manufacturer_slug:
            platform_payload["manufacturer"] = {"slug": manufacturer_slug}
        stage_candidate(
            source="bootstrap",
            object_type="platform",
            payload=platform_payload,
            reason=f"derived from YAML inventory device.os={os_name!r}",
        )
        result.new["platform"] = result.new.get("platform", 0) + 1


def _bootstrap_clusters(yaml_devices, netbox_clusters, pending_index, result):
    """Stage one :NetBoxPendingWrite per unique HA cluster (ADR-0013).

    HA pairs (os=fortios + YAML cluster.size > 1) get a dcim.Cluster object
    in NetBox. Catalyst stacks (os=iosxe/iosxr + YAML cluster.size > 1)
    intentionally do NOT — their cluster membership is preserved on the
    Device candidate as ``stack_cluster`` + ``stack_size`` custom_fields.
    """
    seen_names: set[str] = set()
    for dev in yaml_devices:
        cluster = dev.get("cluster")
        if not isinstance(cluster, dict):
            continue
        os_name = normalize_os(dev.get("os") or "")
        if os_name not in _HA_PAIR_OS:
            continue
        name = cluster.get("name")
        if not name:
            continue
        if name in seen_names:
            continue
        seen_names.add(name)

        if name in netbox_clusters or _already_pending(pending_index, "cluster", name):
            result.skipped["cluster"] = result.skipped.get("cluster", 0) + 1
            continue

        # NetBox dcim.Cluster requires a ClusterType FK. We use the
        # idempotently-provisioned "ha-pair" slug from NetBoxAdapter.
        # Site is optional but useful for filtering in the NetBox UI.
        # NetBox 4.6 requires FKs as dict, not bare strings.
        yaml_site = dev.get("site")
        site_slug = yaml_site.lower() if isinstance(yaml_site, str) else None
        payload: dict[str, Any] = {
            "name": name,
            "type": {"slug": "ha-pair"},
            "status": "active",
            "description": (
                f"FortiGate HA pair (size {cluster.get('size', 'unknown')}). "
                f"Auto-staged from YAML inventory."
            ),
        }
        if site_slug:
            payload["site"] = {"slug": site_slug}
        stage_candidate(
            source="bootstrap",
            object_type="cluster",
            payload=payload,
            reason=f"derived from YAML inventory device.cluster={name!r}",
        )
        result.new["cluster"] = result.new.get("cluster", 0) + 1


def _bootstrap_virtual_chassis(yaml_devices, run_id, pending_index, result, *, netbox_vcs=frozenset()):
    """Stage one :NetBoxPendingWrite per Cisco stack (ADR-0013 per-physical-device model).

    A Cisco stack is a YAML inventory entry with os=iosxe/iosxr AND
    ``device_facts.json[cluster_members]`` length > 1. Each such entry
    becomes one dcim.VirtualChassis whose ``name`` matches the inventory
    entry name (operator-friendly). Member Devices reference it via the
    ``virtual_chassis`` FK in :func:`_bootstrap_devices`.

    ``master`` is intentionally not set on the VirtualChassis payload —
    NetBox accepts a null master and the operator can promote one via the
    UI. Documented limitation (ADR-0013).
    """
    seen: set[str] = set()
    for dev in yaml_devices:
        name = dev.get("name")
        if not name:
            continue
        os_name = normalize_os(dev.get("os") or "")
        members = _load_cluster_members(name, run_id)
        if not _is_cisco_stack(os_name, members):
            continue
        if name in seen:
            continue
        seen.add(name)

        if name in netbox_vcs or _already_pending(pending_index, "virtual_chassis", name):
            result.skipped["virtual_chassis"] = result.skipped.get("virtual_chassis", 0) + 1
            continue

        master_pos = _master_position(members)
        payload: dict[str, Any] = {
            "name": name,
            "description": (
                f"Cisco stack with {len(members)} members "
                f"(active member at position {master_pos}). "
                f"Auto-staged from device_facts.json[cluster_members]."
            ),
        }
        yaml_site = dev.get("site")
        neo4j_site = yaml_site.lower() if isinstance(yaml_site, str) else None
        stage_candidate(
            source="bootstrap",
            object_type="virtual_chassis",
            payload=payload,
            reason=f"derived from device_facts.json[cluster_members] for {name!r}",
            affects_device_name=name,
            affects_device_site=neo4j_site,
        )
        result.new["virtual_chassis"] = result.new.get("virtual_chassis", 0) + 1


def _bootstrap_devices(
    yaml_devices, netbox_devices, pending_index, result,
    *, run_id=None, device_type_id_by_slug=None,
):
    """Stage device candidates with NetBox 4.6-correct payload shape.

    Per-physical-device model: Catalyst stacks and FortiGate HA pairs expand into N candidates
    (one per physical chassis member), each named ``<inventory_name>-<position>``
    (1-indexed). Stack members carry ``virtual_chassis`` + ``vc_position`` FKs;
    HA members carry the ``cluster`` FK. Standalone devices remain 1:1
    with the inventory entry.
    """
    device_type_id_by_slug = device_type_id_by_slug or {}
    for dev in yaml_devices:
        name = dev.get("name")
        if not name:
            continue

        os_name = normalize_os(dev.get("os") or "")
        members = _load_cluster_members(name, run_id) if run_id else []
        is_stack = _is_cisco_stack(os_name, members)
        is_ha = _is_fortigate_ha(os_name, members)

        # Per-inventory-entry context shared across member candidates
        platform_slug = OS_TO_PLATFORM.get(os_name, (None, None))[0]
        role_value = dev.get("role")
        role_slug = role_value.replace("_", "-").lower() if isinstance(role_value, str) else None
        yaml_site = dev.get("site")
        site_slug = yaml_site.lower() if isinstance(yaml_site, str) else None
        neo4j_site = site_slug  # graph/loader normalization is the same lowercase form
        cluster = dev.get("cluster") if isinstance(dev.get("cluster"), dict) else None
        cluster_name = cluster.get("name") if cluster else None

        # Fallback chassis (when a member has no own platform field)
        info_chassis = None
        if run_id:
            facts_file = _runs_dir() / run_id / "facts" / name / "device_facts.json"
            if facts_file.is_file():
                try:
                    _d = json.loads(facts_file.read_text(encoding="utf-8"))
                    info_chassis = (_d.get("device_info") or {}).get("platform")
                except json.JSONDecodeError:
                    info_chassis = None

        # ── Branch: standalone (no expansion) ────────────────────────────
        if not is_stack and not is_ha:
            if name in netbox_devices or _already_pending(pending_index, "device", name):
                result.skipped["device"] = result.skipped.get("device", 0) + 1
                continue
            payload: dict[str, Any] = {"name": name, "status": "active"}
            if site_slug:
                payload["site"] = {"slug": site_slug}
            if role_slug:
                payload["role"] = {"slug": role_slug}
            if platform_slug:
                payload["platform"] = {"slug": platform_slug}
            chassis_slug = _chassis_slug(info_chassis)
            if chassis_slug and chassis_slug in device_type_id_by_slug:
                payload["device_type"] = device_type_id_by_slug[chassis_slug]
            stage_candidate(
                source="bootstrap",
                object_type="device",
                payload=payload,
                reason=f"derived from YAML inventory entry {name!r}",
                affects_device_name=name,
                affects_device_site=neo4j_site,
            )
            result.new["device"] = result.new.get("device", 0) + 1
            continue

        # ── Branch: stack (Cisco) OR HA (FortiGate) — per-member expansion
        master_pos = _master_position(members)
        for idx, member in enumerate(members):
            position = idx + 1  # 1-indexed
            member_name = _member_device_name(name, position)
            if member_name in netbox_devices or _already_pending(pending_index, "device", member_name):
                result.skipped["device"] = result.skipped.get("device", 0) + 1
                continue

            role_label = (member.get("role") or "").lower()
            is_master_member = (position == master_pos)
            member_chassis = member.get("platform") or info_chassis
            member_chassis_slug = _chassis_slug(member_chassis)

            payload = {
                "name": member_name,
                "status": "active",
            }
            if site_slug:
                payload["site"] = {"slug": site_slug}
            if role_slug:
                payload["role"] = {"slug": role_slug}
            if platform_slug:
                payload["platform"] = {"slug": platform_slug}
            if member_chassis_slug and member_chassis_slug in device_type_id_by_slug:
                payload["device_type"] = device_type_id_by_slug[member_chassis_slug]
            if member.get("serial_number"):
                payload["serial"] = str(member["serial_number"])

            if is_stack:
                # Cisco stack → virtual_chassis FK + vc_position (1-indexed slot)
                payload["virtual_chassis"] = {"name": name}
                payload["vc_position"] = position
                if member.get("priority") is not None:
                    payload["vc_priority"] = int(member["priority"])
                payload["description"] = (
                    f"Stack member {position} of {name} (role: {role_label or 'unknown'}"
                    f"{', master' if is_master_member else ''})"
                )
                # custom_fields retained as an operator-friendly label (operator-friendly label).
                custom_fields = payload.setdefault("custom_fields", {})
                custom_fields["stack_cluster"] = name
                custom_fields["stack_size"] = len(members)
            else:
                # FortiGate HA → cluster FK; no virtual_chassis.
                if cluster_name:
                    payload["cluster"] = {"name": cluster_name}
                payload["description"] = (
                    f"HA member {position} of {name} (role: {role_label or 'unknown'}"
                    f"{', master' if is_master_member else ''})"
                )

            stage_candidate(
                source="bootstrap",
                object_type="device",
                payload=payload,
                reason=(
                    f"derived from device_facts.json[cluster_members][{idx}] "
                    f"for inventory entry {name!r}"
                ),
                affects_device_name=name,  # Neo4j :Device remains 1:1 1:1 with the inventory entry
                affects_device_site=neo4j_site,
            )
            result.new["device"] = result.new.get("device", 0) + 1


_INTERFACE_NAME_KEY_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9/.-]*$")


def _bootstrap_interfaces(yaml_devices, run_id, pending_index, result, *, netbox_adapter=None):
    facts_dir = _runs_dir() / run_id / "facts"
    if not facts_dir.is_dir():
        result.warnings.append(
            f"run_id={run_id!r}: facts dir not found at {facts_dir}; skipping all interface candidates"
        )
        return

    _nb_iface_cache: dict[str, set[str]] = {}

    for dev in yaml_devices:
        name = dev.get("name")
        if not name:
            continue

        os_name = normalize_os(dev.get("os") or "")

        trusted_names = False
        iface_file = facts_dir / name / "genie_interface.json"
        if iface_file.is_file():
            try:
                data = json.loads(iface_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                result.warnings.append(f"{name}: genie_interface.json malformed: {exc}")
                continue
        elif os_name == "fortios":
            # s14: FortiGate interfaces come from the REST facts — before this
            # the firewall stayed undocumented (no interfaces → no IPs → no
            # cables terminating on it).
            data = _fortigate_iface_entries(facts_dir / name, result, name)
            if data is None:
                continue
            trusted_names = True  # structured REST rows, not genie dict keys
        else:
            result.warnings.append(
                f"{name}: genie_interface.json missing — no interface candidates for this device"
            )
            continue

        if not isinstance(data, dict) or not data:
            result.warnings.append(f"{name}: interface facts empty for this device")
            continue
        members = _load_cluster_members(name, run_id)
        is_stack = _is_cisco_stack(os_name, members)
        is_ha = _is_fortigate_ha(os_name, members)

        for iface_name, iface_data in data.items():
            if not trusted_names and not _INTERFACE_NAME_KEY_PATTERN.match(iface_name):
                # Skip degenerate genie keys (top-level metadata, error rows).
                # REST-sourced FortiGate rows are structured and keep names
                # the pattern would reject (digit-named VLAN sub-interfaces,
                # underscore tunnels).
                continue

            # Per-physical-device model: resolve the target Device per attribution rule
            if is_stack:
                position = _attribute_interface_to_position(iface_name, members)
                target_device = _member_device_name(name, position)
            elif is_ha:
                # FortiGate HA: all interfaces on the master member
                target_device = _member_device_name(name, _master_position(members))
            else:
                target_device = name

            # Dedup key: (device, interface_name) — interfaces are scoped per-device in NetBox
            dedup_name = f"{target_device}::{iface_name}"
            if target_device not in _nb_iface_cache and netbox_adapter is not None:
                _nb_iface_cache[target_device] = {
                    i["name"] for i in netbox_adapter.get_interfaces(target_device)
                }
            if iface_name in _nb_iface_cache.get(target_device, ()):  # s13: NetBox-side dedup
                result.skipped["interface"] = result.skipped.get("interface", 0) + 1
                continue
            if _already_pending(pending_index, "interface", dedup_name):
                result.skipped["interface"] = result.skipped.get("interface", 0) + 1
                continue

            payload = {
                "device": {"name": target_device},  # NetBox 4.6: FK as dict, not bare string
                "name": iface_name,
                "type": (iface_data.get("type") if iface_data.get("_type_is_netbox")
                         else _normalise_iface_type(iface_data.get("type"))),
                "enabled": bool(iface_data.get("enabled", True)),
                # NetBox forbids null description; coerce None to "".
                "description": iface_data.get("description") or "",
                "mtu": iface_data.get("mtu"),
                "mac_address": iface_data.get("mac_address") or iface_data.get("phys_address"),
                "dedup_key": dedup_name,  # echoed back for the dedup index
            }
            yaml_site = dev.get("site")
            neo4j_site = yaml_site.lower() if isinstance(yaml_site, str) else None
            stage_candidate(
                source="bootstrap",
                object_type="interface",
                payload=payload,
                reason=f"{target_device}/{iface_name} from genie_interface.json",
                affects_device_name=name,  # Neo4j :Device stays 1:1 1:1 with the inventory entry
                affects_device_site=neo4j_site,
                # We don't have a Neo4j :Interface id at hand here; the
                # AFFECTS_INTERFACE edge could be derived later
                # when the operator approves and we look up the matching
                # interface node. Bootstrap ships without this edge
                # candidates; FROM_FINDING + AFFECTS_INTERFACE will land
                # for drift candidates (drift sprint).
            )
            result.new["interface"] = result.new.get("interface", 0) + 1


# ── Inventory items (transceivers) ────────────────────────────────────────────


_INV_BLOCK_RE = re.compile(
    r'NAME:\s*"([^"]+)",\s*DESCR:\s*"([^"]*)".*?PID:\s*(\S+).*?SN:\s*(\S+)',
    re.DOTALL,
)

# Real interface name prefixes (case-preserving — we want NetBox's long form).
_INTERFACE_NAME_PREFIXES = (
    "GigabitEthernet", "TenGigE", "TenGigabitEthernet",
    "TwentyFiveGigE", "TwoGigabitEthernet", "FortyGigE",
    "HundredGigE", "FourHundredGigE",
    "Ethernet", "Eth",
    "FastEthernet", "Fa",
    # Short forms (Cisco abbreviations) — NetBox keeps the full form;
    # we accept these so the parser doesn't lose data, even if interface
    # lookup later fails for them.
    "Hu", "Te", "Tw", "Fo", "Fa", "Gi",
)


def _parse_inventory_xcvrs_preserving_case(inventory_text: str) -> list[dict]:
    """Local parser for ``show inventory`` that PRESERVES the original NAME
    (NetBox's interface long-form is case-sensitive).

    Returns a list of ``{name, description, pid, serial}`` dicts — one per
    NAME block that looks like an interface-attached entry. Chassis / PSU
    / fan tray entries (Rack, 0/PM0, 0/FT0, 0/0, 0/RP0, etc.) are filtered
    out so they don't get staged as InventoryItems on a non-interface.
    """
    out: list[dict] = []
    for m in _INV_BLOCK_RE.finditer(inventory_text):
        name = m.group(1).strip()
        descr = m.group(2).strip()
        pid = m.group(3).strip()
        serial = m.group(4).strip()
        # Keep only entries whose NAME starts with a real interface prefix.
        # (Avoids chassis modules + PSUs + fans + line cards.)
        if not name.startswith(_INTERFACE_NAME_PREFIXES):
            continue
        out.append({"name": name, "description": descr, "pid": pid, "serial": serial})
    return out


def _bootstrap_inventory_items(yaml_devices, run_id, pending_index, result, *, netbox_adapter=None):
    """Stage one :NetBoxPendingWrite per detected transceiver/SFP.

    Cisco devices: read ``raw/<host>/show_inventory.txt``, parse with a
    case-preserving local parser (model_builder's helper canonicalises
    interface names which loses NetBox's required CamelCase form).

    Fortinet devices: read ``facts/<host>/fortigate_interface_transceivers.json``
    — wraps the FortiOS REST response; we walk ``results[]`` and only stage
    rows with a ``vendor_part_number`` populated.

    Each candidate's dedup_key is ``<device>::<interface>::<serial>`` so
    re-running bootstrap doesn't double-stage. The candidate payload
    carries a ``_resolve_interface_name`` hint that
    :func:`staging._write_to_netbox` translates to NetBox's
    ``component_type`` + ``component_id`` FK at write time.
    """
    raw_dir = _runs_dir() / run_id / "raw"
    facts_dir = _runs_dir() / run_id / "facts"

    _nb_item_serials: dict[str, set[str]] = {}

    for dev in yaml_devices:
        name = dev.get("name")
        if not name:
            continue
        os_name = normalize_os(dev.get("os") or "")

        # Per-physical-device model: attribute the SFP to the right physical-member Device.
        members = _load_cluster_members(name, run_id)
        is_stack = _is_cisco_stack(os_name, members)
        is_ha = _is_fortigate_ha(os_name, members)

        def _target_for(iface_name: str) -> str:
            if is_stack:
                pos = _attribute_interface_to_position(iface_name, members)
                return _member_device_name(name, pos)
            if is_ha:
                return _member_device_name(name, _master_position(members))
            return name

        if os_name in ("ios-xr", "ios-xe"):
            inv_path = raw_dir / name / "show_inventory.txt"
            if not inv_path.is_file():
                continue
            try:
                text = inv_path.read_text(encoding="utf-8", errors="replace")
                xcvrs = _parse_inventory_xcvrs_preserving_case(text)
            except Exception as exc:
                result.warnings.append(
                    f"{name}: show_inventory.txt parse failed: {exc}"
                )
                continue
            for entry in xcvrs:
                serial = entry.get("serial")
                pid = entry.get("pid")
                iface_name = entry.get("name")
                if not serial or not pid or not iface_name:
                    continue
                target = _target_for(iface_name)
                dedup = f"{target}::{iface_name}::{serial}"
                if target not in _nb_item_serials and netbox_adapter is not None:
                    _nb_item_serials[target] = {
                        i["serial"] for i in netbox_adapter.get_inventory_items(target)
                        if i.get("serial")
                    }
                if serial in _nb_item_serials.get(target, ()):  # s13: NetBox-side dedup
                    result.skipped["inventory_item"] = result.skipped.get("inventory_item", 0) + 1
                    continue
                if _already_pending(pending_index, "inventory_item", dedup):
                    result.skipped["inventory_item"] = result.skipped.get("inventory_item", 0) + 1
                    continue
                _stage_one_inventory_item(
                    device_name=target,
                    interface_name=iface_name,
                    part_id=pid,
                    serial=serial,
                    description=entry.get("description") or "",
                    manufacturer_slug="cisco",
                    dedup_key=dedup,
                    result=result,
                    affects_inventory_entry=name,
                )

        elif os_name == "fortios":
            fg_path = facts_dir / name / "fortigate_interface_transceivers.json"
            if not fg_path.is_file():
                continue
            try:
                data = json.loads(fg_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                result.warnings.append(
                    f"{name}: fortigate_interface_transceivers.json malformed: {exc}"
                )
                continue
            for r in (data.get("results") or []):
                if not isinstance(r, dict):
                    continue
                iface_name = r.get("interface")
                pid = r.get("vendor_part_number")
                serial = r.get("vendor_serial_number")
                vendor = (r.get("vendor") or "").lower()
                if not iface_name or not pid or not serial:
                    continue
                target = _target_for(iface_name)
                dedup = f"{target}::{iface_name}::{serial}"
                if target not in _nb_item_serials and netbox_adapter is not None:
                    _nb_item_serials[target] = {
                        i["serial"] for i in netbox_adapter.get_inventory_items(target)
                        if i.get("serial")
                    }
                if serial in _nb_item_serials.get(target, ()):  # s13: NetBox-side dedup
                    result.skipped["inventory_item"] = result.skipped.get("inventory_item", 0) + 1
                    continue
                if _already_pending(pending_index, "inventory_item", dedup):
                    result.skipped["inventory_item"] = result.skipped.get("inventory_item", 0) + 1
                    continue
                # FortiGate vendor strings look like "CISCO-FINISAR" / "CISCO-ACCELINK".
                # Map to existing manufacturer slugs we auto-provision (cisco / fortinet);
                # anything else falls back to fortinet.
                if "cisco" in vendor:
                    mfr_slug = "cisco"
                elif "fortinet" in vendor:
                    mfr_slug = "fortinet"
                else:
                    mfr_slug = "fortinet"
                _stage_one_inventory_item(
                    device_name=target,
                    interface_name=iface_name,
                    part_id=pid,
                    serial=serial,
                    description=r.get("type") or "",
                    manufacturer_slug=mfr_slug,
                    dedup_key=dedup,
                    result=result,
                    affects_inventory_entry=name,
                )


def _stage_one_inventory_item(
    *, device_name, interface_name, part_id, serial,
    description, manufacturer_slug, dedup_key, result,
    affects_inventory_entry=None,
):
    """Helper — single :NetBoxPendingWrite{inventory_item} candidate.

    ``device_name`` is the NetBox-side target Device (possibly a member
    suffix, per-physical-device model). ``affects_inventory_entry`` is the YAML inventory
    name used for the Neo4j AFFECTS_DEVICE edge (stays 1:1 with :Device).
    """
    item_name = f"{interface_name} transceiver"
    payload = {
        "device": {"name": device_name},
        "name": item_name,
        "part_id": part_id,
        "serial": serial,
        "description": description,
        "manufacturer": {"slug": manufacturer_slug},
        # Hints consumed by staging._write_to_netbox to resolve the parent
        # Interface FK at write time. Dropped before POST.
        "_resolve_device_name": device_name,
        "_resolve_interface_name": interface_name,
        "dedup_key": dedup_key,
    }
    stage_candidate(
        source="bootstrap",
        object_type="inventory_item",
        payload=payload,
        reason=f"{device_name}/{interface_name} transceiver from show_inventory/transceivers facts",
        affects_device_name=affects_inventory_entry or device_name,
        affects_device_site=None,
    )
    result.new["inventory_item"] = result.new.get("inventory_item", 0) + 1


# ── Helpers ──────────────────────────────────────────────────────────────────


def _provision_device_types(
    yaml_devices, run_id, netbox_adapter, result,
) -> dict[str, int]:
    """Idempotently create dcim.DeviceType per unique chassis + return slug→id map.

    NetBox 4.6 requires Device.device_type as an FK. This helper walks every
    inventory entry AND every ``cluster_members[i].platform`` (Per-physical-device model: each
    physical member can have its own chassis during hardware refresh), calls
    :meth:`NetBoxAdapter.ensure_device_type` once per unique chassis slug, and
    returns a ``{chassis_slug: netbox_device_type_id}`` map for
    :func:`_bootstrap_devices` to resolve per-member.
    """
    facts_dir = _runs_dir() / run_id / "facts"
    if not facts_dir.is_dir():
        result.warnings.append(
            f"run_id={run_id!r}: facts dir missing; device_type pre-resolution skipped"
        )
        return {}

    # Mirror NetBoxAdapter's pre-provisioned manufacturer slugs.
    os_to_mfr_slug = {"ios-xr": "cisco", "ios-xe": "cisco", "fortios": "fortinet"}

    type_id_by_slug: dict[str, int] = {}

    for dev in yaml_devices:
        name = dev.get("name")
        if not name:
            continue
        facts_file = facts_dir / name / "device_facts.json"
        if not facts_file.is_file():
            result.warnings.append(
                f"{name}: device_facts.json missing — device_type not pre-resolved"
            )
            continue

        try:
            data = json.loads(facts_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            result.warnings.append(f"{name}: device_facts.json malformed")
            continue

        info = data.get("device_info") or {}
        members = data.get("cluster_members") or []

        # Collect every distinct chassis model in scope for this inventory entry:
        # - the inventory entry's declared chassis (device_info.platform)
        # - each cluster member's chassis (members[i].platform)
        candidates: list[str] = []
        if info.get("platform"):
            candidates.append(str(info["platform"]).strip())
        for m in members:
            if m.get("platform"):
                candidates.append(str(m["platform"]).strip())
        if not candidates:
            result.warnings.append(f"{name}: no chassis model found in facts")
            continue

        os_name = normalize_os(dev.get("os") or "")
        mfr_slug = os_to_mfr_slug.get(os_name)
        if not mfr_slug:
            result.warnings.append(
                f"{name}: os={os_name!r} → no manufacturer slug; device_type skipped"
            )
            continue

        for chassis in candidates:
            slug = _chassis_slug(chassis)
            if not slug or slug in type_id_by_slug:
                continue
            try:
                type_id = netbox_adapter.ensure_device_type(
                    slug=slug, model=chassis, manufacturer_slug=mfr_slug,
                )
            except Exception as exc:
                result.warnings.append(
                    f"{name}: ensure_device_type({slug!r}, {chassis!r}) failed: {exc}"
                )
                continue
            type_id_by_slug[slug] = type_id

    return type_id_by_slug


_FORTIGATE_IFACE_TYPE = {"physical": "other", "aggregate": "lag",
                         "tunnel": "virtual", "vlan": "virtual"}


def _fortigate_iface_entries(dev_facts_dir: Path, result, name: str) -> dict | None:
    """FortiGate interfaces as genie-shaped entries (s14).

    Reads ``fortigate_system_interface.json`` (REST) and maps each row to
    the field shape the shared staging loop consumes. Returns None (with a
    warning) when the file is absent/malformed.
    """
    fg_file = dev_facts_dir / "fortigate_system_interface.json"
    if not fg_file.is_file():
        result.warnings.append(
            f"{name}: fortigate_system_interface.json missing — no interface candidates"
        )
        return None
    try:
        raw = json.loads(fg_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        result.warnings.append(f"{name}: fortigate_system_interface.json malformed: {exc}")
        return None

    entries: dict[str, dict] = {}
    for row in raw.get("results") or []:
        if not isinstance(row, dict) or not row.get("name"):
            continue
        mac = row.get("macaddr") or None
        if mac in ("00:00:00:00:00:00",):
            mac = None
        entries[row["name"]] = {
            "enabled": (row.get("status") or "").lower() == "up",
            "type": _FORTIGATE_IFACE_TYPE.get((row.get("type") or "").lower(), "other"),
            "_type_is_netbox": True,  # already a NetBox slug — skip genie mapping
            "description": row.get("description") or row.get("alias") or "",
            "mtu": row.get("mtu"),
            "mac_address": mac,
        }
    return entries


def _normalise_iface_type(genie_type: str | None) -> str:
    """Best-effort NetBox interface type mapping."""
    if not genie_type:
        return "other"
    t = genie_type.lower()
    if "etherchannel" in t or "port-channel" in t:
        return "lag"
    if "loopback" in t:
        return "virtual"
    if "vlan" in t:
        return "virtual"
    if "100" in t and ("gig" in t or "gbe" in t or "g/s" in t):
        return "100gbase-x-qsfp28"
    if "10" in t and "gig" in t:
        return "10gbase-x-sfpp"
    if "gigabit" in t or "1000" in t:
        return "1000base-t"
    return "other"


_DEDUP_KEY_FIELD = {
    # object_type → payload field whose value is the dedup key for that type
    "site": "slug",
    "manufacturer": "name",
    "platform": "slug",
    "device": "name",
    "interface": "dedup_key",
    "vlan": "dedup_key",     # "<site>::<vid>" (s14)
    "ipaddress": "address",  # CIDR string (s14)
    "vrf": "name",           # (s14)
    "prefix": "dedup_key",   # "<vrf-or-global>::<cidr>" (s14)
    "cable": "dedup_key",    # "<a>--<b>" termination pair (s14)
    "cluster": "name",    # dcim.Cluster's natural key is its name
    "virtual_chassis": "name",  # dcim.VirtualChassis natural key
    "inventory_item": "dedup_key",  # <device>::<iface>::<serial>
}


# ── Per-physical-device expansion helpers ────────────────────────────────────


_CISCO_STACK_OS = {"ios-xe", "ios-xr"}

# Match "<word>NN/" — first numeric token after the leading interface name family.
# Used for Catalyst-stack interface attribution: GigabitEthernet1/0/1 → slot 1.
_INTERFACE_SLOT_RE = re.compile(r"^[A-Za-z]+(\d+)/")


def _load_cluster_members(device_name: str, run_id: str) -> list[dict]:
    """Return ``device_facts.json[cluster_members]`` sorted by ``member_id``.

    Empty list = standalone device, or facts unavailable / malformed.
    """
    facts_file = _runs_dir() / run_id / "facts" / device_name / "device_facts.json"
    if not facts_file.is_file():
        return []
    try:
        data = json.loads(facts_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    members = data.get("cluster_members")
    if not isinstance(members, list) or not members:
        return []
    return sorted(members, key=lambda m: m.get("member_id") if m.get("member_id") is not None else 0)


def _is_cisco_stack(os_name: str, members: list[dict]) -> bool:
    return os_name in _CISCO_STACK_OS and len(members) > 1


def _is_fortigate_ha(os_name: str, members: list[dict]) -> bool:
    return os_name in _HA_PAIR_OS and len(members) > 1


def _master_position(members: list[dict]) -> int:
    """1-indexed slot of the active/master member; defensive fallback to 1.

    Heuristics in order:
      1. Member whose ``role`` is in ``{active, master}``.
      2. Member with the highest ``priority`` (if any are set).
      3. Position 1 (first sorted member).
    """
    primary_roles = {"active", "master"}
    for i, m in enumerate(members):
        if (m.get("role") or "").lower() in primary_roles:
            return i + 1
    prio = [(i, m.get("priority")) for i, m in enumerate(members) if m.get("priority") is not None]
    if prio:
        prio.sort(key=lambda x: x[1], reverse=True)
        return prio[0][0] + 1
    return 1


def _attribute_interface_to_position(iface_name: str, members: list[dict]) -> int:
    """Return the 1-indexed member position that owns ``iface_name``.

    For Cisco stacks: parse the first numeric token of the interface name
    (Cisco's slot = member_id). For logical interfaces (SVI / Loopback /
    Port-channel) or parse failure, route to the master (Decision §4).
    For HA pairs and standalone devices, attribution is decided by the
    caller; this helper assumes Cisco-stack semantics.
    """
    m = _INTERFACE_SLOT_RE.match(iface_name)
    if not m:
        return _master_position(members)
    slot = int(m.group(1))
    for i, member in enumerate(members):
        if member.get("member_id") == slot:
            return i + 1
    return _master_position(members)


def _member_device_name(inventory_name: str, position_1indexed: int) -> str:
    """Member naming convention: ``<inventory_name>-<position>`` (1-indexed)."""
    return f"{inventory_name}-{position_1indexed}"


def _chassis_slug(model: str | None) -> str | None:
    if not model:
        return None
    return str(model).strip().lower().replace(" ", "-").replace("/", "-").replace("_", "-")


def _dedup_key_from_payload(object_type: str, payload: dict[str, Any]) -> str | None:
    """Return the canonical dedup key for a candidate's payload, or None."""
    field = _DEDUP_KEY_FIELD.get(object_type)
    if field is None:
        return None
    value = payload.get(field)
    return str(value) if value is not None else None


def _index_existing_pending() -> dict[tuple[str, str], str]:
    """Return ``{(object_type, dedup_key): candidate_id}`` for existing pending writes.

    Used for idempotency dedup. The dedup key per object_type is defined by
    :data:`_DEDUP_KEY_FIELD` so the storage and lookup paths agree on which
    payload field uniquely identifies a candidate.
    """
    from netcopilot.graph.client import get_driver

    try:
        with get_driver().session() as session:
            result = session.run(
                "MATCH (p:NetBoxPendingWrite) "
                "RETURN p.id AS id, p.netbox_object_type AS object_type, p.payload_json AS payload_json"
            )
            index: dict[tuple[str, str], str] = {}
            for record in result:
                try:
                    payload = json.loads(record["payload_json"] or "{}")
                except (json.JSONDecodeError, TypeError):
                    continue
                key_name = _dedup_key_from_payload(record["object_type"], payload)
                if key_name is None:
                    continue
                index[(record["object_type"], key_name)] = record["id"]
            return index
    except Exception as exc:
        log.warning("Failed to read existing :NetBoxPendingWrite for dedup: %s", exc)
        return {}


# ── IPAM + cables (s14, ADR-0016) ────────────────────────────────────────────


def _load_model_for_bootstrap(run_id: str, result) -> dict | None:
    """Read the run's network_model.json, or warn honestly and skip IPAM."""
    model_path = _runs_dir() / run_id / "model" / "network_model.json"
    if not model_path.is_file():
        result.warnings.append(
            f"model/network_model.json missing for run {run_id!r} — "
            "IPAM + cable candidates skipped (run the full pipeline first)."
        )
        return None
    try:
        return json.loads(model_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        result.warnings.append(f"network_model.json malformed: {exc} — IPAM + cables skipped.")
        return None


def _full_iface_names(yaml_devices, run_id: str) -> dict[str, dict[str, str]]:
    """Per inventory device: canonical name → genie FULL interface name.

    The model uses short names ("Gi1/0/1"); NetBox interfaces were staged
    with the genie full names ("GigabitEthernet1/0/1"). The genie file is
    the shared source, so IP/cable hints resolve against exactly what
    bootstrap staged.
    """
    from netcopilot.model.interface_normalizer import canonicalize

    facts_dir = _runs_dir() / run_id / "facts"
    out: dict[str, dict[str, str]] = {}
    for dev in yaml_devices:
        name = dev.get("name")
        if not name:
            continue
        iface_file = facts_dir / name / "genie_interface.json"
        data: dict | None = None
        trusted = False
        if iface_file.is_file():
            try:
                data = json.loads(iface_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                data = None
        elif normalize_os(dev.get("os") or "") == "fortios":
            fg_file = facts_dir / name / "fortigate_system_interface.json"
            if fg_file.is_file():
                try:
                    raw = json.loads(fg_file.read_text(encoding="utf-8"))
                    data = {r["name"]: r for r in raw.get("results") or []
                            if isinstance(r, dict) and r.get("name")}
                    trusted = True
                except json.JSONDecodeError:
                    data = None
        if isinstance(data, dict):
            out[name] = {
                canonicalize(k): k for k in data
                if (trusted or _INTERFACE_NAME_KEY_PATTERN.match(k)) and canonicalize(k)
            }
    return out


def _target_member_for(dev: dict, iface_full_name: str, run_id: str) -> str:
    """Per-physical-device attribution for one interface (bootstrap's rule)."""
    name = dev.get("name")
    os_name = normalize_os(dev.get("os") or "")
    members = _load_cluster_members(name, run_id)
    if _is_cisco_stack(os_name, members):
        return _member_device_name(name, _attribute_interface_to_position(iface_full_name, members))
    if _is_fortigate_ha(os_name, members):
        return _member_device_name(name, _master_position(members))
    return name


def _split_ip_len(ip, plen):
    """Some sources embed the mask in ip_address ("192.0.2.5/24", plen=None)."""
    if not ip or ip == "unassigned":
        return None, None
    if plen is None and isinstance(ip, str) and "/" in ip:
        addr, _, embedded = ip.partition("/")
        try:
            return addr, int(embedded)
        except ValueError:
            return None, None
    return ip, plen


def _bootstrap_ipam(yaml_devices, model, run_id, pending_index, result, *, netbox_adapter=None):
    """Stage VRFs, VLANs, prefixes and interface-assigned IPs from the model."""
    import ipaddress as ipaddr_mod

    from netcopilot.model.interface_normalizer import canonicalize

    yaml_by_name = {d.get("name"): d for d in yaml_devices if d.get("name")}
    model_devices = [d for d in model.get("devices", []) if d.get("hostname") in yaml_by_name]
    model_ifaces = [i for i in model.get("interfaces", []) if i.get("device_id") in yaml_by_name]
    full_names = _full_iface_names(yaml_devices, run_id)

    nb_vrfs = {v["name"] for v in netbox_adapter.get_vrfs()} if netbox_adapter else set()
    nb_vlans = {(v.get("site"), v["vid"]) for v in netbox_adapter.get_vlans()} if netbox_adapter else set()
    nb_prefixes = {(p.get("vrf"), p["prefix"]) for p in netbox_adapter.get_prefixes()} if netbox_adapter else set()
    nb_ips = {ip["address"] for ip in netbox_adapter.get_ip_addresses()} if netbox_adapter else set()
    nb_sites = {s["slug"] for s in netbox_adapter.get_sites()} if netbox_adapter else set()
    # Sites the inventory declares — the ones _bootstrap_sites stages this run.
    inventory_sites = {
        (d.get("site") or "").lower() for d in yaml_devices if d.get("site")
    }
    # Resolvable = a site FK a VLAN write can bind to at approve time: already
    # in NetBox, or staged from the inventory this run.
    resolvable_sites = nb_sites | inventory_sites

    def _site_resolvable(slug: str) -> bool:
        # A site-scoped write (VLAN) needs its site FK to exist. Without one the
        # write would 400 ("Related object not found") — skip the candidate
        # honestly rather than stage a doomed one. When NetBox is unreachable
        # (nb_sites empty) the inventory set still guards the common case.
        return slug in resolvable_sites

    # ── VRFs (name-only records; referenced by prefixes + IPs) ──────────────
    vrf_names = sorted({i.get("vrf") for i in model_ifaces if i.get("vrf")})
    for vrf in vrf_names:
        if vrf in nb_vrfs or _already_pending(pending_index, "vrf", vrf):
            result.skipped["vrf"] = result.skipped.get("vrf", 0) + 1
            continue
        stage_candidate(
            source="bootstrap", object_type="vrf",
            payload={"name": vrf},
            reason=f"VRF observed on collected interfaces (run {run_id})",
        )
        result.new["vrf"] = result.new.get("vrf", 0) + 1

    # ── VLANs per (site, vid) ────────────────────────────────────────────────
    seen_vlans: dict[tuple[str, int], str] = {}
    for d in model_devices:
        site = (d.get("site") or "").lower() or None
        for v in d.get("vlans") or []:
            vid, vname = v.get("vlan_id"), v.get("name")
            if vid is None or site is None:
                continue
            key = (site, vid)
            if key in seen_vlans:
                if vname and seen_vlans[key] != vname:
                    result.warnings.append(
                        f"VLAN {vid}@{site}: name differs across devices "
                        f"({seen_vlans[key]!r} vs {vname!r} on {d.get('hostname')}) — kept the first."
                    )
                continue
            seen_vlans[key] = vname or f"VLAN{vid}"
            dedup = f"{site}::{vid}"
            if key in nb_vlans or _already_pending(pending_index, "vlan", dedup):
                result.skipped["vlan"] = result.skipped.get("vlan", 0) + 1
                continue
            if not _site_resolvable(site):
                result.warnings.append(
                    f"VLAN {vid} ({seen_vlans[key]}) references site {site!r}, which is "
                    f"neither in NetBox nor declared by this run's inventory — skipped. A "
                    f"VLAN's site must exist first; bootstrap that site's devices "
                    f"(resolvable sites: {', '.join(sorted(resolvable_sites)) or 'none'})."
                )
                result.skipped["vlan"] = result.skipped.get("vlan", 0) + 1
                continue
            stage_candidate(
                source="bootstrap", object_type="vlan",
                payload={"vid": vid, "name": seen_vlans[key],
                         "site": {"slug": site}, "dedup_key": dedup},
                reason=f"VLAN {vid} ({seen_vlans[key]}) observed on {d.get('hostname')}",
                affects_device_name=d.get("hostname"), affects_device_site=site,
            )
            result.new["vlan"] = result.new.get("vlan", 0) + 1

    # ── Prefixes + IP addresses from interface IPs ───────────────────────────
    # Ambiguity guard: the same address claimed by multiple interfaces
    # (shared NAT'd mgmt, anycast) must not be documented as one arbitrary
    # owner's IP — warn and let the operator decide.
    claim_counts: dict[str, int] = {}
    for i in model_ifaces:
        ip, plen = _split_ip_len(i.get("ip_address"), i.get("prefix_length"))
        if ip and plen is not None:
            key = f"{ip}/{plen}"
            claim_counts[key] = claim_counts.get(key, 0) + 1
    ambiguous = {k for k, n in claim_counts.items() if n > 1}
    for cidr in sorted(ambiguous):
        claimants = sorted(
            f"{i.get('device_id')}/{i.get('name')}" for i in model_ifaces
            if _split_ip_len(i.get("ip_address"), i.get("prefix_length"))[0]
            and "/".join(map(str, _split_ip_len(i.get("ip_address"), i.get("prefix_length")))) == cidr
        )
        result.warnings.append(
            f"IP {cidr} is claimed by {len(claimants)} interfaces "
            f"({', '.join(claimants[:5])}{' …' if len(claimants) > 5 else ''}) — "
            "ambiguous, not staged."
        )

    seen_prefixes: set[tuple[str, str]] = set()
    seen_ips: set[str] = set()
    for i in model_ifaces:
        ip, plen = _split_ip_len(i.get("ip_address"), i.get("prefix_length"))
        if not ip or plen is None:
            continue
        if f"{ip}/{plen}" in ambiguous:
            continue
        dev_name = i.get("device_id")
        dev = yaml_by_name[dev_name]
        vrf = i.get("vrf") or None
        cidr = f"{ip}/{plen}"

        # Prefix (network) — /32 host addresses derive no subnet
        if int(plen) < 32:
            try:
                network = str(ipaddr_mod.ip_network(cidr, strict=False))
            except ValueError:
                result.warnings.append(f"{dev_name}/{i.get('name')}: bad address {cidr!r} — skipped")
                continue
            pkey = (vrf, network)
            if pkey not in seen_prefixes:
                seen_prefixes.add(pkey)
                dedup = f"{vrf or 'global'}::{network}"
                if pkey in nb_prefixes or _already_pending(pending_index, "prefix", dedup):
                    result.skipped["prefix"] = result.skipped.get("prefix", 0) + 1
                else:
                    payload: dict[str, Any] = {"prefix": network, "dedup_key": dedup}
                    if vrf:
                        payload["vrf"] = {"name": vrf}
                    stage_candidate(
                        source="bootstrap", object_type="prefix",
                        payload=payload,
                        reason=f"derived from {dev_name}/{i.get('name')} {cidr}"
                               + (f" (vrf {vrf})" if vrf else ""),
                    )
                    result.new["prefix"] = result.new.get("prefix", 0) + 1

        # IP address assigned to the (per-physical-member) interface
        if cidr in seen_ips:
            continue
        seen_ips.add(cidr)
        canon = canonicalize(i.get("name"))
        full = full_names.get(dev_name, {}).get(canon)
        if full is None:
            result.warnings.append(
                f"{dev_name}/{i.get('name')}: no matching documented interface — IP {cidr} not staged"
            )
            continue
        target = _target_member_for(dev, full, run_id)
        if cidr in nb_ips or _already_pending(pending_index, "ipaddress", cidr):
            result.skipped["ipaddress"] = result.skipped.get("ipaddress", 0) + 1
            continue
        ip_payload: dict[str, Any] = {
            "address": cidr,
            "_resolve_device_name": target,
            "_resolve_interface_name": full,
        }
        if vrf:
            ip_payload["vrf"] = {"name": vrf}
        stage_candidate(
            source="bootstrap", object_type="ipaddress",
            payload=ip_payload,
            reason=f"{target}/{full} {cidr}" + (f" (vrf {vrf})" if vrf else ""),
            affects_device_name=dev_name,
            affects_device_site=(dev.get("site") or "").lower() or None,
        )
        result.new["ipaddress"] = result.new.get("ipaddress", 0) + 1


# Link confidences that count as physical-cable evidence. Medium/low
# (ARP/subnet inference) prove L3 adjacency, not a cable.
_CABLE_CONFIDENCES = {"high", "very_high"}


def _end_cable_media(sfp_pid: str | None, media_type: str | None) -> str | None:
    """NetBox cable type implied by one end's transceiver PID / media type."""
    pid = (sfp_pid or "").upper()
    if pid:
        if "AOC" in pid:
            return "aoc"
        if "DAC" in pid or re.search(r"CU[0-9]M", pid):
            return "dac-passive"
        if re.search(r"(^|[^A-Z])(SR|CSR|SX)", pid):
            return "mmf"
        if re.search(r"(^|[^A-Z])(LR|ER|ZR|LH|LX)", pid):
            return "smf"
        if "BASE-T" in pid or pid.startswith("GLC-T"):
            return "cat6"
        # Unknown PID → fall through to the media_type hint
    media = (media_type or "").lower()
    if media.startswith("copper"):
        return "cat6"
    if media == "fiber-aoc":
        return "aoc"
    if media in ("fiber-sr", "fiber-mm"):
        return "mmf"
    if media == "fiber-lr":
        return "smf"
    return None  # generic "fiber"/absent → don't guess


def _cable_type_for(a_media: str | None, b_media: str | None) -> str | None:
    """Combine both ends' implied media: agree → type; one known → it;
    conflict → None (a mismatched pair is a finding, not documentation)."""
    if a_media and b_media:
        return a_media if a_media == b_media else None
    return a_media or b_media


def _fortigate_hbdev_ports(dev_facts_dir: Path) -> list[str]:
    """Heartbeat interface names from the HA config (hbdev '"ha" 50 "port8" 0')."""
    ha_file = dev_facts_dir / "fortigate_system_ha.json"
    if not ha_file.is_file():
        return []
    try:
        raw = json.loads(ha_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    r = raw.get("results", raw)
    if isinstance(r, list):
        r = r[0] if r else {}
    if not isinstance(r, dict):
        return []
    return re.findall(r'"([^"]+)"', r.get("hbdev") or "")


def _cable_dedup_key(a: tuple[str, str], b: tuple[str, str]) -> str:
    ends = sorted([f"{a[0]}:{a[1]}", f"{b[0]}:{b[1]}"])
    return f"{ends[0]}--{ends[1]}"


def _lag_interfaces(yaml_devices, run_id: str) -> set[tuple[str, str]]:
    """(target_device, full_name) of every aggregate/port-channel interface."""
    facts_dir = _runs_dir() / run_id / "facts"
    out: set[tuple[str, str]] = set()
    for dev in yaml_devices:
        name = dev.get("name")
        if not name:
            continue
        os_name = normalize_os(dev.get("os") or "")
        genie_file = facts_dir / name / "genie_interface.json"
        if genie_file.is_file():
            try:
                data = json.loads(genie_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            for iface_name, iface_data in (data or {}).items():
                if not isinstance(iface_data, dict):
                    continue
                gtype = (iface_data.get("type") or "").lower()
                if "etherchannel" in gtype or "port-channel" in gtype:
                    out.add((_target_member_for(dev, iface_name, run_id), iface_name))
        elif os_name == "fortios":
            fg_file = facts_dir / name / "fortigate_system_interface.json"
            if not fg_file.is_file():
                continue
            try:
                raw = json.loads(fg_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            for row in raw.get("results") or []:
                if isinstance(row, dict) and (row.get("type") or "").lower() == "aggregate":
                    out.add((_target_member_for(dev, row["name"], run_id), row["name"]))
    return out


def _bootstrap_cables(yaml_devices, model, run_id, pending_index, result, *, netbox_adapter=None):
    """Stage one dcim.Cable per high-confidence physical link."""
    from netcopilot.model.interface_normalizer import canonicalize

    yaml_by_name = {d.get("name"): d for d in yaml_devices if d.get("name")}
    full_names = _full_iface_names(yaml_devices, run_id)

    # An interface that already terminates a cable in NetBox is settled —
    # NetBox forbids double-termination, and the operator may have corrected
    # the cable by hand.
    nb_end_cable: dict[tuple[str, str], int] = {}
    if netbox_adapter is not None:
        for dev_name in yaml_by_name:
            members = _load_cluster_members(dev_name, run_id)
            os_name = normalize_os(yaml_by_name[dev_name].get("os") or "")
            targets = ([_member_device_name(dev_name, i + 1) for i in range(len(members))]
                       if members and (_is_cisco_stack(os_name, members) or _is_fortigate_ha(os_name, members))
                       else [dev_name])
            for t in targets:
                for iface in netbox_adapter.get_interfaces(t):
                    if iface.get("cable") is not None:
                        nb_end_cable[(t, iface["name"])] = iface["cable"]

    _STACK_PORT = re.compile(r"^stack_(\d+)/(\d+)$")
    pseudo_stack_ends: set[tuple[str, str, str]] = set()  # (target, iface, inventory_name)

    def _resolve_end(dev_id: str, short_name: str):
        dev = yaml_by_name.get(dev_id)
        if dev is None:
            return None
        # StackWise rear connectors: real physical ports on each member
        # chassis, absent from the interface facts. Modeled as
        # "StackPort<n>" interfaces on the member device (staged below).
        m = _STACK_PORT.match(short_name)
        if m:
            member_pos, port = int(m.group(1)), int(m.group(2))
            target = _member_device_name(dev_id, member_pos)
            iface = f"StackPort{port}"
            pseudo_stack_ends.add((target, iface, dev_id))
            return (target, iface)
        full = full_names.get(dev_id, {}).get(canonicalize(short_name))
        if full is None:
            return None
        return (_target_member_for(dev, full, run_id), full)

    lag_ends = _lag_interfaces(yaml_devices, run_id)

    iface_media = {
        (i.get("device_id"), canonicalize(i.get("name") or "")):
            _end_cable_media(i.get("sfp_pid"), i.get("media_type"))
        for i in model.get("interfaces", [])
    }

    # NetBox enforces one cable per interface. The model can carry several
    # high-confidence links claiming the same end (FDB-derived mgmt links are
    # transitive) — keep the best-confidence claim deterministically, warn
    # the rest, instead of letting NetBox reject them at write time.
    conf_rank = {"very_high": 0, "high": 1}
    links = sorted(
        (l for l in model.get("links", []) if l.get("confidence") in _CABLE_CONFIDENCES),
        key=lambda l: (conf_rank.get(l.get("confidence"), 9), l.get("link_id") or ""),
    )
    claimed_in_wave: dict[tuple[str, str], str] = {}  # end → dedup key

    for link in links:
        a_dev = link.get("local_device_id")
        b_dev = link.get("remote_device_id")
        a_short = (link.get("local_interface_id") or "").split(":", 1)[-1]
        b_short = (link.get("remote_interface_id") or "").split(":", 1)[-1]

        if a_short.startswith("hb_") or b_short.startswith("hb_"):
            # HA heartbeat pseudo-ends (model's hbdev links) — the dedicated
            # hbdev section below stages these cables with real port names.
            continue

        a = _resolve_end(a_dev, a_short)
        b = _resolve_end(b_dev, b_short)
        if a is None or b is None:
            result.warnings.append(
                f"link {link.get('link_id')}: endpoint not documentable "
                f"(unmanaged device or undocumented interface) — cable not staged"
            )
            continue

        # NetBox forbids cable terminations on LAG interfaces; the physical
        # cable belongs to member ports we cannot attribute from this link.
        lagged = [e for e in (a, b) if e in lag_ends]
        if lagged:
            result.warnings.append(
                f"link {link.get('link_id')}: endpoint "
                f"{', '.join(f'{d}/{i}' for d, i in lagged)} is a LAG — "
                "physical member cabling not derivable, cable not staged"
            )
            continue

        dedup = _cable_dedup_key(a, b)

        # Same cable already documented in NetBox (both ends on one cable id)
        # or already pending → clean idempotent skip.
        same_nb_cable = (nb_end_cable.get(a) is not None
                         and nb_end_cable.get(a) == nb_end_cable.get(b))
        if same_nb_cable or _already_pending(pending_index, "cable", dedup):
            claimed_in_wave[a] = claimed_in_wave[b] = dedup
            result.skipped["cable"] = result.skipped.get("cable", 0) + 1
            continue

        # An end held by a DIFFERENT cable (NetBox or earlier in this wave):
        # this link is likely indirect (transitive FDB) — warn, don't stage.
        conflict = [e for e in (a, b)
                    if (e in nb_end_cable)
                    or (claimed_in_wave.get(e) not in (None, dedup))]
        if conflict:
            result.warnings.append(
                f"link {link.get('link_id')}: interface "
                f"{', '.join(f'{d}/{i}' for d, i in conflict)} already claimed by a "
                "different cable — this link is likely indirect, not staged"
            )
            continue

        claimed_in_wave[a] = claimed_in_wave[b] = dedup
        cable_type = _cable_type_for(
            iface_media.get((a_dev, canonicalize(a_short))),
            iface_media.get((b_dev, canonicalize(b_short))),
        )
        payload = {
            "status": "connected",
            "dedup_key": dedup,
            "_resolve_a_device": a[0], "_resolve_a_interface": a[1],
            "_resolve_b_device": b[0], "_resolve_b_interface": b[1],
        }
        if cable_type:
            payload["type"] = cable_type
        stage_candidate(
            source="bootstrap", object_type="cable",
            payload=payload,
            reason=(f"physical link {link.get('link_id')} "
                    f"(discovery: {link.get('discovery_method')}, "
                    f"confidence: {link.get('confidence')})"),
            affects_device_name=a_dev,
            affects_device_site=(yaml_by_name[a_dev].get("site") or "").lower() or None,
        )
        result.new["cable"] = result.new.get("cable", 0) + 1

    # Interfaces for the StackWise rear connectors referenced by staged
    # cables — real ports on each member chassis, not in the interface facts.
    nb_iface_names: dict[str, set[str]] = {}
    for target, iface, inv_name in sorted(pseudo_stack_ends):
        dedup = f"{target}::{iface}"
        if netbox_adapter is not None and target not in nb_iface_names:
            nb_iface_names[target] = {
                i["name"] for i in netbox_adapter.get_interfaces(target)}
        if (iface in nb_iface_names.get(target, ())
                or _already_pending(pending_index, "interface", dedup)):
            result.skipped["interface"] = result.skipped.get("interface", 0) + 1
            continue
        site = (yaml_by_name.get(inv_name, {}).get("site") or "").lower() or None
        stage_candidate(
            source="bootstrap", object_type="interface",
            payload={
                "device": {"name": target},
                "name": iface,
                "type": "other",
                "enabled": True,
                "description": "StackWise stack port (rear connector)",
                "dedup_key": dedup,
            },
            reason=f"stack interconnect endpoint on {target}",
            affects_device_name=inv_name,
            affects_device_site=site,
        )
        result.new["interface"] = result.new.get("interface", 0) + 1

    # ── HA heartbeat cables (hbdev) ──────────────────────────────────────────
    # The HA config names the heartbeat interfaces; they are per-chassis
    # physical ports, so the non-master member gets its own interface records
    # (data interfaces rightly live on the master only in a-p). The cable is
    # assumed direct member-to-member — the standard a-p deployment — and the
    # candidate reason says so for the operator gate to verify.
    for inv_name, dev in yaml_by_name.items():
        os_name = normalize_os(dev.get("os") or "")
        members = _load_cluster_members(inv_name, run_id)
        if not _is_fortigate_ha(os_name, members) or len(members) < 2:
            continue
        hb_ports = _fortigate_hbdev_ports(_runs_dir() / run_id / "facts" / inv_name)
        if not hb_ports:
            continue
        site = (dev.get("site") or "").lower() or None
        master = _member_device_name(inv_name, _master_position(members))
        m_names = [_member_device_name(inv_name, i + 1) for i in range(len(members))]

        for port in hb_ports:
            for target in m_names:
                if target == master:
                    continue  # master's interfaces come from system_interface
                dedup_i = f"{target}::{port}"
                if netbox_adapter is not None and target not in nb_iface_names:
                    nb_iface_names[target] = {
                        i["name"] for i in netbox_adapter.get_interfaces(target)}
                if (port in nb_iface_names.get(target, ())
                        or _already_pending(pending_index, "interface", dedup_i)):
                    result.skipped["interface"] = result.skipped.get("interface", 0) + 1
                    continue
                stage_candidate(
                    source="bootstrap", object_type="interface",
                    payload={
                        "device": {"name": target},
                        "name": port,
                        "type": "other",
                        "enabled": True,
                        "description": "HA heartbeat port (hbdev)",
                        "dedup_key": dedup_i,
                    },
                    reason=f"HA heartbeat interface on standby member {target}",
                    affects_device_name=inv_name,
                    affects_device_site=site,
                )
                result.new["interface"] = result.new.get("interface", 0) + 1

            a, b = (m_names[0], port), (m_names[1], port)
            dedup = _cable_dedup_key(a, b)
            same_nb_cable = (nb_end_cable.get(a) is not None
                             and nb_end_cable.get(a) == nb_end_cable.get(b))
            if same_nb_cable or _already_pending(pending_index, "cable", dedup):
                claimed_in_wave[a] = claimed_in_wave[b] = dedup
                result.skipped["cable"] = result.skipped.get("cable", 0) + 1
                continue
            conflict = [e for e in (a, b)
                        if (e in nb_end_cable)
                        or (claimed_in_wave.get(e) not in (None, dedup))]
            if conflict:
                result.warnings.append(
                    f"HA heartbeat {inv_name}/{port}: interface "
                    f"{', '.join(f'{d}/{i}' for d, i in conflict)} already claimed "
                    "by a different cable — heartbeat cable not staged"
                )
                continue
            claimed_in_wave[a] = claimed_in_wave[b] = dedup
            stage_candidate(
                source="bootstrap", object_type="cable",
                payload={
                    "status": "connected",
                    "dedup_key": dedup,
                    "_resolve_a_device": a[0], "_resolve_a_interface": a[1],
                    "_resolve_b_device": b[0], "_resolve_b_interface": b[1],
                },
                reason=(f"HA heartbeat (hbdev '{port}') — assumed direct "
                        "member-to-member per standard a-p deployment; verify"),
                affects_device_name=inv_name,
                affects_device_site=site,
            )
            result.new["cable"] = result.new.get("cable", 0) + 1


def _already_pending(pending_index: dict[tuple[str, str], str], object_type: str, name: str) -> bool:
    return (object_type, name) in pending_index
