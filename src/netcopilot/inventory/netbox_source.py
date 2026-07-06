"""NetBox-backed inventory source (s15).

Answers the same question the YAML file does — which devices to collect from,
and how to reach each one — but from NetBox, site-scoped. NetBox is the
declared-state system of record (s11–s14 write the network INTO it); this
module closes the loop by letting ``netcopilot run`` take its device list
back OUT of it: ``netcopilot run --inventory netbox://<site> --site <site>``.

Field contract (deterministic, symmetric with bootstrap):

* ``mgmt_ip``   ← the device's ``primary_ip4`` — NetBox's canonical management
  address. Bootstrap stages it with exactly the ``mgmt_ip`` collection used;
  a hand-maintained NetBox works identically because this reader consumes the
  same field. No primary IPv4 → the device is skipped with a warning
  (uncollectable is stated, never silent).
* ``os``        ← the platform *slug*, through the inverse of bootstrap's
  ``OS_TO_PLATFORM`` (one shared map — the writer and the reader cannot
  drift). Unknown slug → skipped with a warning listing the accepted slugs.
* ``role``      ← the role slug with hyphens restored to underscores — the
  exact inverse of bootstrap's ``role.replace("_", "-")``.
* stacks / HA   — NetBox stores one Device per physical chassis (ADR-0016:
  VirtualChassis members ``<name>-<pos>``, HA cluster members likewise). A
  collection target is the *logical* device, so members fold back into one
  entry named after the VC / cluster, reached via whichever member carries a
  primary IPv4.
* hints/creds   ← the device's config context, ``netcopilot`` key, allow-listed
  (``api_token``, ``username``, ``password``, ``enable_password``, ``ssh_only``,
  ``skip_families``, ``vdom``). Values are ``${ENV_VAR}`` *references* — the
  secret itself never lives in NetBox; expansion happens locally in
  ``collect/base.py`` exactly as for YAML per-device secrets.

Honesty: construction pings NetBox and loads eagerly (mirroring YAMLInventory's
parse-at-construction). Unreachable or misconfigured NetBox raises
:class:`NetBoxInventoryError` — never an empty device list.
"""
import logging

from netcopilot.inventory.base import InventorySource

log = logging.getLogger(__name__)

# Per-device keys an operator may set under config context {"netcopilot": {...}}.
# Anything else in the context (other tools' data) is ignored.
_HINT_KEYS = (
    "api_token",
    "username",
    "password",
    "enable_password",
    "ssh_only",
    "skip_families",
    "vdom",
)


class NetBoxInventoryError(RuntimeError):
    """NetBox cannot serve as an inventory source (down or misconfigured)."""


def _slug_to_os() -> dict[str, str]:
    """Inverse of bootstrap's OS_TO_PLATFORM: platform slug → canonical os.

    Imported lazily (bootstrap imports ``inventory.base`` at module level;
    a module-level import here would be a cycle).
    """
    from netcopilot.declared_state.bootstrap import OS_TO_PLATFORM

    return {slug: os_name for os_name, (slug, _display) in OS_TO_PLATFORM.items()}


class NetBoxInventory(InventorySource):
    """Site-scoped collection inventory read from NetBox.

        NetBoxInventory("t75")

    Requires ``NETBOX_URL`` + ``NETBOX_API_TOKEN`` in the environment (the
    s11 adapter's contract). The device list is resolved once at construction;
    NetBox unreachable raises :class:`NetBoxInventoryError` immediately —
    before any run directory exists.
    """

    def __init__(self, site: str, adapter=None):
        if not site:
            raise ValueError("NetBoxInventory requires a site slug (netbox://<site>)")
        self._site = site

        if adapter is None:
            # Lazy: reuses all s11 pynetbox plumbing; keeps the [netbox] extra
            # optional for YAML-only installs.
            from netcopilot.declared_state.netbox_adapter import NetBoxAdapter

            try:
                adapter = NetBoxAdapter()
            except Exception as exc:
                raise NetBoxInventoryError(
                    f"NetBox inventory source unavailable: {exc}"
                ) from exc
        self._adapter = adapter
        self._devices = self._load()

    # ------------------------------------------------------------- contract

    def get_devices(self) -> list[dict]:
        return list(self._devices)

    def get_device(self, name: str) -> dict | None:
        for device in self._devices:
            if device.get("name") == name:
                return device
        return None

    # ------------------------------------------------------------- loading

    def _load(self) -> list[dict]:
        try:
            self._adapter.ping()
        except Exception as exc:
            raise NetBoxInventoryError(
                f"NetBox is unreachable — cannot build the inventory for site "
                f"{self._site!r} (never degrading to an empty device list): {exc}"
            ) from exc

        raw = self._adapter.get_devices(site=self._site)

        entries: list[dict] = []
        groups: dict[tuple[str, str], list[dict]] = {}
        for dev in raw:
            status = (dev.get("status_value") or "").lower()
            if status != "active":
                log.info(
                    "NetBox inventory: skipping %s (status=%s, only active devices collect)",
                    dev.get("name"), status or "unknown",
                )
                continue
            if dev.get("virtual_chassis"):
                groups.setdefault(("virtual chassis", dev["virtual_chassis"]), []).append(dev)
            elif dev.get("cluster"):
                groups.setdefault(("cluster", dev["cluster"]), []).append(dev)
            else:
                entry = self._entry_from(dev, name=dev["name"])
                if entry:
                    entries.append(entry)

        # Per-physical members → one logical collection target per VC/cluster,
        # reached through whichever member carries a primary IPv4.
        for (kind, group_name), members in sorted(groups.items()):
            with_ip = sorted(
                (m for m in members if m.get("mgmt_ip")), key=lambda m: m["name"]
            )
            if not with_ip:
                log.warning(
                    "NetBox inventory: skipping %s %r — no member has a primary "
                    "IPv4 (set primary_ip4 on the management member in NetBox)",
                    kind, group_name,
                )
                continue
            if len(with_ip) > 1:
                log.info(
                    "NetBox inventory: %s %r has %d members with a primary IPv4; "
                    "collecting via %s (lowest name — deterministic)",
                    kind, group_name, len(with_ip), with_ip[0]["name"],
                )
            entry = self._entry_from(with_ip[0], name=group_name)
            if entry:
                entries.append(entry)

        entries.sort(key=lambda e: e["name"])
        log.info(
            "NetBox inventory: site %r → %d collection target(s) from %d NetBox device(s)",
            self._site, len(entries), len(raw),
        )
        return entries

    def _entry_from(self, dev: dict, *, name: str) -> dict | None:
        slug_map = _slug_to_os()
        os_name = slug_map.get(dev.get("platform_slug") or "")
        if not os_name:
            log.warning(
                "NetBox inventory: skipping %s — platform slug %r is not a "
                "collectable os family (accepted slugs: %s)",
                name, dev.get("platform_slug"), ", ".join(sorted(slug_map)),
            )
            return None
        if not dev.get("mgmt_ip"):
            log.warning(
                "NetBox inventory: skipping %s — no primary IPv4 in NetBox "
                "(set primary_ip4 on the device)",
                name,
            )
            return None

        entry: dict = {
            "name": name,
            "mgmt_ip": dev["mgmt_ip"],
            "os": os_name,
            "site": dev.get("site_slug") or self._site,
        }
        if dev.get("role_slug"):
            entry["role"] = dev["role_slug"].replace("-", "_")

        hints = (dev.get("config_context") or {}).get("netcopilot") or {}
        if hints and not isinstance(hints, dict):
            log.warning(
                "NetBox inventory: %s — config context 'netcopilot' key is not "
                "a mapping (%s); ignored", name, type(hints).__name__,
            )
            hints = {}
        for key in _HINT_KEYS:
            if key in hints:
                entry[key] = hints[key]
        return entry
