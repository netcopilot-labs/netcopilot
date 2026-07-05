"""NetBox declared-state adapter (s11, ADR-0013).

Read path against NetBox 4.6+ via ``pynetbox`` 7.x; v2 hashed tokens (format
``nbt_{key}.{plaintext}``) are supported natively via the ``token=`` argument.

The adapter also carries the *infrastructure provisioning* helpers bootstrap
needs (ClusterType, custom fields, device roles, manufacturers, DeviceTypes
enriched from the public netbox-community devicetype-library). These are
plumbing writes — still writes: every one of them is behind the
``NETBOX_WRITE_ENABLED`` gate (Constitution Art. I). The operator-decision
write path (approve → POST/PATCH) lives in :mod:`netcopilot.declared_state.staging`.
"""
import logging
import os

from netcopilot.declared_state.base import DeclaredStateSource
from netcopilot.declared_state.gate import require_write_enabled

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_SECONDS = 10  # Fail fast when NetBox is unreachable.


class ImproperlyConfigured(RuntimeError):
    """Raised when NetBox env vars are missing or malformed."""


class NetBoxAdapter(DeclaredStateSource):
    """Read declared state from NetBox via ``pynetbox``.

    Authentication uses ``NETBOX_URL`` + ``NETBOX_API_TOKEN`` from the
    environment (or constructor args). TLS verification is controlled by
    ``NETBOX_VERIFY_SSL`` (default ``"true"``; set ``"false"`` for
    self-signed lab certificates).
    """

    def __init__(
        self,
        url: str | None = None,
        token: str | None = None,
        verify_ssl: bool | None = None,
        timeout: int = _DEFAULT_TIMEOUT_SECONDS,
    ):
        self._url = url or os.environ.get("NETBOX_URL")
        self._token = token or os.environ.get("NETBOX_API_TOKEN")

        if not self._url:
            raise ImproperlyConfigured(
                "NETBOX_URL is not set. NetBoxAdapter requires NETBOX_URL + NETBOX_API_TOKEN "
                "in the environment (or constructor args)."
            )
        if not self._token:
            raise ImproperlyConfigured(
                "NETBOX_API_TOKEN is not set. NetBoxAdapter requires a valid token "
                "(v2 format: nbt_{key}.{plaintext})."
            )

        if verify_ssl is None:
            verify_ssl = os.environ.get("NETBOX_VERIFY_SSL", "true").lower() != "false"

        # pynetbox is imported lazily so the rest of the package stays usable
        # without the [netbox] extra installed.
        try:
            import pynetbox
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise ImproperlyConfigured(
                "pynetbox is not installed. Install the NetBox extra: "
                "pip install 'netcopilot[netbox]'"
            ) from exc

        self._nb = pynetbox.api(self._url, token=self._token)
        self._nb.http_session.verify = verify_ssl
        self._nb.http_session.timeout = timeout

    # ---------------------------------------------------------------- contract

    def get_devices(self) -> list[dict]:
        try:
            return [self._device_to_dict(d) for d in self._nb.dcim.devices.all()]
        except Exception as exc:  # network error, auth failure, etc.
            log.error("NetBoxAdapter.get_devices() failed: %s", exc)
            return []

    def get_device(self, hostname: str) -> dict | None:
        try:
            dev = self._nb.dcim.devices.get(name=hostname)
            if dev is None:
                return None
            return self._device_to_dict(dev)
        except Exception as exc:
            log.error("NetBoxAdapter.get_device(%r) failed: %s", hostname, exc)
            return None

    def get_sites(self) -> list[dict]:
        try:
            return [self._site_to_dict(s) for s in self._nb.dcim.sites.all()]
        except Exception as exc:
            log.error("NetBoxAdapter.get_sites() failed: %s", exc)
            return []

    def get_interfaces(self, device: str) -> list[dict]:
        try:
            return [
                self._interface_to_dict(iface)
                for iface in self._nb.dcim.interfaces.filter(device=device)
            ]
        except Exception as exc:
            log.error("NetBoxAdapter.get_interfaces(%r) failed: %s", device, exc)
            return []

    # ---------------------------------------------------------------- mapping

    @staticmethod
    def _device_to_dict(dev) -> dict:
        """Flatten a pynetbox device record into the inventory-compatible shape."""
        # pynetbox returns Record objects with __str__ but no .get(); each
        # field goes through getattr guards.
        primary_ip = None
        if getattr(dev, "primary_ip4", None) is not None:
            primary_ip = str(dev.primary_ip4).split("/")[0]
        elif getattr(dev, "primary_ip", None) is not None:
            primary_ip = str(dev.primary_ip).split("/")[0]

        role = None
        if getattr(dev, "role", None) is not None:
            role = str(dev.role)
        elif getattr(dev, "device_role", None) is not None:
            role = str(dev.device_role)

        platform = str(dev.platform) if getattr(dev, "platform", None) is not None else None
        site = str(dev.site) if getattr(dev, "site", None) is not None else None
        status = str(dev.status) if getattr(dev, "status", None) is not None else None
        serial = str(dev.serial) if getattr(dev, "serial", None) else None

        return {
            "name": str(dev.name),
            "mgmt_ip": primary_ip,
            "role": role,
            "platform": platform,
            "site": site,
            "status": status,
            "serial": serial,
            "netbox_id": dev.id,
        }

    @staticmethod
    def _site_to_dict(site) -> dict:
        return {
            "slug": str(site.slug),
            "name": str(site.name),
            "netbox_id": site.id,
        }

    @staticmethod
    def _interface_to_dict(iface) -> dict:
        return {
            "name": str(iface.name),
            "device": str(iface.device) if getattr(iface, "device", None) is not None else None,
            "enabled": bool(iface.enabled) if getattr(iface, "enabled", None) is not None else None,
            "type": str(iface.type) if getattr(iface, "type", None) is not None else None,
            "mtu": iface.mtu if getattr(iface, "mtu", None) is not None else None,
            "mac_address": str(iface.mac_address) if getattr(iface, "mac_address", None) is not None else None,
            "description": str(iface.description) if getattr(iface, "description", None) else "",
            "netbox_id": iface.id,
        }

    # ------------------------------------------------------- dedup-read extras
    # Read helpers beyond the DeclaredStateSource contract, consumed by
    # bootstrap's NetBox-side dedup (s13 fix: interfaces / manufacturers /
    # platforms / virtual-chassis / inventory items were pending-only deduped,
    # so re-clicking Bootstrap re-staged already-documented objects).

    def get_manufacturers(self) -> list[dict]:
        try:
            return [{"slug": str(m.slug), "name": str(m.name), "netbox_id": m.id}
                    for m in self._nb.dcim.manufacturers.all()]
        except Exception as exc:
            log.error("NetBoxAdapter.get_manufacturers() failed: %s", exc)
            return []

    def get_platforms(self) -> list[dict]:
        try:
            return [{"slug": str(p.slug), "name": str(p.name), "netbox_id": p.id}
                    for p in self._nb.dcim.platforms.all()]
        except Exception as exc:
            log.error("NetBoxAdapter.get_platforms() failed: %s", exc)
            return []

    def get_virtual_chassis(self) -> list[dict]:
        try:
            return [{"name": str(v.name), "netbox_id": v.id}
                    for v in self._nb.dcim.virtual_chassis.all()]
        except Exception as exc:
            log.error("NetBoxAdapter.get_virtual_chassis() failed: %s", exc)
            return []

    def get_inventory_items(self, device: str) -> list[dict]:
        try:
            return [{"name": str(i.name),
                     "serial": str(i.serial) if getattr(i, "serial", None) else None,
                     "netbox_id": i.id}
                    for i in self._nb.dcim.inventory_items.filter(device=device)]
        except Exception as exc:
            log.error("NetBoxAdapter.get_inventory_items(%r) failed: %s", device, exc)
            return []

    # ---------------------------------------------------------------- probe

    def ping(self) -> None:
        """Raise if NetBox is unreachable — never degrade to empty reads.

        The get_* methods swallow errors into []/None (acceptable as dedup
        hints); consumers that must distinguish "NetBox is empty" from
        "NetBox is down" (drift detection, s13) call this first.
        """
        self._nb.status()

    # ---------------------------------------------------------------- clusters

    def get_cluster(self, name: str) -> dict | None:
        """Return a single ``dcim.Cluster`` by name, or None."""
        try:
            cl = self._nb.virtualization.clusters.get(name=name)
            if cl is None:
                return None
            return {"name": str(cl.name), "type": str(cl.type), "netbox_id": cl.id}
        except Exception as exc:
            log.error("NetBoxAdapter.get_cluster(%r) failed: %s", name, exc)
            return None

    def get_clusters(self) -> list[dict]:
        try:
            return [
                {"name": str(c.name), "type": str(c.type), "netbox_id": c.id}
                for c in self._nb.virtualization.clusters.all()
            ]
        except Exception as exc:
            log.error("NetBoxAdapter.get_clusters() failed: %s", exc)
            return []

    # ---------------------------------------------------------------- provisioning (gated writes)

    # ClusterType slug used for active/passive HA pairs (firewall HA, etc.).
    HA_CLUSTER_TYPE_SLUG = "ha-pair"
    HA_CLUSTER_TYPE_NAME = "HA Pair"

    # Device custom_fields carrying stack membership for switch stacks.
    STACK_CUSTOM_FIELDS = (
        ("stack_cluster", "text", "Stack/cluster name from the inventory (e.g. SW_CORE)."),
        ("stack_size", "integer", "Number of physical stack members."),
    )

    # Device roles auto-provisioned from the inventory's "role:" values.
    ROLES_TO_PROVISION = (
        ("Border Router", "border-router", "ff5722"),
        ("Core Switch", "core-switch", "1976d2"),
        ("Access Switch", "access-switch", "388e3c"),
        ("Services Switch", "services-switch", "00897b"),
        ("Management Switch", "mgmt-switch", "9e9e9e"),
        ("Firewall", "firewall", "d32f2f"),
    )

    # Auto-provisioned manufacturers (slug-canonical for FK references).
    PROVISIONED_MANUFACTURERS = (
        ("Cisco", "cisco"),
        ("Fortinet", "fortinet"),
    )

    # Chassis model (as reported by device inventory) → community
    # devicetype-library (manufacturer dir, YAML filename). Family names often
    # differ from the specific SKU the library indexes by; this map bridges
    # the common cases. Unknown models fall back to a minimal DeviceType the
    # operator can enrich in the NetBox UI. Extend via subclassing or a
    # future config file when a deployment needs more models.
    _CHASSIS_LIBRARY_MAP = {
        # Cisco
        "C9300-24T": ("Cisco", "C9300-24T"),
        "C9500-32C": ("Cisco", "C9500-32C"),
        "C9500-48Y4C": ("Cisco", "C9500-48Y4C"),
    }

    DEVICETYPE_LIBRARY_BASE_URL = (
        "https://raw.githubusercontent.com/netbox-community/"
        "devicetype-library/master/device-types"
    )

    def ensure_infrastructure(self) -> dict:
        """Idempotently provision NetBox-side prerequisites for bootstrap.

        Creates (if absent): the ``ha-pair`` ClusterType, the two stack
        custom_fields on ``dcim.Device``, the device roles, and the
        manufacturers. Gated: raises ``WritesDisabled`` unless
        ``NETBOX_WRITE_ENABLED=true`` (reads to check presence are fine; the
        creates are not).

        Returns a ``{item: "created"|"present"}`` summary for logging/smoke.

        Raises:
            RuntimeError: if the token lacks the needed read/write permission —
                surfaced before any candidate is staged so the operator sees a
                clear error.
        """
        result: dict[str, str] = {}

        # 1. ClusterType "ha-pair"
        try:
            existing = self._nb.virtualization.cluster_types.get(slug=self.HA_CLUSTER_TYPE_SLUG)
        except Exception as exc:
            raise RuntimeError(
                f"NetBox token lacks read access to virtualization.cluster_types: {exc}"
            ) from exc

        if existing is None:
            require_write_enabled("ensure_infrastructure (ClusterType create)")
            try:
                self._nb.virtualization.cluster_types.create(
                    name=self.HA_CLUSTER_TYPE_NAME,
                    slug=self.HA_CLUSTER_TYPE_SLUG,
                    description="Active/passive HA pair. Auto-provisioned by NetCopilot (ADR-0013).",
                )
                result["cluster_type"] = "created"
            except Exception as exc:
                raise RuntimeError(
                    f"NetBox token lacks write access to virtualization.cluster_types: {exc}"
                ) from exc
        else:
            result["cluster_type"] = "present"

        # 2. Stack custom_fields scoped to dcim.device. NetBox 4.6 accepts
        # object_types as a list of "app.model" strings directly.
        for cf_name, cf_type, cf_description in self.STACK_CUSTOM_FIELDS:
            try:
                existing = self._nb.extras.custom_fields.get(name=cf_name)
            except Exception as exc:
                raise RuntimeError(
                    f"NetBox token lacks read access to extras.custom_fields: {exc}"
                ) from exc

            if existing is None:
                require_write_enabled(f"ensure_infrastructure (custom_field {cf_name})")
                try:
                    self._nb.extras.custom_fields.create(
                        name=cf_name,
                        label=cf_name.replace("_", " ").title(),
                        type=cf_type,
                        required=False,
                        object_types=["dcim.device"],
                        description=cf_description + " Auto-provisioned by NetCopilot (ADR-0013).",
                    )
                    result[cf_name] = "created"
                except Exception as exc:
                    raise RuntimeError(
                        f"NetBox token lacks write access to extras.custom_fields: {exc}"
                    ) from exc
            else:
                result[cf_name] = "present"

        # 3. Device roles (NetBox 4.6 requires Device.role to be a DeviceRole FK).
        for name, slug, color in self.ROLES_TO_PROVISION:
            try:
                existing = self._nb.dcim.device_roles.get(slug=slug)
            except Exception as exc:
                raise RuntimeError(
                    f"NetBox token lacks read access to dcim.device_roles: {exc}"
                ) from exc

            if existing is None:
                require_write_enabled(f"ensure_infrastructure (device_role {slug})")
                try:
                    self._nb.dcim.device_roles.create(
                        name=name,
                        slug=slug,
                        color=color,
                        description="Auto-provisioned by NetCopilot (ADR-0013).",
                    )
                    result[f"role/{slug}"] = "created"
                except Exception as exc:
                    raise RuntimeError(
                        f"NetBox token lacks write access to dcim.device_roles: {exc}"
                    ) from exc
            else:
                result[f"role/{slug}"] = "present"

        # 4. Manufacturers (Device.device_type → Manufacturer FK chain).
        for mfr_name, mfr_slug in self.PROVISIONED_MANUFACTURERS:
            try:
                existing = self._nb.dcim.manufacturers.get(slug=mfr_slug)
            except Exception as exc:
                raise RuntimeError(
                    f"NetBox token lacks read access to dcim.manufacturers: {exc}"
                ) from exc

            if existing is None:
                require_write_enabled(f"ensure_infrastructure (manufacturer {mfr_slug})")
                try:
                    self._nb.dcim.manufacturers.create(
                        name=mfr_name,
                        slug=mfr_slug,
                        description="Auto-provisioned by NetCopilot (ADR-0013).",
                    )
                    result[f"manufacturer/{mfr_slug}"] = "created"
                except Exception as exc:
                    raise RuntimeError(
                        f"NetBox token lacks write access to dcim.manufacturers: {exc}"
                    ) from exc
            else:
                result[f"manufacturer/{mfr_slug}"] = "present"

        log.info("NetBoxAdapter.ensure_infrastructure() complete: %s", result)
        return result

    def ensure_device_type(self, slug: str, model: str, manufacturer_slug: str) -> int:
        """Idempotently provision a ``dcim.DeviceType`` (gated write).

        When the chassis model maps to a community devicetype-library entry
        (``_CHASSIS_LIBRARY_MAP``), the DeviceType is created (or enriched if
        already minimal) with full chassis metadata + port templates. Unknown
        models fall back to a minimal DeviceType (model + slug + manufacturer);
        the operator can enrich via the NetBox UI.

        Re-running upgrades an existing minimal DeviceType in place — fills
        empty fields + creates missing template records. Safe to repeat.

        Returns the DeviceType's NetBox id.
        """
        try:
            existing = self._nb.dcim.device_types.get(slug=slug)
        except Exception as exc:
            raise RuntimeError(
                f"NetBox token lacks read access to dcim.device_types: {exc}"
            ) from exc

        library_yaml = self._fetch_library_device_type(model)

        if existing is None:
            require_write_enabled(f"ensure_device_type ({slug})")
            return self._create_device_type(
                slug=slug, model=model, manufacturer_slug=manufacturer_slug,
                library_yaml=library_yaml,
            )

        # Existing record — enrich if we have library data and it's still minimal.
        if library_yaml is not None:
            require_write_enabled(f"ensure_device_type (enrich {slug})")
            self._enrich_existing_device_type(existing, library_yaml)
        return existing.id

    def _fetch_library_device_type(self, model: str) -> dict | None:
        """Fetch + parse the community-library YAML for a chassis model.

        Returns None if (a) the model has no library mapping, (b) the network
        fetch fails, or (c) the YAML can't be parsed — in all three cases the
        caller falls back to a minimal DeviceType. Failures are logged, never
        raised.
        """
        mapping = self._CHASSIS_LIBRARY_MAP.get(model)
        if mapping is None:
            log.info("No library mapping for chassis %r — DeviceType will be minimal", model)
            return None
        manufacturer_dir, library_name = mapping
        url = f"{self.DEVICETYPE_LIBRARY_BASE_URL}/{manufacturer_dir}/{library_name}.yaml"

        import urllib.request
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                raw = resp.read().decode("utf-8")
        except Exception as exc:
            log.warning("Library fetch failed for %s (%s): %s", model, url, exc)
            return None

        try:
            import yaml
            data = yaml.safe_load(raw)
        except Exception as exc:
            log.warning("Library YAML parse failed for %s: %s", model, exc)
            return None

        if not isinstance(data, dict):
            log.warning("Library YAML for %s is not a dict; ignoring", model)
            return None

        log.info("Loaded library DeviceType for %s from %s", model, library_name)
        return data

    def _create_device_type(
        self, *, slug: str, model: str, manufacturer_slug: str,
        library_yaml: dict | None,
    ) -> int:
        """Create a fresh DeviceType, optionally with library-derived fields + templates."""
        payload: dict = {
            "model": model,
            "slug": slug,
            "manufacturer": {"slug": manufacturer_slug},
            "description": "Auto-provisioned by NetCopilot (ADR-0013).",
        }
        if library_yaml:
            # Promote a curated set of library fields; skip ones NetBox might reject.
            for field in (
                "part_number", "u_height", "is_full_depth",
                "weight", "weight_unit", "subdevice_role",
                "airflow", "comments",
            ):
                if field in library_yaml and library_yaml[field] is not None:
                    payload[field] = library_yaml[field]

        try:
            created = self._nb.dcim.device_types.create(**payload)
        except Exception as exc:
            raise RuntimeError(
                f"NetBox token lacks write access to dcim.device_types: {exc}"
            ) from exc

        if library_yaml:
            self._sync_port_templates(created.id, library_yaml)
        return created.id

    def _enrich_existing_device_type(self, existing, library_yaml: dict) -> None:
        """PATCH empty fields on an existing DeviceType + ensure templates exist.

        Only fills empty fields — never overwrites operator edits. Template
        records are idempotent: existing names skip; missing names create.
        """
        patch: dict = {}
        for field in (
            "part_number", "u_height", "is_full_depth",
            "weight", "weight_unit", "subdevice_role",
            "airflow", "comments",
        ):
            if field not in library_yaml or library_yaml[field] is None:
                continue
            current = getattr(existing, field, None)
            # Treat "" / 0 / None as empty (NetBox returns 0 for unset u_height).
            if current in (None, "", 0):
                patch[field] = library_yaml[field]

        if patch:
            try:
                existing.update(patch)
                log.info("Enriched DeviceType %s with: %s", existing.slug, sorted(patch.keys()))
            except Exception as exc:
                log.warning("Failed to PATCH DeviceType %s: %s", existing.slug, exc)

        self._sync_port_templates(existing.id, library_yaml)

    # YAML key (kebab-case) → pynetbox endpoint attribute (snake_case).
    #
    # NOTE: interface_templates intentionally NOT synced. The community
    # devicetype-library YAMLs use slot-1-baked names; with stacks expanded
    # into N member Devices (per-physical-device model), NetBox would
    # auto-create slot-1 names on EVERY member, colliding with the real
    # slot-N interfaces staged by bootstrap. Bootstrap's staged interface
    # candidates are the only authoritative source for Device.interfaces.
    _PORT_TEMPLATE_ENDPOINTS = (
        ("console-ports", "console_port_templates", ("name", "type")),
        ("power-ports", "power_port_templates", ("name", "type", "maximum_draw", "allocated_draw")),
        ("rear-ports", "rear_port_templates", ("name", "type", "positions")),
        # Module bays — chassis slot definitions; installed modules need
        # collection-layer data not surfaced today (operator adds dcim.Module
        # manually when needed).
        ("module-bays", "module_bay_templates", ("name", "position", "label")),
        # front-ports need a rear_port id unavailable at create time; deferred.
    )

    def _sync_port_templates(self, device_type_id: int, library_yaml: dict) -> None:
        """Create missing port-template records for a DeviceType (idempotent)."""
        for yaml_key, endpoint_attr, allowed_fields in self._PORT_TEMPLATE_ENDPOINTS:
            entries = library_yaml.get(yaml_key) or []
            if not entries:
                continue
            endpoint = getattr(self._nb.dcim, endpoint_attr)

            try:
                existing_names = {
                    str(e.name) for e in endpoint.filter(device_type_id=device_type_id)
                }
            except Exception as exc:
                log.warning(
                    "Could not list %s for DeviceType id=%s: %s",
                    endpoint_attr, device_type_id, exc,
                )
                continue

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                if not name or name in existing_names:
                    continue
                payload = {
                    "device_type": device_type_id,
                    "name": name,
                }
                for field in allowed_fields:
                    if field in entry and entry[field] is not None:
                        payload[field] = entry[field]
                try:
                    endpoint.create(**payload)
                except Exception as exc:
                    log.warning(
                        "Could not create %s '%s' on DeviceType id=%s: %s",
                        endpoint_attr, name, device_type_id, exc,
                    )
