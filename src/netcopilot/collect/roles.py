"""Device role and site taxonomy.

Roles classify what a device is for (core router, firewall, access switch);
sites group devices by location. Both come from the inventory and are advisory:
the taxonomy is *open*, so an unrecognised role is accepted with a warning
rather than rejected — every network names its tiers differently, and forcing a
code change for each new role would create needless friction.

These are pure functions: no I/O, no logging. Callers decide what to do with
the returned warning.
"""
from __future__ import annotations

#: Recognised device roles. Advisory only — unknown roles are accepted with a
#: warning, so this set drives validation hints (and, later, role-aware rules),
#: not rejection. Extend it freely for your network.
KNOWN_ROLES: frozenset[str] = frozenset({
    "core_router",
    "border_router",
    "core_switch",
    "distribution_switch",
    "access_switch",
    "mgmt_switch",
    "services_switch",
    "dmz_switch",
    "firewall",
    "load_balancer",
})

ROLE_DEFAULT = "unknown"
SITE_DEFAULT = "unassigned"


def validate_role(role: str | None) -> tuple[str, str | None]:
    """Normalise a device role, returning ``(role, warning_or_none)``.

    * ``None``/empty → ``("unknown", "missing")``
    * known role     → ``(role, None)``
    * unknown role   → ``(role, "unknown role '<role>' — not in KNOWN_ROLES")``
    """
    if not role or not role.strip():
        return (ROLE_DEFAULT, "missing")

    normalized = role.strip().lower()
    if normalized in KNOWN_ROLES:
        return (normalized, None)
    return (normalized, f"unknown role '{normalized}' — not in KNOWN_ROLES")


def validate_site(site: str | None) -> tuple[str, str | None]:
    """Normalise a site identifier, returning ``(site, warning_or_none)``.

    Site is a free-form location label. Missing/empty → ``("unassigned",
    "missing")``; any non-empty string is accepted as-is.
    """
    if not site or not site.strip():
        return (SITE_DEFAULT, "missing")
    return (site.strip(), None)
