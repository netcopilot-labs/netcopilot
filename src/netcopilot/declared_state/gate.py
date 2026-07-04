"""The documentation-plane write gate (s11, ADR-0013 / Constitution Art. I).

Every code path that would write to the configured NetBox — plumbing
provisioning included — checks :func:`write_enabled` first. The flag defaults
**off**: absent explicit opt-in, NetCopilot is a pure reader of declared state.
Narrowing or widening write access is a configuration change, never a code
change (Constitution Art. IV).
"""
import os


class WritesDisabled(RuntimeError):
    """Raised when a write path is invoked while NETBOX_WRITE_ENABLED is off."""


def write_enabled() -> bool:
    """True iff the deployment explicitly opted into NetBox writes."""
    return os.environ.get("NETBOX_WRITE_ENABLED", "false").lower() == "true"


def require_write_enabled(action: str) -> None:
    """Raise :class:`WritesDisabled` with a clear message unless opted in."""
    if not write_enabled():
        raise WritesDisabled(
            f"{action} requires NETBOX_WRITE_ENABLED=true. NetCopilot writes to a "
            "declared-state source only with explicit opt-in (Constitution Art. I: "
            "staged, human-approved, audited, non-destructive)."
        )
