"""Collection strategy contract.

Every way of pulling data off a device — SSH, NETCONF, RESTCONF, a vendor REST
API — implements the same small interface so the orchestrator can drive them
without knowing which protocol is underneath. A developer adding a protocol
implements :class:`CollectionStrategy` and registers it in the strategy chain;
nothing else changes.

Two rules every strategy honours:

* **Read-only.** Collection never modifies device configuration.
* **No raising for device-level errors.** Connection failures, timeouts, and
  command errors are captured in the returned :class:`CollectionResult` (with
  ``success=False``), never raised. Only genuine programming errors raise.
"""
from __future__ import annotations

import abc
import os
from dataclasses import dataclass, field
from typing import Any, ClassVar


def expand_env_ref(value: str) -> str:
    """Resolve a ``${ENV_VAR}`` reference from the environment.

    Inventories keep secrets out of the file by naming an environment variable
    (e.g. ``password: ${TENANT_A_PW}`` or ``api_token: ${FW_EDGE01_TOKEN}``) —
    the actual secret lives in ``.env``. A literal value is returned unchanged.

    Raises ``ValueError`` if the reference names a variable that is not set, so a
    forgotten env var surfaces as a clear error instead of a silent auth failure
    (``collect_device`` records it per-device and never aborts the run).
    """
    expanded = os.path.expandvars(value)
    if "${" in expanded:
        raise ValueError(f"references an unset environment variable: {value!r}")
    return expanded


@dataclass
class CollectionResult:
    """Outcome of collecting from a single device.

    Attributes:
        success: ``True`` if collection completed without fatal errors.
        strategy_name: Which strategy produced this result (``"ssh"``, ...).
        hostname: Hostname as reported by the device (falls back to the
            inventory name when the device could not be reached).
        files_created: Raw output files written during collection.
        error: Error message when ``success`` is ``False`` (else ``None``).
        commands: Per-command records for the manifest, each a dict of
            ``{"command", "output_file", "status", "error"}``.
    """

    success: bool
    strategy_name: str
    hostname: str
    files_created: list[str] = field(default_factory=list)
    error: str | None = None
    commands: list[dict[str, Any]] = field(default_factory=list)


class CollectionStrategy(abc.ABC):
    """Abstract interface for a device-collection strategy.

    The orchestrator calls :meth:`supports` to ask whether a strategy can reach
    a device, then :meth:`collect` to do the work. Concrete strategies set
    :attr:`name` to the label recorded in the manifest.
    """

    #: Stable label recorded in the manifest (e.g. ``"ssh"``).
    name: ClassVar[str] = ""

    @abc.abstractmethod
    def supports(self, device: dict[str, Any]) -> bool:
        """Return ``True`` if this strategy can collect from ``device``.

        Args:
            device: Device dict carrying at least ``name``, ``mgmt_ip`` and
                ``os``. The ``os`` family usually decides compatibility.
        """

    @abc.abstractmethod
    def collect(
        self,
        device: dict[str, Any],
        commands: list[str],
        output_dir: str,
        credentials: dict[str, Any],
    ) -> CollectionResult:
        """Collect evidence from one device.

        Connects to ``device``, runs ``commands``, writes raw output under
        ``output_dir/<name>/``, and returns a :class:`CollectionResult`. Must
        not raise for device-level errors — capture them in the result.

        Args:
            device: Device dict (``name``, ``mgmt_ip``, ``os``, ...). Example::

                {"name": "core-rtr-01", "mgmt_ip": "192.0.2.1", "os": "ios-xe"}

            commands: CLI commands to run (from the OS command profile).
            output_dir: Base directory for raw files; the strategy creates a
                ``<name>/`` subdirectory beneath it.
            credentials: ``{"username", "password", "enable_password"}``.
        """
