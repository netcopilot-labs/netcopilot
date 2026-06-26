"""NETCONF collection strategy (ncclient).

Fetches structured YANG data (XML) from Cisco IOS XE / IOS XR over NETCONF
(port 830) — schema-defined data instead of screen-scraped CLI text. One class
handles both OS families; the differences (YANG models, ncclient driver,
hostname location) are data, not separate code paths.

Read-only: only ``<get>`` / ``<get-config>`` operations, never ``<edit-config>``.
Raw XML is saved per query as ``raw/<name>/netconf_<query>.xml`` for the parse
layer to consume.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from ncclient import manager

from netcopilot.collect.base import CollectionResult, CollectionStrategy

logger = logging.getLogger(__name__)

SUPPORTED_OS_FAMILIES = frozenset({"ios-xe", "ios-xr"})

#: NetCopilot OS family -> ncclient device_params driver name.
DEVICE_PARAMS = {
    "ios-xe": {"name": "iosxe"},
    "ios-xr": {"name": "iosxr"},
}

NETCONF_PORT = 830  # RFC 6241

#: Connect/RPC timeout. Generous enough for devices whose NETCONF daemon is slow
#: to become ready, short enough to fail a dead host without a long hang.
NETCONF_TIMEOUT = 60

#: Retries after the first attempt (so 1+1 = 2 total). Some platforms need a
#: second try once their NETCONF daemon settles; beyond that the chain falls
#: through to the next strategy.
MAX_RETRIES = 1

# Each YANG query is (name, subtree_filter_xml, operation). name -> filename.
IOSXE_YANG_QUERIES = [
    (
        "system",
        """
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
          <hostname/>
          <version/>
        </native>
        """,
        "get",
    ),
    (
        "device_hardware",
        """
        <device-hardware-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-device-hardware-oper">
          <device-hardware>
            <device-inventory/>
            <device-system-data/>
          </device-hardware>
        </device-hardware-data>
        """,
        "get",
    ),
    (
        "interfaces",
        '<interfaces xmlns="http://openconfig.net/yang/interfaces"></interfaces>',
        "get",
    ),
    (
        "cdp",
        '<cdp-neighbor-details xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-cdp-oper"></cdp-neighbor-details>',
        "get",
    ),
    (
        "lldp",
        '<lldp xmlns="http://openconfig.net/yang/lldp"></lldp>',
        "get",
    ),
    # Stack/member operational data — per-member role, priority, state. Non-stack
    # devices return an empty <data/> gracefully.
    (
        "stack_oper",
        '<stack-oper-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-stack-oper"/>',
        "get",
    ),
]

IOSXR_YANG_QUERIES = [
    (
        "system_hostname",
        '<host-names xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-shellutil-cfg"></host-names>',
        "get-config",
    ),
    (
        "system_version",
        """
        <install xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-install-oper">
          <version/>
        </install>
        """,
        "get",
    ),
    (
        "system_uptime",
        '<system-time xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-shellutil-oper"></system-time>',
        "get",
    ),
    (
        "system_platform",
        """
        <platform-inventory xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-plat-chas-invmgr-ng-oper">
          <racks>
            <rack>
              <name>0</name>
              <attributes>
                <basic-info/>
              </attributes>
            </rack>
          </racks>
        </platform-inventory>
        """,
        "get",
    ),
    (
        "interfaces",
        '<interfaces xmlns="http://openconfig.net/yang/interfaces"></interfaces>',
        "get",
    ),
    (
        "cdp",
        '<cdp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-cdp-oper"></cdp>',
        "get",
    ),
    (
        "lldp",
        '<lldp xmlns="http://openconfig.net/yang/lldp"></lldp>',
        "get",
    ),
]

OS_TO_YANG_QUERIES = {
    "ios-xe": IOSXE_YANG_QUERIES,
    "ios-xr": IOSXR_YANG_QUERIES,
}


def _determine_hostname_from_xml(
    os_family: str,
    xml_files: dict[str, str],
    fallback: str,
) -> str:
    """Extract the device hostname from collected NETCONF XML.

    IOS XE keeps it in ``Cisco-IOS-XE-native/hostname``; IOS XR in
    ``Cisco-IOS-XR-shellutil-cfg/host-name``. Returns ``fallback`` if absent.
    """
    try:
        if os_family == "ios-xe":
            xml_str = xml_files.get("system", "")
            if xml_str:
                root = ElementTree.fromstring(xml_str)
                tag = "{http://cisco.com/ns/yang/Cisco-IOS-XE-native}hostname"
                for elem in root.iter(tag):
                    if elem.text:
                        return elem.text.strip()
        elif os_family == "ios-xr":
            xml_str = xml_files.get("system_hostname", "")
            if xml_str:
                root = ElementTree.fromstring(xml_str)
                tag = "{http://cisco.com/ns/yang/Cisco-IOS-XR-shellutil-cfg}host-name"
                for elem in root.iter(tag):
                    if elem.text:
                        return elem.text.strip()
    except ElementTree.ParseError as exc:
        logger.warning("Failed to parse hostname XML: %s", exc)
    return fallback


class NetconfAdapter(CollectionStrategy):
    """Collect structured YANG data over NETCONF using ncclient."""

    name = "netconf"

    def supports(self, device: dict[str, Any]) -> bool:
        if device.get("ssh_only", False):
            return False
        return device.get("os") in SUPPORTED_OS_FAMILIES

    def collect(
        self,
        device: dict[str, Any],
        commands: list[str],
        output_dir: str,
        credentials: dict[str, Any],
    ) -> CollectionResult:
        """Collect via NETCONF. ``commands`` is ignored (YANG queries are used)."""
        os_family = device["os"]
        params = DEVICE_PARAMS.get(os_family)
        if not params:
            return CollectionResult(
                success=False, strategy_name=self.name,
                hostname=device.get("name", device.get("mgmt_ip", "unknown")),
                error=f"No NETCONF device_params for os '{os_family}'",
            )

        yang_queries = OS_TO_YANG_QUERIES.get(os_family, [])
        inventory_name = device.get("name", device["mgmt_ip"])
        real_hostname = inventory_name
        status = True
        error: str | None = None
        command_entries: list[dict[str, Any]] = []
        files_created: list[str] = []
        xml_by_name: dict[str, str] = {}

        for attempt in range(1 + MAX_RETRIES):
            try:
                status, error, command_entries, files_created, xml_by_name = (
                    self._netconf_collect(device, params, yang_queries, output_dir, credentials)
                )
                break
            except Exception as exc:  # noqa: BLE001 — transport failure is data
                error_msg = f"{type(exc).__name__}: {exc}"
                if attempt < MAX_RETRIES:
                    logger.warning("NETCONF attempt %d failed for '%s': %s. Retrying...",
                                   attempt + 1, inventory_name, error_msg)
                    time.sleep(2)
                else:
                    status = False
                    error = f"NETCONF failed after {1 + MAX_RETRIES} attempts: {error_msg}"
                    logger.error("NETCONF failed for '%s': %s", inventory_name, error_msg)

        if xml_by_name:
            real_hostname = _determine_hostname_from_xml(os_family, xml_by_name, inventory_name)

        return CollectionResult(
            success=status, strategy_name=self.name, hostname=real_hostname,
            files_created=files_created, error=error, commands=command_entries,
        )

    def _netconf_collect(self, device, params, yang_queries, output_dir, credentials):
        """Run all YANG queries within one NETCONF session; raises on connect failure."""
        status = True
        error: str | None = None
        command_entries: list[dict[str, Any]] = []
        files_created: list[str] = []
        xml_by_name: dict[str, str] = {}

        logger.info("Connecting to '%s' (%s) via NETCONF", device["name"], device["mgmt_ip"])
        with manager.connect(
            host=device["mgmt_ip"],
            port=NETCONF_PORT,
            username=credentials["username"],
            password=credentials["password"],
            device_params=params,
            hostkey_verify=False,   # BYO networks rarely run NETCONF host-key PKI; read-only collection
            look_for_keys=False,    # password auth only — don't probe local SSH keys
            allow_agent=False,      # no SSH agent — faster handshake
            timeout=NETCONF_TIMEOUT,
        ) as conn:
            for query_name, filter_xml, operation in yang_queries:
                cmd_status = "success"
                cmd_error: str | None = None
                try:
                    if operation == "get-config":
                        result = conn.get_config(source="running", filter=("subtree", filter_xml))
                    else:
                        result = conn.get(filter=("subtree", filter_xml))
                    xml_by_name[query_name] = str(result)
                except Exception as query_exc:  # noqa: BLE001 — per-query fail-soft
                    # A single query failing is not fatal — partial NETCONF data is
                    # still useful (e.g. stack_oper is absent on non-stack devices).
                    # Only a connection-level failure (outer retry loop) fails the run.
                    cmd_status = "error"
                    cmd_error = f"{type(query_exc).__name__}: {query_exc}"
                    logger.warning("YANG query '%s' failed for '%s': %s",
                                   query_name, device["name"], cmd_error)

                command_entries.append({
                    "command": f"NETCONF:{query_name}",
                    "output_file": None,
                    "status": cmd_status,
                    "error": cmd_error,
                })

        host_path = Path(output_dir) / device.get("name", device["mgmt_ip"])
        host_path.mkdir(parents=True, exist_ok=True)
        for i, (query_name, _, _) in enumerate(yang_queries):
            raw_xml = xml_by_name.get(query_name)
            if raw_xml:
                output_file = host_path / f"netconf_{query_name}.xml"
                output_file.write_text(raw_xml, encoding="utf-8")
                files_created.append(str(output_file))
                command_entries[i]["output_file"] = str(output_file)

        return status, error, command_entries, files_created, xml_by_name
