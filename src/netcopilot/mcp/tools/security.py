"""get_security_posture — security configuration per device.

Reads security_config.json (Cisco) and FortiGate security files
to present AAA, SSH, SNMP, NTP, logging, and access control config.
"""

import json
import logging
from pathlib import Path

from netcopilot.graph.client import get_driver, is_available

log = logging.getLogger(__name__)


async def get_security_posture(
    *,
    device: str | None = None,
    context: dict,
) -> str:
    """Get security configuration for a device or network overview."""
    run_id = context.get("run_id", "")
    data_dir = context.get("data_dir", "")

    if not is_available():
        return "Neo4j is unavailable."

    driver = get_driver()

    # Resolve device name
    if device:
        import re
        filt = device.lower()
        if '-' not in filt:
            filt = re.sub(r'([a-z]{2,})(\d)', r'\1-\2', filt)
        with driver.session() as session:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id}) "
                "WHERE toLower(d.name) CONTAINS $filt "
                "RETURN d.name AS name, d.os_type AS os, d.role AS role "
                "LIMIT 1",
                run_id=run_id, filt=filt,
            )
            rec = result.single()
            if not rec:
                # Check if it's a service name
                svc_result = session.run(
                    "MATCH (d:Device {run_id: $run_id})-[:HAS_INTERFACE]->(i:Interface) "
                    "WHERE toLower(i.description) CONTAINS toLower($name) "
                    "RETURN DISTINCT d.name AS device LIMIT 5",
                    run_id=run_id, name=device,
                )
                svc = [r["device"] for r in svc_result]
                if svc:
                    return (
                        f"'{device}' is a service, not a device. "
                        f"Found on: {', '.join(svc)}. "
                        f"Use get_security_posture(device=\"{svc[0]}\") for security details."
                    )
                return f"Device '{device}' not found."
            device = rec["name"]
            os_type = rec["os"] or ""
            role = rec["role"] or ""
    else:
        # Network-wide overview
        return await _network_overview(run_id, data_dir, driver)

    # Per-device security posture — try Neo4j SecurityConfig first.
    neo4j_result = _posture_from_neo4j(device, role, os_type, run_id, driver)
    if neo4j_result:
        return neo4j_result

    # Fallback to disk read (runs without SecurityConfig nodes).
    facts_dir = Path(data_dir) / "facts" / device
    if os_type == "fortios":
        return _fortigate_posture(device, role, facts_dir)
    else:
        return _cisco_posture(device, role, os_type, facts_dir)


def _posture_from_neo4j(device: str, role: str, os_type: str, run_id: str, driver) -> str | None:
    """Query SecurityConfig node from Neo4j. Returns formatted output or None if not found."""
    try:
        with driver.session() as session:
            result = session.run(
                "MATCH (d:Device {run_id: $run_id, name: $device})"
                "-[:HAS_SECURITY_CONFIG]->(sc:SecurityConfig) "
                "RETURN properties(sc) AS props",
                run_id=run_id, device=device,
            )
            rec = result.single()
            if not rec:
                return None

            sc = rec["props"]
    except Exception as exc:
        log.warning("Neo4j SecurityConfig query failed for %s: %s", device, exc)
        return None

    lines = [
        f"Security posture — {device}",
        f"  Role: {role} | OS: {os_type}",
        "",
    ]

    source = sc.get("config_source", "")

    if source == "cisco":
        # AAA
        lines.append("AAA:")
        auth = sc.get("aaa_authentication_login_default", "not configured")
        authz = sc.get("aaa_authorization_exec_default", "not configured")
        acct = "yes" if sc.get("aaa_accounting_configured") else "no"
        lines.append(f"  Authentication: {auth}")
        lines.append(f"  Authorization: {authz}")
        lines.append(f"  Accounting: {acct}")
        lines.append("")

        # SSH
        ssh_src = sc.get("ssh_source_interface")
        if ssh_src:
            lines.append("SSH:")
            lines.append(f"  source_interface: {ssh_src}")
            lines.append("")

        # SNMP
        lines.append("SNMP:")
        communities_json = sc.get("snmp_communities", "[]")
        try:
            communities = json.loads(communities_json) if isinstance(communities_json, str) else communities_json
            if communities:
                for c in communities:
                    name = c.get("name", "?") if isinstance(c, dict) else c
                    mode = c.get("mode", "?") if isinstance(c, dict) else "?"
                    acl = c.get("acl", "none") if isinstance(c, dict) else "none"
                    lines.append(f"  Community: {name} ({mode}) ACL: {acl}")
            else:
                lines.append("  No SNMP communities configured")
        except (json.JSONDecodeError, TypeError):
            lines.append("  No SNMP communities configured")
        v3_json = sc.get("snmp_v3_users", "[]")
        try:
            v3_users = json.loads(v3_json) if isinstance(v3_json, str) else v3_json
            for u in (v3_users or []):
                if isinstance(u, dict):
                    lines.append(f"  SNMPv3 user: {u.get('name', '?')} auth={u.get('auth', '?')} priv={u.get('priv', '?')}")
        except (json.JSONDecodeError, TypeError):
            pass
        lines.append("")

        # NTP
        lines.append("NTP:")
        lines.append(f"  Authentication: {'yes' if sc.get('ntp_authentication_enabled') else 'no'}")
        lines.append(f"  Servers with key: {sc.get('ntp_servers_with_key', 0)}")
        lines.append("")

        # Logging
        lines.append("Logging:")
        hosts_json = sc.get("logging_hosts", "[]")
        try:
            hosts = json.loads(hosts_json) if isinstance(hosts_json, str) else hosts_json
            if hosts:
                for h in hosts:
                    lines.append(f"  Syslog host: {h}")
            else:
                lines.append("  ⚠ No syslog hosts configured")
        except (json.JSONDecodeError, TypeError):
            lines.append("  ⚠ No syslog hosts configured")
        src = sc.get("logging_source_interface")
        if src:
            lines.append(f"  Source interface: {src}")
        lines.append("")

        # TACACS/RADIUS
        tacacs_json = sc.get("tacacs_radius_tacacs_servers", "[]")
        radius_json = sc.get("tacacs_radius_radius_servers", "[]")
        try:
            tacacs = json.loads(tacacs_json) if isinstance(tacacs_json, str) else tacacs_json
            radius = json.loads(radius_json) if isinstance(radius_json, str) else radius_json
            key = "yes" if sc.get("tacacs_radius_key_configured") else "no"
            lines.append("TACACS/RADIUS:")
            if tacacs:
                lines.append(f"  TACACS servers: {', '.join(str(s) for s in tacacs)}")
            if radius:
                lines.append(f"  RADIUS servers: {', '.join(str(s) for s in radius)}")
            if not tacacs and not radius:
                lines.append("  No TACACS/RADIUS servers")
            lines.append(f"  Key configured: {key}")
            lines.append("")
        except (json.JSONDecodeError, TypeError):
            pass

        # Console/VTY
        timeout = sc.get("console_exec_timeout_minutes")
        if timeout is not None:
            lines.append("Console:")
            lines.append(f"  Exec timeout: {timeout} min")
            lines.append("")

        vty_transport = sc.get("vty_lines_transport_input")
        if vty_transport:
            lines.append("VTY lines:")
            lines.append(f"  transport_input: {vty_transport}")
            acl_in = sc.get("vty_lines_access_class_in")
            if acl_in:
                lines.append(f"  access_class_in: {acl_in}")
            vty_timeout = sc.get("vty_lines_exec_timeout_minutes")
            if vty_timeout is not None:
                lines.append(f"  exec_timeout_minutes: {vty_timeout}")
            lines.append("")

        # Services
        svc_keys = [k for k in sc if k.startswith("services_")]
        if svc_keys:
            lines.append("Services:")
            for k in sorted(svc_keys):
                name = k.replace("services_", "")
                status = "enabled" if sc[k] else "disabled"
                lines.append(f"  {name}: {status}")
            lines.append("")

    elif source == "fortigate":
        # FortiGate — extract from fg_* prefixed properties
        admin_json = sc.get("fg_admin")
        if admin_json:
            try:
                admins = json.loads(admin_json) if isinstance(admin_json, str) else admin_json
                lines.append(f"Admin accounts ({len(admins)}):")
                for a in admins:
                    if isinstance(a, dict):
                        lines.append(f"  {a.get('name', '?')} (profile: {a.get('accprofile', '?')})")
                lines.append("")
            except (json.JSONDecodeError, TypeError):
                pass

        snmp_json = sc.get("fg_snmp")
        if snmp_json:
            try:
                communities = json.loads(snmp_json) if isinstance(snmp_json, str) else snmp_json
                lines.append(f"SNMP communities ({len(communities)}):")
                for c in communities:
                    if isinstance(c, dict):
                        lines.append(f"  {c.get('name', '?')}")
                lines.append("")
            except (json.JSONDecodeError, TypeError):
                pass

        # HA
        ha_mode = sc.get("fg_ha_mode")
        if ha_mode:
            mode_label = {'a-p': 'active-passive', 'a-a': 'active-active'}.get(ha_mode, ha_mode)
            lines.append(f"FortiGate HA:")
            lines.append(f"  Mode: {mode_label}")
            group_name = sc.get("fg_ha_group-name") or sc.get("fg_ha_group_name")
            if group_name:
                lines.append(f"  Group name: {group_name}")
            lines.append("")

    return "\n".join(lines)


def _cisco_posture(device: str, role: str, os_type: str, facts_dir: Path) -> str:
    """Parse security_config.json for Cisco devices."""
    sec_path = facts_dir / "security_config.json"
    if not sec_path.exists():
        return f"No security configuration data for {device}."

    try:
        sec = json.loads(sec_path.read_text())
    except (json.JSONDecodeError, OSError):
        return f"Failed to parse security config for {device}."

    lines = [
        f"Security posture — {device}",
        f"  Role: {role} | OS: {os_type}",
        "",
    ]

    # AAA
    aaa = sec.get("aaa", {})
    lines.append("AAA:")
    if aaa:
        auth = aaa.get("authentication_login_default", "not configured")
        authz = aaa.get("authorization_exec_default", "not configured")
        acct = "yes" if aaa.get("accounting_configured") else "no"
        lines.append(f"  Authentication: {auth}")
        lines.append(f"  Authorization: {authz}")
        lines.append(f"  Accounting: {acct}")
    else:
        lines.append("  ⚠ No AAA configuration")
    lines.append("")

    # SSH
    ssh = sec.get("ssh", {})
    lines.append("SSH:")
    if ssh:
        for k, v in ssh.items():
            lines.append(f"  {k}: {v}")
    else:
        lines.append("  ⚠ No SSH configuration")
    lines.append("")

    # SNMP
    snmp = sec.get("snmp", {})
    lines.append("SNMP:")
    communities = snmp.get("communities", [])
    if communities:
        for c in communities:
            name = c.get("name", "?")
            mode = c.get("mode", "?")
            acl = c.get("acl", "none")
            lines.append(f"  Community: {name} ({mode}) ACL: {acl}")
    else:
        lines.append("  No SNMP communities configured")
    v3_users = snmp.get("v3_users", [])
    if v3_users:
        for u in v3_users:
            lines.append(f"  SNMPv3 user: {u.get('name', '?')} auth={u.get('auth', '?')} priv={u.get('priv', '?')}")
    lines.append("")

    # NTP
    ntp = sec.get("ntp", {})
    lines.append("NTP:")
    auth = "yes" if ntp.get("authentication_enabled") else "no"
    lines.append(f"  Authentication: {auth}")
    servers = ntp.get("servers_with_key", 0)
    lines.append(f"  Servers with key: {servers}")
    lines.append("")

    # Logging
    logging_cfg = sec.get("logging", {})
    lines.append("Logging:")
    hosts = logging_cfg.get("hosts", [])
    if hosts:
        for h in hosts:
            lines.append(f"  Syslog host: {h}")
    else:
        lines.append("  ⚠ No syslog hosts configured")
    src = logging_cfg.get("source_interface", "")
    if src:
        lines.append(f"  Source interface: {src}")
    lines.append("")

    # TACACS/RADIUS
    tacrad = sec.get("tacacs_radius", {})
    if tacrad:
        tacacs = tacrad.get("tacacs_servers", [])
        radius = tacrad.get("radius_servers", [])
        key = "yes" if tacrad.get("key_configured") else "no"
        lines.append("TACACS/RADIUS:")
        if tacacs:
            lines.append(f"  TACACS servers: {', '.join(tacacs)}")
        if radius:
            lines.append(f"  RADIUS servers: {', '.join(radius)}")
        if not tacacs and not radius:
            lines.append("  No TACACS/RADIUS servers")
        lines.append(f"  Key configured: {key}")
        lines.append("")

    # HTTP server
    http = sec.get("http_server", {})
    if http:
        lines.append("HTTP/HTTPS:")
        for k, v in http.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

    # Console/VTY
    console = sec.get("console", {})
    if console:
        lines.append("Console:")
        timeout = console.get("exec_timeout_minutes", "?")
        lines.append(f"  Exec timeout: {timeout} min")
        lines.append("")

    vty = sec.get("vty_lines", {})
    if vty:
        lines.append("VTY lines:")
        for k, v in vty.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

    # Services
    services = sec.get("services", {})
    if services:
        lines.append("Services:")
        for k, v in services.items():
            status = "enabled" if v else "disabled"
            lines.append(f"  {k}: {status}")
        lines.append("")

    # Password policy
    pw = sec.get("password_policy", {})
    if pw:
        lines.append("Password policy:")
        for k, v in pw.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

    # Banner
    banner = sec.get("banner", {})
    if banner:
        has_login = bool(banner.get("login"))
        has_motd = bool(banner.get("motd"))
        lines.append(f"Banner: login={'yes' if has_login else 'no'} motd={'yes' if has_motd else 'no'}")
        lines.append("")

    return "\n".join(lines)


def _fortigate_posture(device: str, role: str, facts_dir: Path) -> str:
    """Parse FortiGate security files."""
    lines = [
        f"Security posture — {device}",
        f"  Role: {role} | OS: fortios",
        "",
    ]

    # Admin accounts
    admin_path = facts_dir / "fortigate_system_admin.json"
    if admin_path.exists():
        try:
            data = json.loads(admin_path.read_text())
            admins = data.get("results", [])
            vdom = data.get("vdom", "")
            lines.append(f"Admin accounts ({len(admins)}):")
            if admins:
                for a in admins:
                    name = a.get("name", "?")
                    prof = a.get("accprofile", "?")
                    lines.append(f"  {name} (profile: {prof})")
            else:
                lines.append("  None found (may require global-scope API token)")
            lines.append("")
        except (json.JSONDecodeError, OSError):
            pass

    # SNMP
    snmp_path = facts_dir / "fortigate_snmp_community.json"
    if snmp_path.exists():
        try:
            data = json.loads(snmp_path.read_text())
            communities = data.get("results", [])
            vdom = data.get("vdom", "")
            lines.append(f"SNMP communities ({len(communities)}):")
            if communities:
                for c in communities:
                    name = c.get("name", "?")
                    lines.append(f"  {name}")
            else:
                lines.append("  None found (may require global-scope API token)")
            lines.append("")
        except (json.JSONDecodeError, OSError):
            pass

    # NTP
    ntp_path = facts_dir / "fortigate_system_ntp.json"
    if ntp_path.exists():
        try:
            data = json.loads(ntp_path.read_text())
            results = data.get("results", data)
            if isinstance(results, dict):
                sync = results.get("ntpsync", "?")
                lines.append(f"NTP: sync={sync}")
                servers = results.get("ntpserver", [])
                for s in servers:
                    lines.append(f"  Server: {s.get('server', '?')}")
            lines.append("")
        except (json.JSONDecodeError, OSError):
            pass

    # Password policy
    pw_path = facts_dir / "fortigate_password_policy.json"
    if pw_path.exists():
        try:
            data = json.loads(pw_path.read_text())
            results = data.get("results", data)
            if isinstance(results, dict):
                lines.append("Password policy:")
                lines.append(f"  Status: {results.get('status', '?')}")
                lines.append(f"  Min length: {results.get('minimum-length', '?')}")
                lines.append(f"  Apply to: {results.get('apply-to', '?')}")
            lines.append("")
        except (json.JSONDecodeError, OSError):
            pass

    # HA status
    ha_path = facts_dir / "fortigate_system_ha.json"
    if ha_path.exists():
        try:
            data = json.loads(ha_path.read_text())
            results = data.get("results", data)
            if isinstance(results, dict):
                mode = results.get('mode', '?')
                mode_label = {'a-p': 'active-passive', 'a-a': 'active-active'}.get(mode, mode)
                lines.append(f"FortiGate HA:")
                lines.append(f"  Mode: {mode_label}")
                lines.append(f"  Group name: {results.get('group-name', '?')}")
            lines.append("")
        except (json.JSONDecodeError, OSError):
            pass

    return "\n".join(lines)


async def _network_overview(run_id: str, data_dir: str, driver) -> str:
    """Network-wide security overview from Neo4j SecurityConfig nodes."""
    lines = ["Security posture — Network overview", ""]

    with driver.session() as session:
        # Query all devices with optional SecurityConfig join
        result = session.run(
            "MATCH (d:Device {run_id: $run_id}) "
            "WHERE d.role IS NOT NULL "
            "OPTIONAL MATCH (d)-[:HAS_SECURITY_CONFIG]->(sc:SecurityConfig) "
            "RETURN d.name AS name, d.os_type AS os, d.role AS role, "
            "properties(sc) AS sc "
            "ORDER BY d.name",
            run_id=run_id,
        )
        devices = [dict(r) for r in result]

    aaa_ok = 0
    aaa_missing = []
    snmp_v2 = []
    ntp_no_auth = []
    no_logging = []
    no_banner = []
    no_data = []
    fortios_devices = []
    tacacs_servers: set[str] = set()
    tacacs_key_missing = []

    for dev in devices:
        name = dev["name"]
        os_type = dev["os"] or ""
        sc = dev["sc"]

        if os_type == "fortios":
            fortios_devices.append(name)
            continue

        if not sc:
            no_data.append(name)
            continue

        # AAA
        if sc.get("aaa_authentication_login_default"):
            aaa_ok += 1
        else:
            aaa_missing.append(name)

        # SNMP v2 communities
        communities_json = sc.get("snmp_communities", "[]")
        try:
            communities = json.loads(communities_json) if isinstance(communities_json, str) else communities_json
            if communities:
                snmp_v2.append(name)
        except (json.JSONDecodeError, TypeError):
            pass

        # TACACS/RADIUS
        tacacs_json = sc.get("tacacs_radius_tacacs_servers", "[]")
        try:
            tacacs = json.loads(tacacs_json) if isinstance(tacacs_json, str) else tacacs_json
            for srv in (tacacs or []):
                tacacs_servers.add(str(srv))
            if tacacs and not sc.get("tacacs_radius_key_configured"):
                tacacs_key_missing.append(name)
        except (json.JSONDecodeError, TypeError):
            pass

        # NTP auth
        if not sc.get("ntp_authentication_enabled"):
            ntp_no_auth.append(name)

        # Logging
        hosts_json = sc.get("logging_hosts", "[]")
        try:
            hosts = json.loads(hosts_json) if isinstance(hosts_json, str) else hosts_json
            if not hosts:
                no_logging.append(name)
        except (json.JSONDecodeError, TypeError):
            no_logging.append(name)

        # Banner
        if not sc.get("banner_login_present") and not sc.get("banner_motd_present"):
            no_banner.append(name)

    analyzed = aaa_ok + len(aaa_missing)
    lines.append(f"Cisco devices analyzed: {analyzed}")
    if fortios_devices:
        lines.append(f"FortiGate devices: {', '.join(fortios_devices)} (use per-device query)")
    if no_data:
        lines.append(f"No security data: {', '.join(no_data)} (unreachable or not collected)")
    lines.append(f"AAA configured: {aaa_ok}/{analyzed}")
    if tacacs_servers:
        lines.append(f"TACACS servers: {', '.join(sorted(tacacs_servers))}")
    lines.append("")

    if aaa_missing:
        lines.append(f"⚠ No AAA ({len(aaa_missing)}): {', '.join(aaa_missing)}")
    if snmp_v2:
        lines.append(f"⚠ SNMPv2 communities ({len(snmp_v2)}): {', '.join(snmp_v2)}")
    if ntp_no_auth:
        lines.append(f"⚠ NTP no auth ({len(ntp_no_auth)}): {', '.join(ntp_no_auth)}")
    if no_logging:
        lines.append(f"⚠ No syslog ({len(no_logging)}): {', '.join(no_logging)}")
    if no_banner:
        lines.append(f"⚠ No banner ({len(no_banner)}): {', '.join(no_banner)}")
    if tacacs_key_missing:
        lines.append(f"⚠ TACACS key missing ({len(tacacs_key_missing)}): {', '.join(tacacs_key_missing)}")

    if not aaa_missing and not snmp_v2 and not ntp_no_auth and not no_logging:
        lines.append("✓ No critical security gaps detected")

    lines.append("")
    lines.append("Use get_security_posture(device=\"<name>\") for per-device detail.")

    return "\n".join(lines)
