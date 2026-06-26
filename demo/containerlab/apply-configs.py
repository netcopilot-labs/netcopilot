#!/usr/bin/env python3
"""Apply the device configs to the deployed Containerlab demo, post-boot.

The nodes boot config-less (see topology.clab.yml); this script applies the
per-device routing configs over the management network with netmiko, *additively*,
so Containerlab's auto-injected management/SSH setup is preserved on every node.
Run it once the lab is deployed and the nodes are healthy:

    python3 -m venv venv && . venv/bin/activate && pip install netmiko
    ./apply-configs.py

Why post-boot instead of Containerlab startup-config: the serial-console
startup-config push is unreliable on these heavy images — it drops the scrapli
session on xrv9k under load and truncates on cat9kv (the routing section is
silently lost). Booting config-less keeps clab's mgmt/SSH setup intact.

Credentials: the IOS-XR border routers connect with the vrnetlab default
clab/clab@123 (their config then adds an admin/admin user); every other node
uses admin/admin. After this runs, all 12 devices accept admin/admin.
"""
import os
import sys

from netmiko import ConnectHandler

HERE = os.path.dirname(os.path.abspath(__file__))

# name, mgmt_ip, netmiko device_type, (username, password) for the first connect
DEVICES = [
    ("bdr-rtr-01", "192.0.2.11", "cisco_xr",  ("clab", "clab@123")),
    ("bdr-rtr-02", "192.0.2.12", "cisco_xr",  ("clab", "clab@123")),
    ("bdr-rtr-03", "192.0.2.13", "cisco_xr",  ("clab", "clab@123")),
    ("isp-01",     "192.0.2.21", "cisco_xr",  ("clab", "clab@123")),
    ("isp-02",     "192.0.2.22", "cisco_xr",  ("clab", "clab@123")),
    ("isp-03",     "192.0.2.23", "cisco_xr",  ("clab", "clab@123")),
    ("core-sw-01", "192.0.2.31", "cisco_xe",  ("admin", "admin")),
    ("acc-sw-01",  "192.0.2.41", "cisco_xe",  ("admin", "admin")),
    ("acc-sw-03",  "192.0.2.43", "cisco_xe",  ("admin", "admin")),
    ("acc-sw-04",  "192.0.2.44", "cisco_xe",  ("admin", "admin")),
    ("edge-fw-01", "192.0.2.51", "fortinet",  ("admin", "admin")),
]


def config_lines(name):
    with open(os.path.join(HERE, "configs", f"{name}.cfg")) as fh:
        return [ln.rstrip() for ln in fh if ln.strip() and ln.strip() != "end"]


def main():
    failed = []
    for name, ip, dtype, (user, pw) in DEVICES:
        print(f"==> {name} ({ip}, {dtype})", flush=True)
        try:
            conn = ConnectHandler(
                device_type=dtype, host=ip, username=user, password=pw,
                fast_cli=False, conn_timeout=45, banner_timeout=45, auth_timeout=45,
            )
            lines = config_lines(name)
            if dtype == "cisco_xr":
                conn.send_config_set(lines, exit_config_mode=False, read_timeout=180)
                conn.commit()
                conn.exit_config_mode()
            elif dtype == "fortinet":
                # FortiOS config-over-SSH is occasionally flaky (commands sent
                # but not applied); verify a known line landed and retry once.
                conn.send_config_set(lines, read_timeout=180, cmd_verify=False)
                if "0.0.0.0" in conn.send_command("show system interface port2"):
                    conn.send_config_set(lines, read_timeout=180, cmd_verify=False)
            else:
                conn.send_config_set(lines, read_timeout=180)
                conn.save_config()
            conn.disconnect()
            print(f"    {name} OK")
        except Exception as exc:  # noqa: BLE001 - report and continue
            print(f"    {name} FAILED: {type(exc).__name__}: {str(exc)[:160]}")
            failed.append(name)

    print("\ndone. Allow ~60s for OSPF/BGP to converge, then verify.")
    if failed:
        print(f"FAILED: {', '.join(failed)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
