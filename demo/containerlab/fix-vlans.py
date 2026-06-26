#!/usr/bin/env python3
"""Push the VLAN-naming cleanup to the RUNNING demo lab — live, no redeploy.

Run this ON THE LAB HOST (where the containerlab mgmt net 192.0.2.0/24 is
reachable; `ping 192.0.2.43` should answer). It fixes the two config-hygiene
defects without rebuilding the lab:

  * acc-sw-01: renumber the user VLAN 10 (USERS-A) -> 50 (GUEST-USERS) so it no
    longer collides with the TRANSIT-RED transit VLAN.
  * acc-sw-03: rename 30 USERS-RED -> RED-USERS-CAMPUS, 31 USERS-BLUE -> BLUE-USERS-CAMPUS.
  * acc-sw-04: rename 40 USERS-BLUE -> BLUE-USERS-BRANCH (kills the duplicate name).

Usage (on the lab host):
    python3 -m venv venv && . venv/bin/activate && pip install netmiko
    python3 fix-vlans.py
    # then re-collect with NetCopilot and reload the dashboard.

Safe to re-run: the renames re-apply idempotently; the acc-sw-01 block no-ops
once vlan 10 is already gone.
"""
from netmiko import ConnectHandler

USER, PW = "admin", "admin"

PUSH = {
    "acc-sw-01": ("192.0.2.41", [
        "vlan 50", " name GUEST-USERS",
        "interface GigabitEthernet1/0/2", " switchport access vlan 50",
        "interface Vlan10", " shutdown", " no ip address",
        "interface Vlan50", " description GUEST-USERS gateway",
        " ip address 198.51.100.49 255.255.255.240", " no shutdown",
        "router ospf 1", " no passive-interface Vlan10", " passive-interface Vlan50",
        "exit", "no interface Vlan10", "no vlan 10",
    ]),
    "acc-sw-03": ("192.0.2.43", [
        "vlan 30", " name RED-USERS-CAMPUS",
        "vlan 31", " name BLUE-USERS-CAMPUS",
        "interface Vlan30", " description RED-USERS-CAMPUS gateway",
        "interface Vlan31", " description BLUE-USERS-CAMPUS gateway",
    ]),
    "acc-sw-04": ("192.0.2.44", [
        "vlan 40", " name BLUE-USERS-BRANCH",
        "interface Vlan40", " description BLUE-USERS-BRANCH gateway",
    ]),
}


def main() -> None:
    for name, (ip, cmds) in PUSH.items():
        print(f"== {name} ({ip}) ==")
        conn = ConnectHandler(
            device_type="cisco_xe", host=ip,
            username=USER, password=PW, fast_cli=False,
        )
        print(conn.send_config_set(cmds))
        conn.save_config()
        conn.disconnect()
    print("\nDONE. Now re-collect with NetCopilot and reload the dashboard.")


if __name__ == "__main__":
    main()
