#!/usr/bin/env python3
"""Apply the campus-ha config overlays onto the running base lab.

Reads overlays/<device>.txt and pushes each over SSH (netmiko). Device mgmt
reachability + admin/admin (override via NETCOPILOT_SSH_USERNAME/PASSWORD).

acc-sw-03 enables `aaa new-model` (dot1x prerequisite) on a device that ran
`no aaa new-model`, which can lock out vty. It is pushed with a lifeline: the
config session is held open while a *fresh* login is verified; if the fresh
login fails, `no aaa new-model` is rolled back over the still-open session.
The FortiGate is never touched.
"""
import os
import sys
from pathlib import Path

from netmiko import ConnectHandler

USER = os.environ.get("NETCOPILOT_SSH_USERNAME", "admin")
PWD = os.environ.get("NETCOPILOT_SSH_PASSWORD", "admin")
OVERLAYS = Path(__file__).resolve().parent / "overlays"

# (name, mgmt_ip, netmiko_device_type, uses_aaa_lifeline)
DEVICES = [
    ("bdr-rtr-01", "192.0.2.11", "cisco_xr", False),
    ("bdr-rtr-02", "192.0.2.12", "cisco_xr", False),
    ("core-sw-01", "192.0.2.31", "cisco_xe", False),
    ("acc-sw-04", "192.0.2.44", "cisco_xe", False),
    ("acc-sw-03", "192.0.2.43", "cisco_xe", True),   # aaa new-model -> lifeline
]


def load_overlay(name):
    lines = (OVERLAYS / f"{name}.txt").read_text().splitlines()
    # drop pure-comment and blank lines; keep real config (indentation preserved)
    return [ln for ln in lines if ln.strip() and not ln.strip().startswith("!")]


def base_kwargs(ip, dtype):
    return dict(device_type=dtype, host=ip, username=USER, password=PWD,
                fast_cli=False, conn_timeout=30, banner_timeout=30, auth_timeout=30)


def push_plain(name, ip, dtype, cfg):
    conn = ConnectHandler(**base_kwargs(ip, dtype))
    out = conn.send_config_set(cfg, read_timeout=120)
    if dtype == "cisco_xr":
        out += "\n" + conn.commit()   # IOS-XR needs an explicit commit
    conn.disconnect()
    return out


def push_with_lifeline(name, ip, dtype, cfg):
    conn = ConnectHandler(**base_kwargs(ip, dtype))          # lifeline session
    out = conn.send_config_set(cfg, read_timeout=120)
    try:
        verify = ConnectHandler(**base_kwargs(ip, dtype))    # fresh login test
        verify.disconnect()
        conn.disconnect()
        return out + "\n[lifeline] fresh login OK"
    except Exception as e:
        rollback = conn.send_config_set(["no aaa new-model"], read_timeout=60)
        conn.disconnect()
        raise RuntimeError(
            f"fresh login FAILED after aaa change ({e}); rolled back "
            f"'no aaa new-model'. Rollback output:\n{rollback}")


def main():
    rc = 0
    for name, ip, dtype, lifeline in DEVICES:
        cfg = load_overlay(name)
        try:
            fn = push_with_lifeline if lifeline else push_plain
            out = fn(name, ip, dtype, cfg)
            bad = [l for l in out.splitlines()
                   if "% " in l or "Invalid" in l or "rejected" in l.lower()]
            tag = "WARN" if bad else "OK"
            print(f"[{tag}] {name} ({ip}) — {len(cfg)} lines pushed")
            for l in bad:
                print(f"        ! {l.strip()}")
            if bad:
                rc = 1
        except Exception as e:
            print(f"[FAIL] {name} ({ip}) — {e}")
            rc = 2
    return rc


if __name__ == "__main__":
    sys.exit(main())
