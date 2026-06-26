"""F3e: Phase-1 CIS compliance rules (Cisco IOS XE / IOS XR, FortiGate).

Contract (the full CIS set is discovered) + a behavioral check for a config-
based CIS rule (IOS XE SSH hardening) proving the load_running_config path.
Clean-evaluate of all rules is covered by test_rules_topology's all-rules loop.
The engine post-processes CIS findings to severity='cis' (covered in F3b).
"""

from netcopilot.rules.discovery import discover_rules, get_rule_by_id


def test_cis_rule_families_present():
    ids = {r.rule_id for r in discover_rules()}
    cis = {i for i in ids if i.startswith("CIS_")}
    assert len(cis) >= 60                                  # the full CIS set
    assert any(i.startswith("CIS_XE_") for i in cis)       # Cisco IOS XE
    assert any(i.startswith("CIS_XR_") for i in cis)       # Cisco IOS XR
    assert any(i.startswith("CIS_FG_") for i in cis)       # FortiGate


def test_full_phase1_rule_set():
    # F3c (~34) + F3d (~69) + F3e CIS (~68)
    assert len(discover_rules()) >= 170


def test_cis_rules_declare_non_cis_severity():
    # rules declare ∈ {critical,high,low,info}; 'cis' is engine-applied, not declared
    for r in discover_rules():
        if r.rule_id.startswith("CIS_"):
            assert r.severity in {"critical", "high", "low", "info"}


def test_cis_xe_ssh_behavioral(tmp_path):
    rule = get_rule_by_id("CIS_XE_2_1_SSH")
    model = {"devices": [
        {"hostname": "core-rtr-01", "os_family": "iosxe"},   # incomplete SSH config → fires
        {"hostname": "dist-sw-01", "os_family": "iosxe"},    # complete → no finding
        {"hostname": "fw-01", "os_family": "fortios"},        # not iosxe → skipped
    ], "interfaces": [], "links": []}
    run = tmp_path / "run"
    configs = {
        "core-rtr-01": "hostname core-rtr-01\n",  # no 'ip ssh version 2', no 'ip domain'
        "dist-sw-01": "hostname dist-sw-01\nip ssh version 2\nip domain name example.com\n",
        "fw-01": "config system global\n",
    }
    for host, cfg in configs.items():
        d = run / "facts" / host
        d.mkdir(parents=True)
        (d / "running_config.txt").write_text(cfg)

    findings = rule.evaluate(model, {"run_id": "r1", "run_path": str(run), "manifest": {}})
    flagged = {f.evidence["element_id"] for f in findings}
    assert flagged == {"core-rtr-01"}   # only the incomplete iosxe device
