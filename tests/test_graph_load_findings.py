"""F3h: findings loader — findings/findings.json → Finding nodes (fake driver).

Closes the F2-6 deferral: the rules layer writes findings.json, and load_model
now materialises Finding nodes linked to their Device via HAS_FINDING.
"""

import json

from netcopilot.graph.loader import (
    _derive_category,
    _devices_from_element_id,
    _load_findings,
)
from test_graph_load_model import FakeDriver

SITE, RUN = "dc", "r1"


def test_devices_from_element_id():
    assert _devices_from_element_id("core-rtr-01") == ["core-rtr-01"]
    assert _devices_from_element_id("core-rtr-01:Gi0/1") == ["core-rtr-01"]
    # link finding: two devices
    assert _devices_from_element_id("core-rtr-01:Hu0/0--dist-sw-01:Hu0/1") == ["core-rtr-01", "dist-sw-01"]


def test_derive_category():
    assert _derive_category("BGP_NEIGHBOR_DOWN") == "bgp"
    assert _derive_category("CIS_XE_2_1_SSH") == "security"
    assert _derive_category("WIDGET_FROBNICATE") == "other"


def _write_findings(run_dir, findings):
    d = run_dir / "findings"
    d.mkdir(parents=True)
    (d / "findings.json").write_text(json.dumps({"metadata": {"run_id": RUN}, "findings": findings}))


def test_load_findings_creates_finding_nodes(tmp_path):
    run = tmp_path / "run"
    _write_findings(run, [
        {"finding_id": "NTP_OFFSET::core-rtr-01", "rule_id": "NTP_OFFSET", "severity": "high",
         "title": "NTP Offset", "message": "drift", "recommendation": "fix",
         "detected_at": "2026-01-15T00:00:00Z",
         "evidence": {"element_type": "device", "element_id": "core-rtr-01",
                      "key_facts": {"offset_ms": 600}}},
    ])
    driver = FakeDriver()
    n = _load_findings(driver, run, SITE, RUN)
    assert n == 1
    params = next(p["findings"] for c, p in driver.calls if "[:HAS_FINDING]" in c and "CREATE" in c)
    fin = params[0]
    assert fin["finding_id"] == "NTP_OFFSET::core-rtr-01"
    assert fin["device"] == "core-rtr-01" and fin["severity"] == "high"
    assert fin["category"] == "other"             # NTP_ prefix not in category map → other
    assert fin["kf_offset_ms"] == 600             # key_facts flattened to kf_*


def test_load_findings_cross_device_secondary_rels(tmp_path):
    run = tmp_path / "run"
    _write_findings(run, [
        {"finding_id": "BGP_PEER_AS_MISMATCH::core-rtr-01:Hu0--dist-sw-01:Hu1",
         "rule_id": "BGP_PEER_AS_MISMATCH", "severity": "high", "title": "AS mismatch",
         "message": "m", "recommendation": "r", "detected_at": "x",
         "evidence": {"element_type": "link",
                      "element_id": "core-rtr-01:Hu0--dist-sw-01:Hu1", "key_facts": {}}},
    ])
    driver = FakeDriver()
    _load_findings(driver, run, SITE, RUN)
    fin = next(p["findings"] for c, p in driver.calls if "[:HAS_FINDING]" in c and "CREATE" in c)[0]
    assert fin["cross_device"] is True
    assert "dist-sw-01" in fin["involved_devices"]
    # a secondary HAS_FINDING MERGE for the second device
    assert any("MERGE (d)-[:HAS_FINDING]" in c for c, _ in driver.calls)


def test_load_findings_no_file_returns_zero(tmp_path):
    assert _load_findings(FakeDriver(), tmp_path / "empty", SITE, RUN) == 0
