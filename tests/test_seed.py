"""F1-3: the synthetic seed is well-formed and references are consistent (no Neo4j)."""

import ipaddress
import json
from pathlib import Path

SEED = Path(__file__).resolve().parents[1] / "fixtures" / "seed.json"


def _seed() -> dict:
    return json.loads(SEED.read_text())


def test_seed_is_consistent():
    data = _seed()
    assert data["site"] and data["run_id"]
    assert len(data["devices"]) >= 3
    names = {d["name"] for d in data["devices"]}
    for i in data["interfaces"]:
        assert i["device"] in names
    for link in data["links"]:
        assert link["a"] in names and link["b"] in names
    for adj in data["adjacencies"]:
        assert adj["a"] in names and adj["b"] in names
    for f in data["findings"]:
        assert f["device"] in names
        assert f["finding_id"] and f["rule_id"] and f["severity"]


def test_seed_uses_documentation_ips_only():
    # RFC 5737 documentation ranges — never a real address.
    doc_nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for d in _seed()["devices"]:
        ip = d.get("mgmt_ip")
        if not ip:
            continue
        addr = ipaddress.ip_address(ip)
        assert any(addr in net for net in doc_nets), f"{ip} is not a documentation IP"
