"""F2-5p: cisco_native OSPF running-config parser.

parse_ospf_process_configs extracts process-level OSPF config Genie's
learn('ospf') misses: area types (incl. totally-*), passive-default +
exceptions, capability vrf-lite, redistribute.
"""

from netcopilot.parse.cisco_native.ospf_config import parse_ospf_process_configs

CONFIG = """\
!
router ospf 1
 router-id 203.0.113.1
 area 2 stub no-summary
 area 5 nssa
 passive-interface default
 no passive-interface Vlan10
 capability vrf-lite
 redistribute connected
 redistribute static
!
router ospf 2 vrf TENANT-VRF
 area 7 nssa
!
interface Vlan10
 ip ospf 1 area 2
!
"""


def test_parse_ospf_process_configs():
    cfgs = parse_ospf_process_configs(CONFIG)
    # default-VRF process 100
    p100 = cfgs[("1", "default")]
    assert p100["area_types"] == {2: "totally-stub", 5: "nssa"}
    assert p100["passive_default"] is True
    assert p100["active_interfaces"] == ["Vlan10"]
    assert p100["capability_vrf_lite"] is True
    assert p100["redistribute"] == ["connected", "static"]
    # vrf process 200
    p200 = cfgs[("2", "TENANT-VRF")]
    assert p200["area_types"] == {7: "nssa"}
    assert p200["passive_default"] is False


def test_parse_ospf_empty():
    assert parse_ospf_process_configs("!\nhostname x\n!\n") == {}
