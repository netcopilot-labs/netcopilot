"""F2-5q: cisco_native BGP running-config parser (IOS XE + IOS XR).

parse_bgp_process_config extracts process + per-neighbor settings Genie misses
(route policies, BFD, password presence, maximum-prefix, network statements).
Synthetic ASNs (private 65000/64500) + RFC 5737 IPs.
"""

from netcopilot.parse.cisco_native.bgp_config import parse_bgp_process_config

XE_CONFIG = """\
!
router bgp 65000
 bgp router-id 203.0.113.1
 bgp log-neighbor-changes
 neighbor 198.51.100.2 remote-as 64500
 neighbor 198.51.100.2 description UPSTREAM-ISP
 neighbor 198.51.100.2 fall-over bfd
 neighbor 198.51.100.2 password 7 REDACTED
 address-family ipv4
  neighbor 198.51.100.2 activate
  neighbor 198.51.100.2 route-map PEER-IN in
  neighbor 198.51.100.2 route-map ADVERTISE-PREFIXES out
  network 203.0.113.0 mask 255.255.255.0
 exit-address-family
!
"""

XR_CONFIG = """\
!
router bgp 65000
 bgp router-id 203.0.113.1
 neighbor 198.51.100.2
  remote-as 64500
  description UPSTREAM-ISP
  bfd fast-detect
  address-family ipv4 unicast
   route-policy PEER-IN in
   route-policy ADVERTISE-PREFIXES out
   maximum-prefix 1000000
  !
 !
!
"""


def test_parse_bgp_xe():
    cfg = parse_bgp_process_config(XE_CONFIG)
    assert cfg["as_number"] == 65000
    assert cfg["router_id"] == "203.0.113.1"
    assert cfg["log_neighbor_changes"] is True
    assert cfg["network_statements"] == ["203.0.113.0"]
    nbr = cfg["neighbors"]["198.51.100.2"]
    assert nbr["remote_as"] == 64500
    assert nbr["description"] == "UPSTREAM-ISP"
    assert nbr["bfd"] is True
    assert nbr["password_configured"] is True
    assert nbr["route_policy_in"] == "PEER-IN"
    assert nbr["route_policy_out"] == "ADVERTISE-PREFIXES"


def test_parse_bgp_xr():
    cfg = parse_bgp_process_config(XR_CONFIG)
    assert cfg["as_number"] == 65000
    nbr = cfg["neighbors"]["198.51.100.2"]
    assert nbr["remote_as"] == 64500
    assert nbr["bfd"] is True
    assert nbr["route_policy_in"] == "PEER-IN"
    assert nbr["route_policy_out"] == "ADVERTISE-PREFIXES"
    assert nbr["maximum_prefix"] == 1000000


def test_parse_bgp_none_without_router_bgp():
    assert parse_bgp_process_config("!\nhostname x\n!\n") is None


# Route-reflector config — genie omits route-reflector-client (config-only) and
# an unset cluster-id, so the running-config parser is the only source.

XE_RR_CONFIG = """\
!
router bgp 64496
 bgp router-id 198.51.100.100
 bgp cluster-id 198.51.100.100
 neighbor 198.51.100.101 remote-as 64496
 neighbor 198.51.100.101 update-source Loopback0
 address-family ipv4
  neighbor 198.51.100.101 activate
  neighbor 198.51.100.101 route-reflector-client
 exit-address-family
!
"""

XR_RR_CONFIG = """\
!
router bgp 64496
 bgp router-id 198.51.100.100
 bgp cluster-id 198.51.100.100
 neighbor 198.51.100.101
  remote-as 64496
  update-source Loopback0
  address-family ipv4 unicast
   route-reflector-client
  !
 !
!
"""


def test_parse_bgp_xe_route_reflector():
    cfg = parse_bgp_process_config(XE_RR_CONFIG)
    assert cfg["cluster_id"] == "198.51.100.100"
    assert cfg["neighbors"]["198.51.100.101"]["route_reflector_client"] is True


def test_parse_bgp_xr_route_reflector():
    cfg = parse_bgp_process_config(XR_RR_CONFIG)
    assert cfg["cluster_id"] == "198.51.100.100"
    assert cfg["neighbors"]["198.51.100.101"]["route_reflector_client"] is True


def test_parse_bgp_non_rr_client_defaults_false():
    # The plain XE config (no route-reflector-client) → flag defaults False,
    # cluster-id absent → None.
    cfg = parse_bgp_process_config(XE_CONFIG)
    assert cfg["cluster_id"] is None
    assert cfg["neighbors"]["198.51.100.2"]["route_reflector_client"] is False
    # R1-BGP-2: no allowas-in here → absent on the neighbor.
    assert "allowas_in" not in cfg["neighbors"]["198.51.100.2"]


def test_parse_bgp_xr_allowas_in():
    # R1-BGP-2: XR `allowas-in N` inside the neighbor address-family was dropped.
    cfg = parse_bgp_process_config("""\
router bgp 65000
 neighbor 198.51.100.2
  remote-as 64500
  address-family ipv4 unicast
   allowas-in 3
  !
 !
!
""")
    nbr = cfg["neighbors"]["198.51.100.2"]
    assert nbr["allowas_in"] is True
    assert nbr["allowas_in_number"] == 3


def test_parse_bgp_xe_allowas_in():
    # R1-BGP-2: XE flat AF `neighbor X allowas-in [N]`.
    cfg = parse_bgp_process_config("""\
router bgp 65000
 neighbor 198.51.100.2 remote-as 64500
 address-family ipv4
  neighbor 198.51.100.2 allowas-in
 exit-address-family
!
""")
    nbr = cfg["neighbors"]["198.51.100.2"]
    assert nbr["allowas_in"] is True
    assert "allowas_in_number" not in nbr  # no count given


def test_parse_bgp_redistribute_route_map():
    # R1-BGP-3: the `route-map <name>` qualifier was dropped; redistribute list
    # shape stays unchanged, the binding is captured additively.
    cfg = parse_bgp_process_config("""\
router bgp 65000
 address-family ipv4
  redistribute connected route-map CONN-TO-BGP
  redistribute static
 exit-address-family
!
""")
    assert cfg["redistribute"] == ["connected", "static"]   # shape unchanged
    assert cfg["redistribute_route_maps"] == {"connected": "CONN-TO-BGP"}
