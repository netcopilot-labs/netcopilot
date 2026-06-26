"""F4a-1: SessionAnonymizer — deterministic scrub + round-trip fidelity.

Synthetic data only (RFC 5737 documentation IPs, RFC 6996 private ASNs,
generic device/site names) — never real network identifiers.
"""

from netcopilot.anonymizer import SessionAnonymizer


def test_hostname_replaced():
    anon = SessionAnonymizer()
    anon.register_device("core-rtr-01")
    result = anon.anonymize("Device core-rtr-01 is down")
    assert "core-rtr-01" not in result
    assert "device-1" in result


def test_ip_address_replaced():
    anon = SessionAnonymizer()
    result = anon.anonymize("IP 192.0.2.101 is unreachable")
    assert "192.0.2.101" not in result
    assert "10.0.0." in result


def test_route_prefix_not_replaced():
    anon = SessionAnonymizer()
    result = anon.anonymize("default route 0.0.0.0 via 192.0.2.1")
    assert "0.0.0.0" in result          # route prefix preserved
    assert "192.0.2.1" not in result    # real host scrubbed


def test_site_name_replaced():
    anon = SessionAnonymizer()
    anon.register_site("hq")
    result = anon.anonymize("Site hq has issues")
    assert "site-A" in result


def test_two_hostnames_distinct_labels():
    anon = SessionAnonymizer()
    anon.register_device("core-rtr-01")
    anon.register_device("core-rtr-02")
    result = anon.anonymize("core-rtr-01 connects to core-rtr-02")
    assert "device-1" in result and "device-2" in result


def test_mapping_deterministic_within_session():
    anon = SessionAnonymizer()
    anon.register_device("core-rtr-01")
    assert anon.anonymize("core-rtr-01") == anon.anonymize("core-rtr-01")


def test_round_trip_fidelity():
    anon = SessionAnonymizer()
    anon.register_device("core-rtr-01")
    anon.register_device("dist-sw-01")
    anon.register_site("hq")
    original = "Device core-rtr-01 at 192.0.2.101 connects to dist-sw-01 in site hq"
    restored = anon.deanonymize(anon.anonymize(original))
    assert restored == original


def test_multiple_ips_get_distinct_labels():
    anon = SessionAnonymizer()
    result = anon.anonymize("192.0.2.101 and 192.0.2.102")
    assert "10.0.0.1" in result and "10.0.0.2" in result


def test_asn_both_forms_scrubbed():
    anon = SessionAnonymizer()
    anon.register_asn("AS65010")
    result = anon.anonymize("peer AS65010 advertises via 65010")
    assert "65010" not in result
    assert "AS64501" in result


def test_vrf_default_preserved():
    anon = SessionAnonymizer()
    assert anon.register_vrf("default") == "default"
    label = anon.register_vrf("CUSTOMER-A")
    assert label == "vrf-1"


def test_credentials_scrubbed_and_restored():
    anon = SessionAnonymizer()
    anonymized = anon.anonymize("login password: s3cr3t-pw")
    assert "s3cr3t-pw" not in anonymized
    assert "[CREDENTIAL-1]" in anonymized
    assert "s3cr3t-pw" in anon.deanonymize(anonymized)


def test_empty_text():
    anon = SessionAnonymizer()
    assert anon.anonymize("") == ""
    assert anon.deanonymize("") == ""


def test_summary_counts():
    anon = SessionAnonymizer()
    anon.register_device("core-rtr-01")
    anon.anonymize("core-rtr-01 at 192.0.2.5")
    summary = anon.get_summary()
    assert summary["devices_anonymized"] == 1
    assert summary["ips_anonymized"] == 1
