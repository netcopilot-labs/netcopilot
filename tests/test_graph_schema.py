"""F1-3: graph schema is cleaned (no NetBox), core labels present, client imports."""

import netcopilot.graph.client as client
from netcopilot.graph import schema


def test_core_labels_present():
    assert schema.DEVICE == "Device"
    assert schema.FINDING == "Finding"
    assert schema.INTERFACE == "Interface"
    assert schema.RUN == "Run"


def test_no_netbox_labels_or_edges():
    names = set(vars(schema))
    assert not any("NETBOX" in n for n in names)
    for removed in ("AFFECTS_DEVICE", "AFFECTS_INTERFACE", "FROM_FINDING"):
        assert removed not in names


def test_indexes_have_no_netbox_targets():
    labels = {label for label, _props, _name in schema.INDEX_DEFINITIONS}
    assert not any("NetBox" in lab for lab in labels)


def test_client_module_imports():
    # neo4j is imported lazily inside get_driver, so the module imports without the driver installed
    assert hasattr(client, "get_driver")
    assert hasattr(client, "is_available")
    assert hasattr(client, "get_site_for_run")
