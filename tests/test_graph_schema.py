"""F1-3: graph schema core labels present, client imports.

History: extraction (F1-3) deliberately excluded NetBox and asserted the
exclusion here. s11 (ADR-0013) reinstates NetBox as the declared-state layer,
so the old ``test_no_netbox_labels_or_edges`` / ``test_indexes_have_no_netbox_
targets`` guards are retired and replaced by positive assertions.
"""

import netcopilot.graph.client as client
from netcopilot.graph import schema


def test_core_labels_present():
    assert schema.DEVICE == "Device"
    assert schema.FINDING == "Finding"
    assert schema.INTERFACE == "Interface"
    assert schema.RUN == "Run"


def test_netbox_staging_labels_present():
    # s11 (ADR-0013): staging label is transient, audit label is append-only.
    assert schema.NETBOX_PENDING_WRITE == "NetBoxPendingWrite"
    assert schema.NETBOX_WRITE == "NetBoxWrite"
    for edge in ("AFFECTS_DEVICE", "AFFECTS_INTERFACE", "FROM_FINDING"):
        assert getattr(schema, edge) == edge


def test_client_module_imports():
    # neo4j is imported lazily inside get_driver, so the module imports without the driver installed
    assert hasattr(client, "get_driver")
    assert hasattr(client, "is_available")
    assert hasattr(client, "get_site_for_run")
