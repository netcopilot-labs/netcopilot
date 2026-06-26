"""Positive-trigger fixtures for the CLUSTER / HA health rules.

These read device.cluster_members[] / cluster_declared_size. Like the STACK/SVL
family they're unexercised on the goldens (the clusters are healthy), so these
synthetic fixtures prove the rule logic fires on the correct data shape.
"""

from netcopilot.rules.rules.cluster_member_not_ready import ClusterMemberNotReadyRule
from netcopilot.rules.rules.cluster_no_standby import ClusterNoStandbyRule
from netcopilot.rules.rules.cluster_platform_mismatch import ClusterPlatformMismatchRule
from netcopilot.rules.rules.cluster_size_mismatch import ClusterSizeMismatchRule
from netcopilot.rules.rules.cluster_version_mismatch import ClusterVersionMismatchRule
from netcopilot.rules.rules.ha_not_synchronized import HANotSynchronizedRule
from netcopilot.rules.rules.ha_path_diversity_missing import HaPathDiversityMissingRule


def _dev(**kw):
    d = {"hostname": "clust-01"}
    d.update(kw)
    return {"devices": [d]}


def test_cluster_member_not_ready_fires():
    m = _dev(cluster_members=[
        {"member_id": 1, "state": "ready"},
        {"member_id": 2, "state": "Initializing"},   # not healthy
    ])
    assert len(ClusterMemberNotReadyRule().evaluate(m, {})) == 1


def test_cluster_no_standby_fires():
    m = _dev(cluster_members=[
        {"member_id": 1, "role": "active"},
        {"member_id": 2, "role": "active"},          # no standby/passive role
    ])
    assert len(ClusterNoStandbyRule().evaluate(m, {})) == 1


def test_cluster_platform_mismatch_fires():
    m = _dev(cluster_members=[
        {"member_id": 1, "platform": "C9500-32C"},
        {"member_id": 2, "platform": "C9500-48Y4C"},  # different hardware
    ])
    assert len(ClusterPlatformMismatchRule().evaluate(m, {})) == 1


def test_cluster_size_mismatch_fires():
    m = _dev(cluster_declared_size=2, cluster_members=[{"member_id": 1}])  # 1 != 2
    assert len(ClusterSizeMismatchRule().evaluate(m, {})) == 1


def test_cluster_version_mismatch_fires():
    m = _dev(cluster_members=[
        {"member_id": 1, "version": "17.9.1"},
        {"member_id": 2, "version": "17.6.3"},        # different software
    ])
    assert len(ClusterVersionMismatchRule().evaluate(m, {})) == 1


def test_ha_not_synchronized_fires():
    m = _dev(cluster_members=[
        {"member_id": 1, "member_type": "ha_active_passive", "state": "HA synchronized"},
        {"member_id": 2, "member_type": "ha_active_passive", "state": "HA out of sync"},
    ])
    assert len(HANotSynchronizedRule().evaluate(m, {})) == 1


def test_ha_path_diversity_missing_fires():
    # FortiGate HA: both active and passive members connect to the SAME
    # non-stacked upstream -> single point of failure, no path diversity.
    model = {
        "devices": [{"hostname": "fwl-ha", "os_family": "fortios", "cluster_declared_size": 2}],
        "links": [
            {"ha_member": "active", "local_device_id": "fwl-ha",
             "remote_device_id": "sw-up", "target_member_id": 1},
            {"ha_member": "passive", "local_device_id": "fwl-ha",
             "remote_device_id": "sw-up", "target_member_id": 1},
        ],
    }
    assert len(HaPathDiversityMissingRule().evaluate(model, {})) == 1
