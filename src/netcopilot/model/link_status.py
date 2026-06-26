"""
Link status calculator for network model building.

This module calculates link operational status from the states
of both interface endpoints. It's a logical interpretation of
observed interface data, not inference.

Status Values:
    up         - Both endpoints admin=up AND oper=up
    down       - One/both endpoints oper=down (but not admin down)
    admin_down - One/both endpoints administratively shutdown
    unknown    - Cannot determine (missing interface data)

Priority Order (for determination):
    1. Check for missing data → unknown
    2. Either end admin down → admin_down
    3. Both ends fully up → up
    4. Either end oper down → down
    5. Fallback → unknown

Why This Order?
    - Missing data is checked first because we can't proceed without it
    - Admin_down is checked before up because a shutdown interface
      means the operator intentionally disabled it (not a fault)
    - Oper down checked last as a catch-all for connectivity issues

OS Differences (handled by the model builder before calling this):
    - IOS XE: "administratively down" → admin_status="down"
    - IOS XR: "Shutdown" → admin_status="down"
    - Both normalized to "up" or "down" before reaching this function

Design Principles:
    - Deterministic: Same interface states → same link status
    - Traceable: Link references interface IDs for verification
    - Explicit: Missing data = "unknown" (never guessed)
    - Simple: Just combines two observed states (no inference)
"""

from typing import Any, Literal

# -------------------------------------------------------------------------
# Type Definition
# -------------------------------------------------------------------------
# Literal type ensures we only return valid status values
# This gives us compile-time checking in IDEs and type checkers
LinkStatus = Literal["up", "down", "admin_down", "unknown"]


def calculate_link_status(
    local_interface: dict[str, Any] | None,
    remote_interface: dict[str, Any] | None,
) -> LinkStatus:
    """
    Calculate link status from both endpoint interface states.

    A link is only "up" if BOTH endpoints are administratively
    and operationally up. Any other combination indicates a
    problem or intentional shutdown.

    Truth Table (simplified):
        Local Admin | Local Oper | Remote Admin | Remote Oper | Result
        ------------|------------|--------------|-------------|--------
        up          | up         | up           | up          | up
        down        | *          | *            | *           | admin_down
        *           | *          | down         | *           | admin_down
        up          | down       | up           | *           | down
        up          | *          | up           | down        | down
        (missing)   | *          | *            | *           | unknown

    Args:
        local_interface: Local endpoint interface dict with
                        'admin_status' and 'oper_status' fields
        remote_interface: Remote endpoint interface dict

    Returns:
        Link status: "up", "down", "admin_down", or "unknown"

    Examples:
        >>> local = {"admin_status": "up", "oper_status": "up"}
        >>> remote = {"admin_status": "up", "oper_status": "up"}
        >>> calculate_link_status(local, remote)
        'up'

        >>> local = {"admin_status": "up", "oper_status": "up"}
        >>> remote = {"admin_status": "up", "oper_status": "down"}
        >>> calculate_link_status(local, remote)
        'down'

        >>> local = {"admin_status": "down", "oper_status": "down"}
        >>> remote = {"admin_status": "up", "oper_status": "up"}
        >>> calculate_link_status(local, remote)
        'admin_down'
    """
    # -------------------------------------------------------------------------
    # Step 1: Check for missing interface data
    # -------------------------------------------------------------------------
    # If we don't have data for one or both endpoints, we can't determine
    # the link status. This happens when:
    # - Interface wasn't in "show ip interface brief" output
    # - Device wasn't collected (neighbor is outside our inventory)
    # - Parsing failed for that interface
    if local_interface is None:
        return "unknown"
    if remote_interface is None:
        # Partial data: remote interface unknown (e.g. lacp_unilateral to a
        # firewall where the peer side cannot be identified). Use local interface
        # status only — a link where LACP is actively negotiating is
        # operationally up on our side.
        local_admin = local_interface.get("admin_status", "unknown")
        local_oper = local_interface.get("oper_status", "unknown")
        if local_admin == "down":
            return "admin_down"
        if local_oper == "up":
            return "up"
        if local_oper == "down":
            return "down"
        return "unknown"

    # -------------------------------------------------------------------------
    # Step 2: Extract status values
    # -------------------------------------------------------------------------
    # We use .get() with "unknown" default to handle missing fields gracefully
    # This shouldn't happen with properly built interfaces, but defensive coding
    local_admin = local_interface.get("admin_status", "unknown")
    local_oper = local_interface.get("oper_status", "unknown")
    remote_admin = remote_interface.get("admin_status", "unknown")
    remote_oper = remote_interface.get("oper_status", "unknown")

    # -------------------------------------------------------------------------
    # Step 3: Check for admin down (intentional shutdown)
    # -------------------------------------------------------------------------
    # If either endpoint is administratively down, the link is admin_down
    # This is checked first because it indicates operator intent, not a fault
    #
    # Why check admin_down before checking "up"?
    # An admin-down interface may also be operationally down, but the root
    # cause is the administrative action, not a connectivity problem
    if local_admin == "down" or remote_admin == "down":
        return "admin_down"

    # -------------------------------------------------------------------------
    # Step 4: Check for both ends fully up
    # -------------------------------------------------------------------------
    # Link is "up" only if ALL of these are true:
    # - Local admin is up (enabled by operator)
    # - Local oper is up (protocol working)
    # - Remote admin is up (enabled by operator)
    # - Remote oper is up (protocol working)
    if (
        local_admin == "up"
        and local_oper == "up"
        and remote_admin == "up"
        and remote_oper == "up"
    ):
        return "up"

    # -------------------------------------------------------------------------
    # Step 5: Check for operational down (connectivity problem)
    # -------------------------------------------------------------------------
    # If we get here, both ends are administratively up, but one or both
    # are operationally down. This indicates a connectivity issue:
    # - Cable problem
    # - Port error (CRC, input errors)
    # - Negotiation failure
    # - Remote device down
    if local_oper == "down" or remote_oper == "down":
        return "down"

    # -------------------------------------------------------------------------
    # Step 6: Fallback for unknown states
    # -------------------------------------------------------------------------
    # If we couldn't determine status (e.g., status values are "unknown"),
    # return "unknown" rather than guessing
    return "unknown"
