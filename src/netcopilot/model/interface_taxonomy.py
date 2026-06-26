"""Interface taxonomy helpers shared across the pipeline.

A single canonical definition of "virtual interface" so the link builder
(link-type classification) and any render layer agree on which interfaces are
L3-only / virtual versus physical-port.
"""

# Interface name prefixes that indicate a virtual / L3-only interface.
VIRTUAL_INTERFACE_PREFIXES: tuple[str, ...] = (
    "loopback", "lo",
    "vlan", "vl",
    "bvi",
    "bdi",
    "tunnel", "tu",
    "nve",
)


def is_virtual_interface(intf_name: str | None) -> bool:
    """Return True if the interface name indicates a virtual / L3-only interface.

    Virtual interfaces include Loopback, VLAN SVI, BVI, BDI, Tunnel, and NVE.
    Also matches FortiGate numeric-only VLAN interfaces (e.g., "4094").

    Port-channel and Bundle-Ether are NOT virtual — they are LAG aggregates
    that carry data-plane traffic over physical member links.

    Args:
        intf_name: Interface name (e.g., "Loopback0", "Vlan99", "399"). May be None.

    Returns:
        True if the interface is virtual.
    """
    if not intf_name:
        return False

    name_lower = intf_name.lower()

    # FortiGate numeric-only VLAN interfaces (e.g., "4094", "100")
    if intf_name.isdigit():
        return True

    # Check known virtual prefixes
    for prefix in VIRTUAL_INTERFACE_PREFIXES:
        if name_lower.startswith(prefix):
            # For short prefixes (lo, vl, tu), ensure the next char is a digit
            # to avoid false positives (e.g., "local" != "lo0")
            if len(prefix) <= 2 and len(name_lower) > len(prefix):
                next_char = name_lower[len(prefix)]
                if next_char.isdigit():
                    return True
            elif len(prefix) > 2:
                return True

    return False
