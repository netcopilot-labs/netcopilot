"""
Shared formatting helpers for QoS rules.

Provides human-readable formatting for large counter values and
bit-rate values used in QoS rule finding messages.
"""


def fmt_count(n: int) -> str:
    """Format large counter for readability: 6,968,522,314 → '6.97B'."""
    if n >= 1_000_000_000_000:
        return f"{n / 1_000_000_000_000:.2f}T"
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.2f}B"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 10_000:
        return f"{n / 1_000:.1f}K"
    return f"{n:,}"


def fmt_rate(bps: int | None) -> str:
    """Format bps rate: 7500000000 → '7.5 Gbps'."""
    if bps is None:
        return "unknown"
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.1f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.0f} Mbps"
    return f"{bps / 1_000:.0f} Kbps"
