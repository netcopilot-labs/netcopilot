"""
DOT Generator - Graphviz Syntax Generation

Transforms network model into valid Graphviz DOT format for rendering.

Core responsibilities:
  1. Generate graph/node/edge declarations
  2. Ensure deterministic output (sorted by ID)
  3. Format interface labels (abbreviated)
  4. Indicate link status (up/down/admin_down)
  5. Handle bidirectional vs unidirectional links

Architecture:
    network_model.json
            │
            ├─► _generate_header()     ──► Graph attributes
            │
            ├─► _generate_nodes()      ──► Device nodes (sorted by device_id)
            │
            └─► _generate_edges()      ──► Links as edges (sorted by link_id)
                    │
                    ├─► _abbreviate_interface()   ──► Hu0/0/1/0
                    ├─► _format_edge_label()      ──► "Hu0/0/1/0 ↔ Hu0/0/0/0"
                    └─► _edge_style_for_status()  ──► solid/dashed

Design Principles:
    - Deterministic: Always sort before output
    - No inference: Only render what exists in model
    - Self-contained: No external state dependencies
    - Simple DOT: Valid Graphviz (no advanced features)

Example Usage:
    >>> from src.diagram.dot_generator import DotGenerator
    >>> generator = DotGenerator(model)
    >>> dot_content = generator.generate()
    >>> print(dot_content)  # Valid Graphviz DOT format
"""

# -----------------------------------------------------------------------------
# Standard library imports
# -----------------------------------------------------------------------------
from typing import Dict, Any, List


class DotGenerator:
    """
    Converts network model to Graphviz DOT format.

    Produces deterministic, readable DOT files suitable for rendering
    with Graphviz tools (dot, neato, etc.).
    """

    # Interface prefix mapping: Full name → Abbreviation
    INTERFACE_ABBREVIATIONS = {
        "hundredgige": "Hu",
        "tengigabitethernet": "Te",
        "twentyfivegige": "Twe",
        "gigabitethernet": "Gi",
        "fastethernet": "Fa",
        "ethernet": "Et",
        "loopback": "Lo",
        "vlan": "Vl",
        "port-channel": "Po",
        "management": "Mg",
    }

    # OS family → Node fill color mapping (for visual distinction)
    OS_FAMILY_COLORS = {
        "iosxr": "#e6f3ff",    # Light blue for IOS XR
        "iosxe": "#ffe6e6",    # Light red for IOS XE
        "fortios": "#e6ffe6",  # Light green for FortiOS (Sprint 9)
        "nxos": "#e6ffe6",     # Light green for NX-OS
        "ios": "#fff9e6",      # Light yellow for IOS
    }

    # Unmanaged device color (appears in links but not in devices list)
    UNMANAGED_COLOR = "#fffacd"  # Light yellow for unmanaged/external devices

    def __init__(self, model: Dict[str, Any]) -> None:
        """
        Initialize DOT generator with network model.

        Args:
            model: Network model dictionary with devices, interfaces, links
        """
        self.model = model
        self._identify_unmanaged_devices()

    def _identify_unmanaged_devices(self) -> None:
        """
        Identify devices that appear in links but not in devices list.

        Sets self.unmanaged_devices to a set of device IDs that are
        external/unmanaged (appear in links only).
        """
        # Get managed device IDs
        managed_devices = set(
            d.get("device_id") for d in self.model.get("devices", [])
        )

        # Get all devices appearing in links
        all_link_devices = set()
        for link in self.model.get("links", []):
            local_dev = link.get("local_device_id")
            remote_dev = link.get("remote_device_id")
            if local_dev:
                all_link_devices.add(local_dev)
            if remote_dev:
                all_link_devices.add(remote_dev)

        # Unmanaged = in links but not in devices
        self.unmanaged_devices = all_link_devices - managed_devices

    def generate(self) -> str:
        """
        Generate complete Graphviz DOT format string.

        Returns:
            Valid DOT format string ready for rendering with dot command
        """
        lines: List[str] = []

        # Graph header with layout attributes
        lines.extend(self._generate_header())

        # Device nodes (sorted deterministically)
        lines.extend(self._generate_nodes())

        # Link edges (sorted deterministically)
        lines.extend(self._generate_edges())

        # Legend (visual reference for colors and styles)
        lines.extend(self._generate_legend())

        # Graph footer
        lines.append("}")

        return "\n".join(lines)

    # =========================================================================
    # Graph Structure Generation
    # =========================================================================

    def _generate_header(self) -> List[str]:
        """
        Generate graph header with attributes.

        Returns:
            List of header lines (digraph, graph attributes, node defaults)
        """
        return [
            'digraph topology {',
            '    // Graph attributes for readability',
            '    graph [rankdir=TB, splines=true, overlap=false, sep=0.5];',
            '    node [shape=box, style=filled, fillcolor=white, fontname=sans];',
            '    edge [fontsize=10, fontname=sans];',
            '',
            '    // Nodes (devices) - colored by OS family',
        ]

    def _generate_nodes(self) -> List[str]:
        """
        Generate node declarations from model devices.

        Devices are sorted by device_id for deterministic output.
        Node fill color is based on OS family for visual distinction.
        Unmanaged devices (appearing in links only) use gray color.
        Sprint 11C: Devices are grouped into subgraph clusters by site.

        Returns:
            List of DOT node statements
        """
        lines: List[str] = []
        devices = self.model.get("devices", [])

        # Sort devices by device_id (alphabetically) for determinism
        sorted_devices = sorted(devices, key=lambda d: d.get("device_id", ""))

        # -----------------------------------------------------------------------
        # Sprint 11C: Group devices by site for subgraph clustering
        # -----------------------------------------------------------------------
        sites: Dict[str, List[Dict[str, Any]]] = {}
        ungrouped: List[Dict[str, Any]] = []

        for device in sorted_devices:
            site = device.get("site", "")
            if site and site != "unassigned":
                sites.setdefault(site, []).append(device)
            else:
                ungrouped.append(device)

        # Emit site subgraph clusters (sorted by site name for determinism)
        for site_name in sorted(sites):
            lines.append(f'    subgraph cluster_{site_name} {{')
            lines.append(f'        label="{site_name}";')
            lines.append('        style=dashed;')
            lines.append('        color=gray60;')
            lines.append('        fontsize=14;')
            lines.append('        fontname=sans;')
            lines.append("")

            for device in sites[site_name]:
                stmt = self._format_node_statement(device, indent=8)
                lines.append(stmt)

            lines.append("    }")
            lines.append("")

        # Emit ungrouped managed devices (no site / "unassigned")
        for device in ungrouped:
            lines.append(self._format_node_statement(device, indent=4))

        # Add unmanaged devices (appear in links but not in devices list)
        # These are external/unmanaged devices colored in light gray
        for device_id in sorted(self.unmanaged_devices):
            lines.append(
                f'    "{device_id}" [label="{device_id}", fillcolor="{self.UNMANAGED_COLOR}"];'
            )

        lines.append("")
        lines.append("    // Edges (links)")

        return lines

    def _generate_edges(self) -> List[str]:
        """
        Generate edge declarations from model links.

        Links are sorted by link_id for deterministic output.
        Edges include abbreviated interface labels and status indication.

        Returns:
            List of DOT edge statements
        """
        lines: List[str] = []
        links = self.model.get("links", [])

        # Sort links by link_id (alphabetically) for determinism
        sorted_links = sorted(links, key=lambda l: l.get("link_id", ""))

        for link in sorted_links:
            local_device = link.get("local_device_id", "unknown")
            remote_device = link.get("remote_device_id", "unknown")

            # Extract interface names from interface_id fields (format: "device:interface")
            local_interface_id = link.get("local_interface_id", "")
            remote_interface_id = link.get("remote_interface_id", "")
            local_interface = self._extract_interface_name(local_interface_id)
            remote_interface = self._extract_interface_name(remote_interface_id)
            status = link.get("status", "unknown")
            direction = link.get("direction", "bidirectional")

            # Abbreviate interface names for readability
            local_short = self._abbreviate_interface(local_interface)
            remote_short = self._abbreviate_interface(remote_interface)

            # Format edge label showing both interface endpoints
            label = self._format_edge_label(local_short, remote_short, direction)

            # Determine edge style based on link status
            style = self._edge_style_for_status(status)

            # Determine arrow direction based on link directionality
            edge_dir = "none" if direction == "bidirectional" else "forward"

            # Build edge statement
            # Format: "local_device" -> "remote_device" [label="...", ...]
            edge_statement = f'    "{local_device}" -> "{remote_device}" ['
            edge_statement += f'label="{label}", dir={edge_dir}'
            if style:
                edge_statement += f", {style}"
            edge_statement += "];"

            lines.append(edge_statement)

        return lines

    # =========================================================================
    # Legend Generation
    # =========================================================================

    def _generate_legend(self) -> List[str]:
        """
        Generate legend subgraph showing color meanings and link styles.

        Creates a visual reference in bottom-right corner showing:
        - Device colors (IOS XR, IOS XE, Unmanaged)
        - Link directionality (bidirectional vs unidirectional)
        - Finding annotation (with severity marker)
        - Link status (up, down, admin_down)

        Returns:
            List of DOT subgraph statements for the legend
        """
        lines: List[str] = []

        lines.append("")
        lines.append("    // Legend - visual reference for colors and styles")
        lines.append('    subgraph cluster_legend {')
        lines.append('        label="Legend";')
        lines.append('        style=filled;')
        lines.append('        fillcolor=white;')
        lines.append('        color=black;')
        lines.append('        penwidth=2.5;')
        lines.append('        fontsize=12;')
        lines.append('        margin=15;')
        lines.append("")

        # Device color legend
        lines.append('        // Device types by OS family')
        lines.append('        _legend_iosxr [label="IOS XR", fillcolor="#e6f3ff", shape=box, style=filled, fontsize=10];')
        lines.append('        _legend_iosxe [label="IOS XE", fillcolor="#ffe6e6", shape=box, style=filled, fontsize=10];')
        lines.append('        _legend_fortios [label="FortiOS", fillcolor="#e6ffe6", shape=box, style=filled, fontsize=10];')
        lines.append('        _legend_unmanaged [label="Unmanaged", fillcolor="#fffacd", shape=box, style=filled, fontsize=10];')
        lines.append("")

        # Link directionality legend
        lines.append('        // Link directionality')
        lines.append('        _legend_bidir [label="Bidirectional", shape=point, width=0];')
        lines.append('        _legend_unidir [label="Unidirectional", shape=point, width=0];')
        lines.append('        _legend_bidir -> _legend_unidir [label="↔ (both ways)", dir=none, fontsize=10];')
        lines.append('        _legend_unidir -> _legend_unmanaged [label="→ (one way)", dir=forward, fontsize=10];')
        lines.append("")

        # Finding annotation legend
        lines.append('        // Finding severity (colors and markers)')
        lines.append('        _legend_finding [label="With Finding [?]", shape=point, width=0];')
        lines.append('        _legend_unmanaged -> _legend_finding [label="[?] medium", color=goldenrod, dir=forward, fontsize=10];')
        lines.append("")

        # Link status legend
        lines.append('        // Link status (line style)')
        lines.append('        _legend_up [label="Link: up", shape=point, width=0];')
        lines.append('        _legend_down [label="Link: down", shape=point, width=0];')
        lines.append('        _legend_up -> _legend_down [label="solid", dir=none, style=solid, fontsize=10];')
        lines.append('        _legend_down -> _legend_iosxr [label="dashed", dir=none, style=dashed, fontsize=10];')
        lines.append("")

        lines.append('    }')

        return lines

    # =========================================================================
    # Helper Functions for Node Formatting
    # =========================================================================

    def _format_node_statement(self, device: Dict[str, Any], indent: int = 4) -> str:
        """
        Format a single device as a DOT node statement.

        Builds a multi-line label: hostname, optional [role], optional [cluster].
        Node fill color is determined by OS family.

        Args:
            device: Device dict from the model.
            indent: Number of spaces for indentation.

        Returns:
            DOT node statement string.
        """
        device_id = device.get("device_id", "unknown")
        hostname = device.get("hostname", device_id)
        os_family = device.get("os_family", "unknown")

        # Determine fill color based on OS family
        fillcolor = self.OS_FAMILY_COLORS.get(os_family, "white")

        # Sprint 11C: Append role label beneath hostname
        role = device.get("role", "")
        role_suffix = f"[{role}]" if role else ""

        # Sprint 10: Append cluster/HA label for redundant devices
        cluster_suffix = self._cluster_label(device)

        # Build multi-line label: hostname \n [role] \n [cluster]
        label = hostname
        if role_suffix:
            label = f"{label}\\n{role_suffix}"
        if cluster_suffix:
            label = f"{label}\\n{cluster_suffix}"

        pad = " " * indent
        return f'{pad}"{device_id}" [label="{label}", fillcolor="{fillcolor}"];'

    # =========================================================================
    # Helper Functions for Cluster Labels
    # =========================================================================

    # Member type → display label prefix mapping
    CLUSTER_LABEL_MAP = {
        "stackwise": "stack",
        "ha_active_passive": "HA",
        "ha_active_active": "HA",
        "vss": "VSS",
    }

    def _cluster_label(self, device: Dict[str, Any]) -> str:
        """
        Generate cluster/HA label suffix for a device node.

        For devices with cluster_members, returns a label like "[stack: 2]"
        or "[HA: 2]" based on the member_type of the first member. Non-cluster
        devices return an empty string.

        Args:
            device: Device dict from the model with cluster_members[].

        Returns:
            Label string like "[stack: 2]", or empty string for non-cluster.
        """
        members = device.get("cluster_members", [])
        if not members:
            return ""

        # Determine label from first member's type
        member_type = members[0].get("member_type", "")
        label_prefix = self.CLUSTER_LABEL_MAP.get(member_type, "cluster")

        return f"[{label_prefix}: {len(members)}]"

    # =========================================================================
    # Helper Functions for Interface Handling
    # =========================================================================

    def _extract_interface_name(self, interface_id: str) -> str:
        """
        Extract interface name from interface_id.

        Format: "device_id:interface_name"
        Example: "core-sw-01:Hu1/0/1" → "Hu1/0/1"

        Args:
            interface_id: Full interface identifier

        Returns:
            Interface name portion, or empty string if malformed
        """
        if not interface_id:
            return ""
        
        # Split on colon; take everything after first colon
        parts = interface_id.split(":", 1)
        return parts[1] if len(parts) > 1 else interface_id

    def _abbreviate_interface(self, interface_name: str) -> str:
        """
        Abbreviate Cisco interface name for readability.

        Examples:
            HundredGigE0/0/1/0 → Hu0/0/1/0
            TwentyFiveGigE1/0/8 → Twe1/0/8
            GigabitEthernet0/0 → Gi0/0

        Args:
            interface_name: Full interface name from model

        Returns:
            Abbreviated interface name (unknown types unchanged)
        """
        if not interface_name:
            return ""

        # Convert to lowercase for case-insensitive matching
        interface_lower = interface_name.lower()

        # Extract prefix and numbers
        # Match the longest prefix first to avoid partial matches
        for full_prefix in sorted(
            self.INTERFACE_ABBREVIATIONS.keys(), key=len, reverse=True
        ):
            if interface_lower.startswith(full_prefix):
                short_prefix = self.INTERFACE_ABBREVIATIONS[full_prefix]
                # Keep everything after the prefix (slot/port numbers)
                remainder = interface_name[len(full_prefix) :]
                return short_prefix + remainder

        # Unknown type: return unchanged
        return interface_name

    def _format_edge_label(
        self, local_short: str, remote_short: str, direction: str
    ) -> str:
        """
        Format edge label showing both interface endpoints.

        Args:
            local_short: Abbreviated local interface name
            remote_short: Abbreviated remote interface name
            direction: Link direction (bidirectional, unidirectional, etc.)

        Returns:
            Formatted label string suitable for DOT edge
        """
        if direction == "unidirectional":
            # Single arrow for unidirectional
            return f"{local_short} → {remote_short}"
        else:
            # Double arrow for bidirectional (or unknown)
            return f"{local_short} ↔ {remote_short}"

    def _edge_style_for_status(self, status: str) -> str:
        """
        Generate DOT style attribute based on link status.

        Status indicators:
            - up: solid line (default, no special style)
            - down: dashed line
            - admin_down: dotted line
            - unknown: solid line with ? marker

        Args:
            status: Link status from model

        Returns:
            DOT style attribute (e.g., 'style=dashed') or empty string
        """
        if status == "down":
            return "style=dashed"
        elif status == "admin_down":
            return "style=dotted"
        else:
            # up or unknown: use default (solid)
            return ""
