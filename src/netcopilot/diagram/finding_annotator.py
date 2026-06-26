"""
Finding Annotator - Finding-Based Diagram Annotation

Enhances Graphviz DOT syntax with finding highlights using colors and markers.

Core responsibilities:
  1. Parse DOT syntax
  2. Map findings to model elements (devices, links, interfaces)
  3. Apply colors and markers based on severity
  4. Merge multiple findings on same element (highest severity wins)
  5. Return annotated DOT

Architecture:
    findings.json
        │
        ├─► Build element_id → severity mapping
        │   (Highest severity if multiple)
        │
        ├─► Iterate DOT node/edge statements
        │
        ├─► Check if element has finding
        │
        └─► Apply color, marker, annotations

Severity → Visual Mapping (ADR-025):
    critical: Red fill (#ffcccc) + [!] marker
    high:     Orange fill (#ffe0cc) + [!] marker
    medium:   Yellow fill (#ffffcc) + [?] marker
    low:      Gray fill (#e0e0e0) + [-] marker

Design Principles:
    - Non-destructive: Adds attributes, doesn't remove existing ones
    - Highest-severity-wins: Multiple findings → use max severity
    - Additive: Works on any DOT syntax
    - Idempotent: Calling twice produces same result

Example Usage:
    >>> from src.diagram.finding_annotator import FindingAnnotator
    >>> annotator = FindingAnnotator(findings_dict)
    >>> annotated_dot = annotator.annotate(original_dot)
"""

# -----------------------------------------------------------------------------
# Standard library imports
# -----------------------------------------------------------------------------
import re
from typing import Dict, Any, Optional


class FindingAnnotator:
    """
    Annotates DOT syntax with finding highlights.

    Maps findings to network elements and applies visual indicators
    (colors, markers) to nodes and edges.
    """

    # Severity levels ordered by priority (highest first). Must cover every
    # value in the findings taxonomy (critical/high/low/cis/info); "medium" is
    # retained for backward compatibility. "info" was added after this module
    # was first written — omitting it crashed the highest-severity-wins lookup.
    SEVERITY_ORDER = ["critical", "high", "medium", "low", "cis", "info"]

    # Severity → Visual mapping
    SEVERITY_COLORS = {
        "critical": {"fill": "#ffcccc", "edge": "red", "marker": "[!]"},
        "high": {"fill": "#ffe0cc", "edge": "orange", "marker": "[!]"},
        "medium": {"fill": "#ffffcc", "edge": "goldenrod", "marker": "[?]"},
        "low": {"fill": "#e0e0e0", "edge": "gray", "marker": "[-]"},
        "cis": {"fill": "#d9e6f2", "edge": "steelblue", "marker": "[C]"},
        "info": {"fill": "#eef2f7", "edge": "lightgray", "marker": "[i]"},
    }

    def __init__(self, findings_data: Dict[str, Any], model_data: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize finding annotator.

        Args:
            findings_data: Parsed findings.json dictionary with "findings" key
            model_data: Optional network model dict (used for link_id lookup)
        """
        self.findings_data = findings_data
        self.model_data = model_data or {}
        self._build_element_severity_map()

    def annotate(self, dot_content: str) -> str:
        """
        Annotate DOT syntax with finding highlights.

        Parses DOT, identifies elements with findings, applies colors/markers,
        and returns updated DOT.

        Args:
            dot_content: Original DOT format string from generator

        Returns:
            Annotated DOT format string with findings highlighted
        """
        if not self.element_severity_map:
            # No findings to annotate
            return dot_content

        # =====================================================================
        # Annotate Nodes (Devices with Findings)
        # =====================================================================
        annotated = self._annotate_nodes(dot_content)

        # =====================================================================
        # Annotate Edges (Links with Findings)
        # =====================================================================
        annotated = self._annotate_edges(annotated)

        return annotated

    # =========================================================================
    # Building Element-to-Severity Map
    # =========================================================================

    def _build_element_severity_map(self) -> None:
        """
        Build mapping from element IDs to their highest severity.

        Handles:
            - Multiple findings on same element → use max severity
            - element_type: device → node annotation
            - element_type: link → edge annotation
            - element_type: interface → node annotation (device owning interface)

        Creates self.element_severity_map: {element_id: severity_level}
        """
        self.element_severity_map: Dict[str, str] = {}

        findings = self.findings_data.get("findings", [])

        for finding in findings:
            element_type = finding.get("evidence", {}).get("element_type", "")
            element_id = finding.get("evidence", {}).get("element_id", "")
            severity = finding.get("severity", "low")

            if not element_id or not element_type:
                # Skip findings without element reference
                continue

            # Determine which element to annotate in DOT
            # - device findings: annotate device node
            # - link findings: annotate edge
            # - interface findings: annotate parent device node
            target_id = element_id
            if element_type == "interface":
                # Interface findings apply to the device node
                # Extract device ID (before colon if present)
                target_id = element_id.split(":")[0] if ":" in element_id else element_id

            # Update map: keep highest severity if multiple findings
            if target_id in self.element_severity_map:
                current_severity = self.element_severity_map[target_id]
                # Compare severity levels
                if self.SEVERITY_ORDER.index(severity) < self.SEVERITY_ORDER.index(
                    current_severity
                ):
                    # New severity is higher (lower index = higher)
                    self.element_severity_map[target_id] = severity
            else:
                self.element_severity_map[target_id] = severity

    # =========================================================================
    # Annotating Nodes
    # =========================================================================

    def _annotate_nodes(self, dot_content: str) -> str:
        """
        Annotate device nodes with finding indicators.

        Modifies node statements to add fillcolor and marker to label.

        Args:
            dot_content: DOT content string

        Returns:
            DOT content with annotated nodes
        """
        # Match node statements: "device_id" [label="hostname", ...];
        # Pattern: quoted device_id, followed by [attributes]
        node_pattern = r'(\s*)"([^"]+)"\s+\[label="([^"]+)"([^\]]*)\];'

        def replace_node(match):
            indent = match.group(1)
            device_id = match.group(2)
            label = match.group(3)
            attrs = match.group(4)

            # Check if this device has findings
            if device_id not in self.element_severity_map:
                # No findings: return unchanged
                return match.group(0)

            severity = self.element_severity_map[device_id]
            colors = self.SEVERITY_COLORS.get(severity, {})

            # Add marker to label
            marker = colors.get("marker", "")
            new_label = f"{label} {marker}" if marker else label

            # Replace existing fillcolor in attributes (findings override OS family color)
            fillcolor = colors.get("fill", "white")
            # Remove existing fillcolor if present to avoid duplicate attributes
            new_attrs = re.sub(r',?\s*fillcolor="[^"]*"', '', attrs)
            new_attrs = f', fillcolor="{fillcolor}"' + new_attrs

            # Rebuild node statement
            return f'{indent}"{device_id}" [label="{new_label}"{new_attrs}];'

        return re.sub(node_pattern, replace_node, dot_content)

    # =========================================================================
    # Annotating Edges
    # =========================================================================

    def _annotate_edges(self, dot_content: str) -> str:
        """
        Annotate link edges with finding indicators.

        Modifies edge statements to add color and marker to label.
        For links, finding element_id is the link_id from model.

        Args:
            dot_content: DOT content string

        Returns:
            DOT content with annotated edges
        """
        # Match edge statements: "device1" -> "device2" [label="...", ...];
        # Need to extract devices and check if the link has findings
        # Pattern: quoted source, arrow, quoted target, [attributes]
        # Use DOTALL flag to match across newlines (edge statements may wrap)
        edge_pattern = r'(\s*)"([^"]+)"\s*->\s*"([^"]+)"\s+\[label="([^"]+)"([^\]]*)\];'

        def replace_edge(match):
            indent = match.group(1)
            local_device = match.group(2)
            remote_device = match.group(3)
            label = match.group(4)
            attrs = match.group(5)

            # Try to find link_id by matching devices
            # The element_severity_map has full link_ids like:
            #   "dist-sw-01:Twe 1/0/8--dist-sw-02:Te2/1/8"
            # But the edge only has device names like:
            #   "dist-sw-01" -> "dist-sw-02"
            # So we look for a link_id that starts with local_device and contains remote_device
            link_id = None
            for elem_id in self.element_severity_map.keys():
                # Check if elem_id matches these devices
                # elem_id format: "device1:interface1--device2:interface2"
                parts = elem_id.split("--")
                if len(parts) == 2:
                    local_part = parts[0].split(":")[0]  # device name before colon
                    remote_part = parts[1].split(":")[0]  # device name before colon
                    
                    # Check if this elem_id matches our edge
                    if (local_part == local_device and remote_part == remote_device) or \
                       (local_part == remote_device and remote_part == local_device):
                        link_id = elem_id
                        break

            if not link_id:
                # No findings for this link
                return match.group(0)

            severity = self.element_severity_map[link_id]
            colors = self.SEVERITY_COLORS.get(severity, {})

            # Add marker to label
            marker = colors.get("marker", "")
            new_label = f"{label} {marker}" if marker else label

            # Add color to attributes
            edge_color = colors.get("edge", "black")
            new_attrs = f', color="{edge_color}"' + attrs

            # Rebuild edge statement
            return f'{indent}"{local_device}" -> "{remote_device}" [label="{new_label}"{new_attrs}];'

        return re.sub(edge_pattern, replace_edge, dot_content, flags=re.DOTALL)


