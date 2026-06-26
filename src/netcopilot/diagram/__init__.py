"""
Diagram Generation Package

Transforms network model and findings into Graphviz DOT files and rendered
visualizations (SVG, PNG) for topology understanding and issue identification.

Public API:
    - build_diagram(run_id: str) -> dict
      Main entry point for diagram generation

Architecture:
    Network Model + Findings
            │
            ▼
    ┌──────────────────────┐
    │ diagram_builder.py   │
    │ (Orchestration)      │
    └──────┬───────────────┘
           │
    ┌──────┴────────────────┬──────────────────┬──────────────┐
    ▼                       ▼                  ▼              ▼
  dot_gen            finding_annotator      renderer      validation
  (DOT syntax)     (Color/marker mapping)   (SVG/PNG)    (Structure check)

This package only imports from standard library and netcopilot.model/netcopilot.rules.
"""

from typing import Dict, Any

# Lazy import pattern — functions imported at call site to reduce startup time
__all__ = ["build_diagram"]


def build_diagram(run_id: str) -> Dict[str, Any]:
    """
    Generate diagram from network model and findings.

    Args:
        run_id: Run identifier (e.g., "2026-01-30_17-53-12")

    Returns:
        Dictionary with keys:
            - "success": bool indicating if generation succeeded
            - "dot_file": Path to generated topology.dot
            - "svg_file": Path to topology.svg (None if rendering failed)
            - "png_file": Path to topology.png (None if rendering failed)
            - "device_count": Number of devices in diagram
            - "link_count": Number of links in diagram
            - "finding_count": Number of findings annotated
            - "warnings": List of warning messages (empty if no issues)

    Raises:
        FileNotFoundError: If run_id directory or model file doesn't exist
        ValueError: If model is malformed
    """
    # Import here to defer dependency resolution
    from netcopilot.diagram.diagram_builder import DiagramBuilder

    builder = DiagramBuilder(run_id)
    return builder.build()
