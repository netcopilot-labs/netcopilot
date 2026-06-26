"""
Diagram Builder - Main Orchestration

Orchestrates the complete diagram generation pipeline:
  1. Load network model from JSON
  2. Load findings (if available)
  3. Generate Graphviz DOT syntax
  4. Annotate with findings (colors, markers)
  5. Render to SVG and PNG via Graphviz

Architecture:
    runs/<run-id>/
        ├── model/network_model.json  ←── Load
        ├── findings/findings.json    ←── Load (optional)
        └── diagrams/ (created)       ──→ Output DOT, SVG, PNG

Design Principles:
    - Single responsibility: Orchestrate, don't implement details
    - Delegate to specialized modules (dot_generator, finding_annotator, renderer)
    - Deterministic: Same input always produces same output
    - Graceful degradation: DOT always produced, rendering is best-effort

Example Usage:
    >>> from src.diagram import build_diagram
    >>> result = build_diagram("2026-01-30_17-53-12")
    >>> print(result["dot_file"])  # Path to topology.dot
    >>> print(result["warnings"])  # Any non-fatal issues
"""

# -----------------------------------------------------------------------------
# Standard library imports
# -----------------------------------------------------------------------------
import json
import os
from pathlib import Path
from typing import Any, Dict

# -----------------------------------------------------------------------------
# Local imports
# -----------------------------------------------------------------------------
from netcopilot.diagram.dot_generator import DotGenerator
from netcopilot.diagram.finding_annotator import FindingAnnotator
from netcopilot.diagram.renderer import Renderer


class DiagramBuilder:
    """
    Main orchestrator for diagram generation pipeline.

    Loads model and findings, coordinates generation and rendering,
    and returns a comprehensive result dictionary.
    """

    def __init__(self, run_id: str) -> None:
        """
        Initialize diagram builder.

        Args:
            run_id: Run identifier (directory name under runs/)
        """
        self.run_id = run_id
        self.run_dir = Path(os.environ.get("RUNS_DIR", "runs")) / run_id
        self.diagrams_dir = self.run_dir / "diagrams"

        # State initialized by build()
        self.model: Dict[str, Any] = {}
        self.findings: Dict[str, Any] = {}
        self.dot_content: str = ""
        self.warnings: list[str] = []

    def build(self) -> Dict[str, Any]:
        """
        Execute complete diagram generation pipeline.

        Returns:
            Result dictionary with:
                - success: Overall success (True if DOT produced, False if fatal error)
                - dot_file: Path to generated topology.dot
                - svg_file: Path to topology.svg (None if rendering failed)
                - png_file: Path to topology.png (None if rendering failed)
                - device_count: Number of devices
                - link_count: Number of links
                - finding_count: Number of findings annotated
                - warnings: List of non-fatal issues

        Raises:
            FileNotFoundError: If model file doesn't exist
            ValueError: If model is malformed
        """
        try:
            # =====================================================================
            # Load Input Data
            # =====================================================================
            self._load_model()
            self._load_findings()

            # =====================================================================
            # Generate DOT Syntax
            # =====================================================================
            self._create_diagrams_directory()
            generator = DotGenerator(self.model)
            self.dot_content = generator.generate()

            # =====================================================================
            # Annotate with Findings
            # =====================================================================
            if self.findings:
                annotator = FindingAnnotator(self.findings, self.model)
                self.dot_content = annotator.annotate(self.dot_content)
            else:
                self.warnings.append("No findings file found; diagram has no annotations")

            # =====================================================================
            # Write DOT File (Always Produced)
            # =====================================================================
            dot_file_path = self._write_dot_file()

            # =====================================================================
            # Render to SVG and PNG (Best-Effort)
            # =====================================================================
            renderer = Renderer(str(dot_file_path))
            svg_file, png_file, render_warnings = renderer.render()
            self.warnings.extend(render_warnings)

            # =====================================================================
            # Build Result Dictionary
            # =====================================================================
            return {
                "success": True,
                "dot_file": str(dot_file_path),
                "svg_file": str(svg_file) if svg_file else None,
                "png_file": str(png_file) if png_file else None,
                "device_count": len(self.model.get("devices", [])),
                "link_count": len(self.model.get("links", [])),
                "finding_count": len(self.findings.get("findings", [])),
                "warnings": self.warnings,
            }

        except Exception as e:
            # Fatal error: return failure but ensure diagrams dir exists for logs
            self._create_diagrams_directory()
            raise

    def _load_model(self) -> None:
        """
        Load network model from JSON file.

        Raises:
            FileNotFoundError: If model file doesn't exist
            ValueError: If JSON is invalid
        """
        model_file = self.run_dir / "model" / "network_model.json"

        if not model_file.exists():
            raise FileNotFoundError(
                f"Model file not found: {model_file}\n"
                f"Run diagram generation after model builder (Sprint 3)"
            )

        try:
            with open(model_file, "r", encoding="utf-8") as f:
                self.model = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {model_file}: {e}")

        # Validate required top-level keys
        required_keys = ["devices", "interfaces", "links"]
        missing = [k for k in required_keys if k not in self.model]
        if missing:
            raise ValueError(
                f"Model missing required keys: {missing}\n"
                f"Expected: {required_keys}"
            )

    def _load_findings(self) -> None:
        """
        Load findings from JSON file (optional).

        If findings file doesn't exist, self.findings remains empty {}
        and annotation is skipped.
        """
        findings_file = self.run_dir / "findings" / "findings.json"

        if not findings_file.exists():
            self.findings = {}
            return

        try:
            with open(findings_file, "r", encoding="utf-8") as f:
                findings_data = json.load(f)
                self.findings = findings_data
        except json.JSONDecodeError as e:
            self.warnings.append(f"Could not parse findings file: {e}")
            self.findings = {}

    def _create_diagrams_directory(self) -> None:
        """Create runs/<run-id>/diagrams/ directory if it doesn't exist."""
        self.diagrams_dir.mkdir(parents=True, exist_ok=True)

    def _write_dot_file(self) -> Path:
        """
        Write DOT content to topology.dot file.

        Returns:
            Path to the written DOT file
        """
        dot_file = self.diagrams_dir / "topology.dot"

        with open(dot_file, "w", encoding="utf-8") as f:
            f.write(self.dot_content)

        return dot_file
