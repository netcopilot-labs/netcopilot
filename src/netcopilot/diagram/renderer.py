"""
Renderer - Graphviz Output Rendering

Renders Graphviz DOT files to SVG and PNG using the `dot` command.

Core responsibilities:
  1. Execute `dot` command on input DOT file
  2. Produce SVG and PNG output files
  3. Handle graceful degradation if Graphviz not installed
  4. Return result status without failing

Architecture:
    topology.dot
        │
        ├─► check_dot_available()
        │
        ├─► render_svg()  ──► dot -Tsvg
        │
        └─► render_png()  ──► dot -Tpng

Design Principles:
    - Graceful degradation: DOT is primary artifact, rendering is best-effort
    - Non-blocking: If `dot` not found, warn and return None (don't raise)
    - Subprocess safety: Use subprocess.run with proper error handling
    - Clear feedback: Return warnings for all issues

Example Usage:
    >>> from src.diagram.renderer import Renderer
    >>> renderer = Renderer("topology.dot")
    >>> svg_path, png_path, warnings = renderer.render()
    >>> for w in warnings:
    ...     print(f"Warning: {w}")
"""

# -----------------------------------------------------------------------------
# Standard library imports
# -----------------------------------------------------------------------------
import subprocess
from pathlib import Path
from typing import Tuple, Optional, List


class Renderer:
    """
    Renders Graphviz DOT files to SVG and PNG formats.

    Uses the `dot` command from Graphviz; gracefully handles
    case where Graphviz is not installed.
    """

    def __init__(self, dot_file_path: str) -> None:
        """
        Initialize renderer.

        Args:
            dot_file_path: Path to topology.dot file
        """
        self.dot_file = Path(dot_file_path)
        self.output_dir = self.dot_file.parent
        self.warnings: List[str] = []

    def render(
        self,
    ) -> Tuple[Optional[Path], Optional[Path], List[str]]:
        """
        Render DOT file to SVG and PNG.

        Returns:
            Tuple of (svg_path, png_path, warnings_list)
            - svg_path: Path to generated SVG (None if rendering failed)
            - png_path: Path to generated PNG (None if rendering failed)
            - warnings: List of non-fatal issues (empty if no problems)

        Note:
            This method never raises exceptions. All errors are captured
            as warnings, allowing the pipeline to continue.
        """
        self.warnings = []

        # =====================================================================
        # Check Graphviz Availability
        # =====================================================================
        if not self._check_dot_available():
            return None, None, self.warnings

        # =====================================================================
        # Render to SVG
        # =====================================================================
        svg_path = self._render_svg()

        # =====================================================================
        # Render to PNG
        # =====================================================================
        png_path = self._render_png()

        return svg_path, png_path, self.warnings

    # =========================================================================
    # Graphviz Availability Check
    # =========================================================================

    def _check_dot_available(self) -> bool:
        """
        Check if `dot` command is available on system.

        Returns:
            True if `dot` found and working, False otherwise
        """
        try:
            result = subprocess.run(
                ["dot", "-V"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                return True
            else:
                self.warnings.append(
                    "Graphviz `dot` command returned error; SVG/PNG rendering skipped"
                )
                return False
        except FileNotFoundError:
            self.warnings.append(
                "Graphviz not installed; SVG/PNG rendering skipped. "
                "Install with: sudo apt install graphviz"
            )
            return False
        except subprocess.TimeoutExpired:
            self.warnings.append("`dot -V` command timed out; SVG/PNG rendering skipped")
            return False
        except Exception as e:
            self.warnings.append(f"Unexpected error checking Graphviz: {e}")
            return False

    # =========================================================================
    # SVG Rendering
    # =========================================================================

    def _render_svg(self) -> Optional[Path]:
        """
        Render DOT file to SVG format.

        Uses: dot -Tsvg input.dot -o output.svg

        Returns:
            Path to generated SVG file, or None if rendering failed
        """
        svg_output = self.output_dir / "topology.svg"

        try:
            result = subprocess.run(
                ["dot", "-Tsvg", str(self.dot_file), "-o", str(svg_output)],
                capture_output=True,
                timeout=30,
                text=True,
            )

            if result.returncode == 0:
                return svg_output
            else:
                self.warnings.append(
                    f"SVG rendering failed: {result.stderr.strip()}"
                )
                return None

        except subprocess.TimeoutExpired:
            self.warnings.append("SVG rendering timed out (>30s)")
            return None
        except Exception as e:
            self.warnings.append(f"SVG rendering error: {e}")
            return None

    # =========================================================================
    # PNG Rendering
    # =========================================================================

    def _render_png(self) -> Optional[Path]:
        """
        Render DOT file to PNG format.

        Uses: dot -Tpng input.dot -o output.png

        Returns:
            Path to generated PNG file, or None if rendering failed
        """
        png_output = self.output_dir / "topology.png"

        try:
            result = subprocess.run(
                ["dot", "-Tpng", str(self.dot_file), "-o", str(png_output)],
                capture_output=True,
                timeout=30,
                text=True,
            )

            if result.returncode == 0:
                return png_output
            else:
                self.warnings.append(
                    f"PNG rendering failed: {result.stderr.strip()}"
                )
                return None

        except subprocess.TimeoutExpired:
            self.warnings.append("PNG rendering timed out (>30s)")
            return None
        except Exception as e:
            self.warnings.append(f"PNG rendering error: {e}")
            return None
