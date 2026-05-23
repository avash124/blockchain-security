"""Renders the final HTML forensic report from a Jinja2 template."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.ir.nodes import IRGraph
from src.verifier.verdict import VerdictReport


class ReportRenderer:
    """Renders an HTML forensic report."""

    TEMPLATE_DIR = Path(__file__).parent
    TEMPLATE_NAME = "template.html.j2"

    def render(
        self,
        verdict: VerdictReport,
        ir_graph: IRGraph,
        mermaid_diagram: str,
        scenario_config: dict[str, Any],
        output_path: Path,
        security_fixes: list[dict[str, str]] | None = None,
    ) -> Path:
        """Render the report and write to disk."""
        try:
            from jinja2 import Environment, FileSystemLoader
        except ImportError:
            raise RuntimeError("Install jinja2: pip install jinja2")

        env = Environment(
            loader=FileSystemLoader(str(self.TEMPLATE_DIR)),
            autoescape=True,
        )
        template = env.get_template(self.TEMPLATE_NAME)

        html = template.render(
            scenario=scenario_config,
            verdict=verdict.to_dict(),
            mermaid=mermaid_diagram,
            actions=ir_graph.to_dict()["actions"],
            edges=ir_graph.to_dict()["edges"],
            security_fixes=security_fixes or [],
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html)
        return output_path
