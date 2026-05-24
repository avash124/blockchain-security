"""Single-command entry point: python demo.py euler"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from src.ir.visualizer import IRVisualizer
from src.orchestrator import ForensicPipeline, PipelineConfig


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if len(sys.argv) < 2:
        print("Usage: python demo.py <scenario_name> [--skip-ablation|--run-ablation]")
        print("Available scenarios: euler, cream, harvest, beanstalk")
        sys.exit(1)

    args = sys.argv[1:]
    scenario_name = args[0]
    # Ablation is opt-in for now: the predefined causal factors in
    # _TECHNIQUE_FACTORS don't carry address/slot params yet, so the
    # ablation step burns 1–3 minutes per scenario producing only ERROR
    # outcomes. Use --run-ablation explicitly when you've populated the
    # factor params for the technique you're verifying.
    skip_ablation = "--run-ablation" not in args
    scenarios_dir = Path(__file__).parent / "scenarios"

    if not (scenarios_dir / scenario_name).exists():
        print(f"Error: scenario '{scenario_name}' not found in {scenarios_dir}")
        sys.exit(1)

    config = PipelineConfig(
        scenario_dir=scenarios_dir,
        rpc_url=os.getenv("MAINNET_RPC_URL", ""),
        etherscan_api_key=os.getenv("ETHERSCAN_API_KEY", ""),
        anthropic_api_key=os.getenv("OPENAI_API_KEY", ""),
        output_dir=Path("output"),
        skip_ablation=skip_ablation,
    )

    if not config.rpc_url:
        print("Error: MAINNET_RPC_URL not set. Copy .env.example to .env and fill in values.")
        sys.exit(1)

    pipeline = ForensicPipeline(config)
    verdict = pipeline.run(scenario_name)

    # Render the Mermaid forensic diagram (forensic flowchart + sequence
    # diagram + security findings) into a NEW standalone markdown file under
    # docs/ on every run — name includes scenario + timestamp so runs don't
    # overwrite each other.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    diagram_filename = f"diagram_{scenario_name}_{timestamp}.md"
    diagram_path = IRVisualizer().export_to_markdown(
        graph=pipeline.last_ir_graph,
        output_dir=Path(__file__).parent / "docs",
        scenario_config=pipeline.last_scenario_config,
        frame_count=len(pipeline.last_trace.frames),
        filename=diagram_filename,
    )

    blast = pipeline.last_blast_radius

    print(f"\n{'='*60}")
    print(f"Scenario:   {scenario_name}")
    print(f"Verdict:    {verdict.verdict.value}")
    print(f"Confidence: {verdict.confidence:.1%}")
    print(f"Technique:  {verdict.technique}")
    print(f"Diagram:    {diagram_path}")
    print(f"{'='*60}")

    print("\nBlast Radius")
    print(f"  Primary loss:        ${blast.primary_loss_usd:,.2f}")
    print(f"  Affected protocols:  {len(blast.affected_protocols)}")
    for ap in blast.affected_protocols:
        addr = f" [{ap.address}]" if ap.address else ""
        print(f"    - [{ap.risk_level:>6}] {ap.name}{addr} — {ap.relationship}")
    if blast.cascading_risks:
        print("  Cascading risks:")
        for risk in blast.cascading_risks:
            print(f"    - {risk}")
    if blast.recommendations:
        print("  Recommendations:")
        for rec in blast.recommendations:
            print(f"    - {rec}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
