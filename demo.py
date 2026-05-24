"""Single-command entry point: python demo.py euler"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from src.orchestrator import ForensicPipeline, PipelineConfig


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if len(sys.argv) < 2:
        print("Usage: python demo.py <scenario_name>")
        print("Available scenarios: euler, nomad, beanstalk")
        sys.exit(1)

    scenario_name = sys.argv[1]
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
    )

    if not config.rpc_url:
        print("Error: MAINNET_RPC_URL not set. Copy .env.example to .env and fill in values.")
        sys.exit(1)

    pipeline = ForensicPipeline(config)
    verdict = pipeline.run(scenario_name)

    print(f"\n{'='*60}")
    print(f"Scenario:   {scenario_name}")
    print(f"Verdict:    {verdict.verdict.value}")
    print(f"Confidence: {verdict.confidence:.1%}")
    print(f"Technique:  {verdict.technique}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
