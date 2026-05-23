"""Main pipeline orchestrator — coordinates acquisition, IR, classification, verification, and reporting."""

from __future__ import annotations

import logging
import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.acquisition.fork_manager import ForkManager
from src.acquisition.trace_fetcher import TraceFetcher
from src.acquisition.etherscan_client import EtherscanClient
from src.agents.classifier import ExploitClassifier
from src.agents.blast_radius import BlastRadiusAnalyzer
from src.ir.lifter import IRLifter
from src.ir.visualizer import IRVisualizer
from src.llm.client import LLMClient
from src.verifier.causal import CausalVerifier
from src.verifier.predicates import PredicateEngine
from src.verifier.state_diff import StateDiffComputer
from src.verifier.verdict import VerdictEngine, VerdictReport
from src.report.render import ReportRenderer

logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    scenario_dir: Path
    rpc_url: str
    etherscan_api_key: str
    anthropic_api_key: str
    output_dir: Path = Path("output")
    skip_ablation: bool = False


class ForensicPipeline:
    """End-to-end forensic analysis pipeline."""

    def __init__(self, config: PipelineConfig):
        self._config = config
        self._llm = LLMClient(api_key=config.anthropic_api_key)
        self._fork_manager = ForkManager()
        self._trace_fetcher = TraceFetcher(rpc_url=config.rpc_url)
        self._etherscan = EtherscanClient(api_key=config.etherscan_api_key)
        self._lifter = IRLifter()
        self._visualizer = IRVisualizer()
        self._classifier = ExploitClassifier(llm_client=self._llm)
        self._blast_radius = BlastRadiusAnalyzer(llm_client=self._llm)
        self._predicate_engine = PredicateEngine()
        self._state_diff_computer = StateDiffComputer(rpc_url=config.rpc_url)
        self._causal_verifier = CausalVerifier(
            fork_manager=self._fork_manager, rpc_url=config.rpc_url
        )
        self._verdict_engine = VerdictEngine()
        self._reporter = ReportRenderer()

    def run(self, scenario_name: str) -> VerdictReport:
        """Execute the full forensic pipeline for a scenario."""
        logger.info(f"Starting forensic analysis for scenario: {scenario_name}")

        # 1. Load scenario config
        scenario_config = self._load_scenario(scenario_name)
        tx_hash = scenario_config["tx_hash"]
        fork_block = scenario_config["fork_block"]

        # 2. Acquire trace
        logger.info(f"Fetching trace for tx {tx_hash}")
        trace = self._trace_fetcher.fetch_trace(tx_hash)

        # 3. Fetch contract sources
        for contract in scenario_config.get("target_contracts", []):
            source = self._etherscan.get_source(contract["address"])
            logger.info(f"Fetched source for {source.name}")

        # 4. Lift to IR
        logger.info("Lifting trace to IR")
        ir_graph = self._lifter.lift(trace)

        # 5. Classify exploit
        logger.info("Classifying exploit technique")
        classification = self._classifier.classify(ir_graph)
        logger.info(
            f"Primary hypothesis: {classification.primary_hypothesis.technique} "
            f"(confidence: {classification.primary_hypothesis.confidence})"
        )

        # 6. Compute state diff
        # Include the attacker EOA, declared target contracts, and the attack
        # contract (tx.to stored in IR metadata) so profits that stay inside the
        # attack contract are captured rather than appearing as zero gains.
        addresses = [scenario_config["attacker_address"]] + [
            c["address"] for c in scenario_config.get("target_contracts", [])
        ]
        attack_contract = ir_graph.metadata.get("tx_to", "")
        if attack_contract and attack_contract.lower() not in {a.lower() for a in addresses}:
            addresses.append(attack_contract)

        tokens = scenario_config.get("tokens") or None
        state_diff = self._state_diff_computer.compute(tx_hash, addresses, tokens=tokens)

        # 7. Run predicates
        logger.info("Evaluating predicates")
        predicate_results = self._predicate_engine.evaluate_all(
            ir_graph, state_diff, scenario_config
        )

        # 8. Ablation testing (optional)
        ablation_results = []
        if not self._config.skip_ablation:
            logger.info("Running ablation tests")
            causal_factors = self._extract_causal_factors(classification)
            ablation_results = self._causal_verifier.run_ablation(
                tx_hash, fork_block, causal_factors
            )

        # 9. Produce verdict
        verdict = self._verdict_engine.evaluate(
            classification, predicate_results, ablation_results
        )
        logger.info(f"Verdict: {verdict.verdict.value} (confidence: {verdict.confidence})")

        # 10. Generate report
        mermaid = self._visualizer.to_mermaid_flowchart(ir_graph)
        self._reporter.render(
            verdict=verdict,
            ir_graph=ir_graph,
            mermaid_diagram=mermaid,
            scenario_config=scenario_config,
            output_path=self._config.output_dir / f"{scenario_name}_report.html",
        )

        return verdict

    def _load_scenario(self, name: str) -> dict[str, Any]:
        config_path = self._config.scenario_dir / name / "config.yaml"
        with open(config_path) as f:
            return yaml.safe_load(f)

    def _extract_causal_factors(self, classification) -> list[dict[str, Any]]:
        """Extract testable causal factors from the classification."""
        # TODO: map technique-specific factors to ablation test configs
        return []
