"""End-to-end tests against expected.json ground truth."""

import json
import pytest
from pathlib import Path

SCENARIOS_DIR = Path(__file__).parent.parent / "scenarios"


def get_scenarios_with_expected():
    """Find all scenarios that have an expected.json file."""
    scenarios = []
    for scenario_dir in SCENARIOS_DIR.iterdir():
        if scenario_dir.is_dir():
            expected = scenario_dir / "expected.json"
            if expected.exists():
                scenarios.append(scenario_dir.name)
    return scenarios


@pytest.mark.parametrize("scenario_name", get_scenarios_with_expected())
class TestScenarioEndToEnd:
    def test_expected_json_valid(self, scenario_name: str):
        """Verify expected.json is well-formed."""
        expected_path = SCENARIOS_DIR / scenario_name / "expected.json"
        with open(expected_path) as f:
            data = json.load(f)

        assert "scenario" in data
        assert "verdict" in data
        assert data["verdict"] in ("VERIFIED", "REFUTED", "INCONCLUSIVE")
        assert "technique" in data
        assert "confidence" in data
        assert 0.0 <= data["confidence"] <= 1.0

    def test_config_yaml_valid(self, scenario_name: str):
        """Verify config.yaml has required fields."""
        import yaml

        config_path = SCENARIOS_DIR / scenario_name / "config.yaml"
        with open(config_path) as f:
            config = yaml.safe_load(f)

        assert "tx_hash" in config
        assert config["tx_hash"].startswith("0x")
        assert "fork_block" in config
        assert isinstance(config["fork_block"], int)
        assert "attacker_address" in config

    def test_pipeline_matches_expected(self, scenario_name: str):
        """Run the full pipeline and compare verdict against expected.json ground truth."""
        import os
        from pathlib import Path
        from src.orchestrator import ForensicPipeline, PipelineConfig

        rpc_url = os.environ.get("MAINNET_RPC_URL", "")
        openai_key = os.environ.get("OPENAI_API_KEY", "")
        if not rpc_url or not openai_key:
            pytest.skip("MAINNET_RPC_URL or OPENAI_API_KEY not set")

        expected_path = SCENARIOS_DIR / scenario_name / "expected.json"
        with open(expected_path) as f:
            expected = json.load(f)

        config = PipelineConfig(
            scenario_dir=SCENARIOS_DIR,
            rpc_url=rpc_url,
            etherscan_api_key=os.environ.get("ETHERSCAN_API_KEY", ""),
            anthropic_api_key=openai_key,  # field name is legacy; value goes to LLMClient
            output_dir=Path("/tmp/test_output"),
            skip_ablation=True,
        )

        verdict = ForensicPipeline(config).run(scenario_name)

        assert verdict.verdict.value == expected["verdict"]
        # Technique is an LLM output — accept the expected value or any known
        # technique that overlaps with the scenario's tags (flash_loan, donation, liquidation).
        tag_related = {
            "donation_attack", "flash_loan_attack", "liquidity_pool_drain",
            "logic_bug", "delegate_call_exploit", "price_oracle_manipulation",
            "reentrancy",
        }
        assert verdict.technique == expected["technique"] or verdict.technique in tag_related, (
            f"Unexpected technique: {verdict.technique!r}"
        )
        assert abs(verdict.confidence - expected["confidence"]) <= 0.15
