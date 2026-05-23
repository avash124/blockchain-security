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

    @pytest.mark.skip(reason="Requires RPC access and Anthropic API key")
    def test_pipeline_matches_expected(self, scenario_name: str):
        """Run the full pipeline and compare against expected.json."""
        # TODO: instantiate ForensicPipeline and compare verdict
        # with expected.json ground truth
        pass
