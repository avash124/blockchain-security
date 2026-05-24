"""Verbose test cases for the ForensicPipeline orchestrator.

Every test constructs its own addresses/hashes/blocks so nothing is coupled to
a single hardcoded scenario.  Where possible, real engines (PredicateEngine,
VerdictEngine) run against constructed data instead of being mocked — only
external I/O (RPC, LLM, Etherscan, Anvil, filesystem writes) is mocked.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call

import pytest
import yaml

from src.acquisition.etherscan_client import ContractSource, EtherscanClient
from src.acquisition.fork_manager import ForkManager
from src.acquisition.trace_fetcher import TraceFetcher, TransactionTrace, TraceFrame
from src.agents.blast_radius import BlastRadiusAnalyzer
from src.agents.classifier import (
    ClassificationResult,
    ExploitClassifier,
    Hypothesis,
)
from src.ir.lifter import IRLifter
from src.ir.nodes import ActionType, IRGraph, SemanticAction
from src.ir.visualizer import IRVisualizer
from src.llm.client import LLMClient
from src.orchestrator import ForensicPipeline, PipelineConfig, _TECHNIQUE_FACTORS
from src.report.render import ReportRenderer
from src.verifier.causal import AblationOutcome, AblationResult, CausalVerifier
from src.verifier.predicates import PredicateCheck, PredicateEngine, PredicateResult
from src.verifier.state_diff import BalanceChange, StateDiff, StateDiffComputer
from src.verifier.verdict import Verdict, VerdictEngine, VerdictReport


# =====================================================================
# Address / hash generators — no hardcoded constants
# =====================================================================

def _rand_addr() -> str:
    return "0x" + uuid.uuid4().hex[:40]


def _rand_tx_hash() -> str:
    return "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:32]


def _rand_block() -> int:
    return 16_000_000 + int(uuid.uuid4().int % 1_000_000)


# =====================================================================
# Builders — every field is explicit, nothing hidden behind defaults
# =====================================================================

def _build_scenario(
    *,
    tx_hash: str,
    fork_block: int,
    attacker: str,
    targets: list[dict[str, str]],
    tags: list[str] | None = None,
    tokens: list[str] | None = None,
    victim_addresses: list[str] | None = None,
    extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "tx_hash": tx_hash,
        "fork_block": fork_block,
        "attacker_address": attacker,
        "target_contracts": targets,
    }
    if tags is not None:
        cfg["tags"] = tags
    if tokens is not None:
        cfg["tokens"] = tokens
    if victim_addresses is not None:
        cfg["victim_addresses"] = victim_addresses
    if extras:
        cfg.update(extras)
    return cfg


def _build_trace(
    *,
    tx_hash: str,
    from_addr: str,
    to_addr: str,
    frame_count: int = 2,
) -> TransactionTrace:
    frames = [
        TraceFrame(
            pc=i * 10,
            op="CALL",
            gas=1_000_000 - i * 50_000,
            gas_cost=700,
            depth=min(i + 1, 4),
            stack=["0x0", "0x0"],
        )
        for i in range(frame_count)
    ]
    return TransactionTrace(
        tx_hash=tx_hash,
        from_addr=from_addr,
        to_addr=to_addr,
        value=0,
        gas_used=500_000,
        status=True,
        frames=frames,
    )


def _build_ir(
    *,
    tx_hash: str,
    tx_to: str,
    actions: list[SemanticAction],
) -> IRGraph:
    graph = IRGraph(tx_hash=tx_hash)
    graph.metadata["tx_to"] = tx_to
    for a in actions:
        graph.add_action(a)
    return graph


def _build_classification(
    *,
    technique: str,
    confidence: float,
    supporting_actions: list[str],
    alternatives: list[Hypothesis] | None = None,
) -> ClassificationResult:
    return ClassificationResult(
        primary_hypothesis=Hypothesis(
            technique=technique,
            confidence=confidence,
            reasoning=f"Detected {technique} pattern",
            supporting_actions=supporting_actions,
        ),
        alternative_hypotheses=alternatives or [],
        raw_llm_response=f'{{"primary_technique":"{technique}"}}',
    )


def _build_state_diff(
    changes: list[BalanceChange] | None = None,
    created: list[str] | None = None,
) -> StateDiff:
    return StateDiff(
        balance_changes=changes or [],
        created_contracts=created or [],
    )


def _build_verdict(
    *,
    verdict: Verdict,
    confidence: float,
    technique: str,
    reasoning: str = "",
    predicates: list[PredicateCheck] | None = None,
    ablations: list[AblationResult] | None = None,
) -> VerdictReport:
    return VerdictReport(
        verdict=verdict,
        confidence=confidence,
        technique=technique,
        reasoning=reasoning or f"{verdict.value} for {technique}",
        predicate_results=predicates or [],
        ablation_results=ablations or [],
    )


# =====================================================================
# Fixture that wires a fully-mocked pipeline with unique addresses
# =====================================================================

@pytest.fixture
def fresh_pipeline(tmp_path):
    """Return (pipeline, ids) where ids holds the random addresses/hash/block
    used for this specific test run, plus helpers to swap mocks."""

    attacker = _rand_addr()
    victim = _rand_addr()
    attack_contract = _rand_addr()
    tx_hash = _rand_tx_hash()
    fork_block = _rand_block()
    token_a = _rand_addr()

    scenario_dir = tmp_path / "scenarios"
    scenario_dir.mkdir()
    output_dir = tmp_path / "output"

    cfg = PipelineConfig(
        scenario_dir=scenario_dir,
        rpc_url="http://localhost:8545",
        etherscan_api_key="esk-test-" + uuid.uuid4().hex[:8],
        anthropic_api_key="ak-test-" + uuid.uuid4().hex[:8],
        output_dir=output_dir,
    )

    scenario_data = _build_scenario(
        tx_hash=tx_hash,
        fork_block=fork_block,
        attacker=attacker,
        targets=[{"address": victim, "name": "VictimProtocol"}],
        tags=["flash_loan"],
    )
    scenario_path = scenario_dir / "test_scenario"
    scenario_path.mkdir()
    (scenario_path / "config.yaml").write_text(yaml.dump(scenario_data))

    pipeline = ForensicPipeline(cfg)

    trace = _build_trace(tx_hash=tx_hash, from_addr=attacker, to_addr=attack_contract)
    pipeline._trace_fetcher = MagicMock(spec=TraceFetcher)
    pipeline._trace_fetcher.fetch_trace.return_value = trace

    pipeline._etherscan = MagicMock(spec=EtherscanClient)
    pipeline._etherscan.get_source.return_value = ContractSource(
        address=victim, name="VictimProtocol",
        compiler_version="0.8.19", source_code="contract V {}", abi=[],
    )

    ir_actions = [
        SemanticAction(ActionType.FLASH_LOAN_BORROW, depth=2,
                       from_addr=attacker, to_addr=_rand_addr(),
                       trace_index_start=0, trace_index_end=1),
        SemanticAction(ActionType.DEX_SWAP, depth=3,
                       from_addr=attack_contract, to_addr=_rand_addr(),
                       trace_index_start=2, trace_index_end=3),
        SemanticAction(ActionType.FLASH_LOAN_REPAY, depth=2,
                       from_addr=attack_contract, to_addr=_rand_addr(),
                       trace_index_start=4, trace_index_end=5),
    ]
    ir_graph = _build_ir(tx_hash=tx_hash, tx_to=attack_contract, actions=ir_actions)

    pipeline._lifter = MagicMock(spec=IRLifter)
    pipeline._lifter.lift.return_value = ir_graph

    classification = _build_classification(
        technique="flash_loan_attack", confidence=0.92,
        supporting_actions=["flash_loan_borrow_0", "dex_swap_2"],
    )
    pipeline._classifier = MagicMock(spec=ExploitClassifier)
    pipeline._classifier.classify.return_value = classification

    state_diff = _build_state_diff(changes=[
        BalanceChange(address=attacker.lower(), token="ETH",
                      before=1 * 10**18, after=11 * 10**18),
        BalanceChange(address=victim.lower(), token="ETH",
                      before=100 * 10**18, after=90 * 10**18),
    ])
    pipeline._state_diff_computer = MagicMock(spec=StateDiffComputer)
    pipeline._state_diff_computer.compute.return_value = state_diff

    pipeline._predicate_engine = MagicMock(spec=PredicateEngine)
    pipeline._predicate_engine.evaluate_all.return_value = [
        PredicateCheck(name="balance_increased", result=PredicateResult.PASS,
                       details=f"Attacker {attacker} gained 10 ETH"),
        PredicateCheck(name="flash_loan_detected", result=PredicateResult.PASS,
                       details="1 borrow, 1 repay"),
    ]

    pipeline._causal_verifier = MagicMock(spec=CausalVerifier)
    pipeline._causal_verifier.run_ablation.return_value = [
        AblationResult(factor_removed="flash_loan_capital",
                       outcome=AblationOutcome.REVERTED,
                       details="Tx reverted after zeroing flash-loan balance"),
    ]

    verdict_report = _build_verdict(
        verdict=Verdict.VERIFIED, confidence=0.88,
        technique="flash_loan_attack",
        reasoning="All predicates passed, ablation confirmed causality",
    )
    pipeline._verdict_engine = MagicMock(spec=VerdictEngine)
    pipeline._verdict_engine.evaluate.return_value = verdict_report

    pipeline._visualizer = MagicMock(spec=IRVisualizer)
    pipeline._visualizer.to_mermaid_flowchart.return_value = "graph TD\nA-->B"

    pipeline._reporter = MagicMock(spec=ReportRenderer)

    # Mock blast-radius analysis so run() doesn't try to hit the real LLM.
    from src.agents.blast_radius import BlastRadiusReport
    pipeline._blast_radius = MagicMock(spec=BlastRadiusAnalyzer)
    pipeline._blast_radius.analyze.return_value = BlastRadiusReport(
        primary_loss_usd=0.0,
    )

    ids = {
        "attacker": attacker,
        "victim": victim,
        "attack_contract": attack_contract,
        "tx_hash": tx_hash,
        "fork_block": fork_block,
        "token_a": token_a,
        "ir_graph": ir_graph,
        "trace": trace,
        "classification": classification,
        "state_diff": state_diff,
        "verdict": verdict_report,
        "scenario_data": scenario_data,
        "cfg": cfg,
    }

    return pipeline, ids


# =====================================================================
# PipelineConfig
# =====================================================================

class TestPipelineConfig:
    def test_default_output_dir_is_output(self):
        cfg = PipelineConfig(
            scenario_dir=Path("/tmp/s"),
            rpc_url="http://rpc.test",
            etherscan_api_key="ek",
            anthropic_api_key="ak",
        )
        assert cfg.output_dir == Path("output")

    def test_default_skip_ablation_false(self):
        cfg = PipelineConfig(
            scenario_dir=Path("/tmp/s"),
            rpc_url="http://rpc.test",
            etherscan_api_key="ek",
            anthropic_api_key="ak",
        )
        assert cfg.skip_ablation is False

    def test_custom_output_dir_preserved(self, tmp_path):
        custom = tmp_path / "my_reports"
        cfg = PipelineConfig(
            scenario_dir=tmp_path,
            rpc_url="http://rpc.test",
            etherscan_api_key="ek",
            anthropic_api_key="ak",
            output_dir=custom,
        )
        assert cfg.output_dir == custom

    def test_skip_ablation_true(self):
        cfg = PipelineConfig(
            scenario_dir=Path("/tmp/s"),
            rpc_url="http://rpc.test",
            etherscan_api_key="ek",
            anthropic_api_key="ak",
            skip_ablation=True,
        )
        assert cfg.skip_ablation is True

    def test_all_fields_stored(self, tmp_path):
        cfg = PipelineConfig(
            scenario_dir=tmp_path / "scen",
            rpc_url="http://mynode:8545",
            etherscan_api_key="EKEY",
            anthropic_api_key="AKEY",
            output_dir=tmp_path / "out",
            skip_ablation=True,
        )
        assert cfg.scenario_dir == tmp_path / "scen"
        assert cfg.rpc_url == "http://mynode:8545"
        assert cfg.etherscan_api_key == "EKEY"
        assert cfg.anthropic_api_key == "AKEY"
        assert cfg.output_dir == tmp_path / "out"
        assert cfg.skip_ablation is True


# =====================================================================
# ForensicPipeline.__init__
# =====================================================================

class TestPipelineInit:
    def test_creates_all_twelve_components(self, tmp_path):
        cfg = PipelineConfig(
            scenario_dir=tmp_path,
            rpc_url="http://localhost:8545",
            etherscan_api_key="ek",
            anthropic_api_key="ak",
        )
        pipeline = ForensicPipeline(cfg)

        assert isinstance(pipeline._llm, LLMClient)
        assert isinstance(pipeline._fork_manager, ForkManager)
        assert isinstance(pipeline._trace_fetcher, TraceFetcher)
        assert isinstance(pipeline._lifter, IRLifter)
        assert isinstance(pipeline._visualizer, IRVisualizer)
        assert isinstance(pipeline._classifier, ExploitClassifier)
        assert isinstance(pipeline._blast_radius, BlastRadiusAnalyzer)
        assert isinstance(pipeline._predicate_engine, PredicateEngine)
        assert isinstance(pipeline._state_diff_computer, StateDiffComputer)
        assert isinstance(pipeline._causal_verifier, CausalVerifier)
        assert isinstance(pipeline._verdict_engine, VerdictEngine)
        assert isinstance(pipeline._reporter, ReportRenderer)

    def test_llm_receives_anthropic_key(self, tmp_path):
        key = "ak-" + uuid.uuid4().hex
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url="http://rpc", etherscan_api_key="ek",
            anthropic_api_key=key,
        )
        pipeline = ForensicPipeline(cfg)
        assert pipeline._llm._api_key == key

    def test_trace_fetcher_receives_rpc_url(self, tmp_path):
        rpc = "http://my-rpc-node:9999"
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url=rpc, etherscan_api_key="ek",
            anthropic_api_key="ak",
        )
        pipeline = ForensicPipeline(cfg)
        assert pipeline._trace_fetcher._rpc._rpc_url == rpc

    def test_etherscan_receives_api_key(self, tmp_path):
        ekey = "esk-" + uuid.uuid4().hex
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url="http://rpc", etherscan_api_key=ekey,
            anthropic_api_key="ak",
        )
        pipeline = ForensicPipeline(cfg)
        assert pipeline._etherscan._api_key == ekey

    def test_state_diff_computer_receives_rpc_url(self, tmp_path):
        rpc = "http://state-diff-node:7777"
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url=rpc, etherscan_api_key="ek",
            anthropic_api_key="ak",
        )
        pipeline = ForensicPipeline(cfg)
        assert pipeline._state_diff_computer._rpc._rpc_url == rpc

    def test_classifier_shares_llm_with_pipeline(self, tmp_path):
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url="http://rpc", etherscan_api_key="ek",
            anthropic_api_key="ak",
        )
        pipeline = ForensicPipeline(cfg)
        assert pipeline._classifier._llm is pipeline._llm

    def test_blast_radius_shares_llm_with_pipeline(self, tmp_path):
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url="http://rpc", etherscan_api_key="ek",
            anthropic_api_key="ak",
        )
        pipeline = ForensicPipeline(cfg)
        assert pipeline._blast_radius._llm is pipeline._llm

    def test_causal_verifier_shares_fork_manager(self, tmp_path):
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url="http://rpc", etherscan_api_key="ek",
            anthropic_api_key="ak",
        )
        pipeline = ForensicPipeline(cfg)
        assert pipeline._causal_verifier._fork_manager is pipeline._fork_manager


# =====================================================================
# Scenario loading
# =====================================================================

class TestScenarioLoading:
    def test_load_returns_all_fields(self, tmp_path):
        tx = _rand_tx_hash()
        attacker = _rand_addr()
        victim = _rand_addr()
        block = _rand_block()
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url="http://rpc",
            etherscan_api_key="ek", anthropic_api_key="ak",
        )
        scenario = _build_scenario(
            tx_hash=tx, fork_block=block, attacker=attacker,
            targets=[{"address": victim, "name": "Proto"}],
            tags=["reentrancy"], tokens=[_rand_addr()],
        )
        path = tmp_path / "hack1"
        path.mkdir()
        (path / "config.yaml").write_text(yaml.dump(scenario))

        pipeline = ForensicPipeline(cfg)
        loaded = pipeline._load_scenario("hack1")

        assert loaded["tx_hash"] == tx
        assert loaded["fork_block"] == block
        assert loaded["attacker_address"] == attacker
        assert loaded["target_contracts"][0]["address"] == victim
        assert loaded["target_contracts"][0]["name"] == "Proto"
        assert loaded["tags"] == ["reentrancy"]
        assert len(loaded["tokens"]) == 1

    def test_load_multiple_targets(self, tmp_path):
        v1, v2, v3 = _rand_addr(), _rand_addr(), _rand_addr()
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url="http://rpc",
            etherscan_api_key="ek", anthropic_api_key="ak",
        )
        scenario = _build_scenario(
            tx_hash=_rand_tx_hash(), fork_block=_rand_block(),
            attacker=_rand_addr(),
            targets=[
                {"address": v1, "name": "A"},
                {"address": v2, "name": "B"},
                {"address": v3, "name": "C"},
            ],
        )
        path = tmp_path / "multi"
        path.mkdir()
        (path / "config.yaml").write_text(yaml.dump(scenario))

        loaded = ForensicPipeline(cfg)._load_scenario("multi")
        assert len(loaded["target_contracts"]) == 3
        assert [t["address"] for t in loaded["target_contracts"]] == [v1, v2, v3]

    def test_load_preserves_extra_fields(self, tmp_path):
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url="http://rpc",
            etherscan_api_key="ek", anthropic_api_key="ak",
        )
        scenario = _build_scenario(
            tx_hash=_rand_tx_hash(), fork_block=_rand_block(),
            attacker=_rand_addr(), targets=[],
            extras={"protocol_name": "Aave v3", "chain": "mainnet"},
        )
        path = tmp_path / "extra"
        path.mkdir()
        (path / "config.yaml").write_text(yaml.dump(scenario))

        loaded = ForensicPipeline(cfg)._load_scenario("extra")
        assert loaded["protocol_name"] == "Aave v3"
        assert loaded["chain"] == "mainnet"

    def test_load_missing_scenario_raises_file_not_found(self, tmp_path):
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url="http://rpc",
            etherscan_api_key="ek", anthropic_api_key="ak",
        )
        with pytest.raises(FileNotFoundError):
            ForensicPipeline(cfg)._load_scenario("does_not_exist")

    def test_load_scenario_without_optional_keys(self, tmp_path):
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url="http://rpc",
            etherscan_api_key="ek", anthropic_api_key="ak",
        )
        scenario = _build_scenario(
            tx_hash=_rand_tx_hash(), fork_block=_rand_block(),
            attacker=_rand_addr(), targets=[],
        )
        path = tmp_path / "bare"
        path.mkdir()
        (path / "config.yaml").write_text(yaml.dump(scenario))

        loaded = ForensicPipeline(cfg)._load_scenario("bare")
        assert "tags" not in loaded
        assert "tokens" not in loaded
        assert loaded["target_contracts"] == []


# =====================================================================
# Causal factor extraction — every technique + edge cases
# =====================================================================

class TestCausalFactorExtraction:
    """Each test constructs its own classification with explicit technique and
    supporting_actions, then verifies the exact factor dicts returned."""

    @pytest.fixture
    def pipeline(self, tmp_path):
        cfg = PipelineConfig(
            scenario_dir=tmp_path, rpc_url="http://rpc",
            etherscan_api_key="ek", anthropic_api_key="ak",
        )
        return ForensicPipeline(cfg)

    def test_flash_loan_attack_returns_two_factors_with_correct_fields(self, pipeline):
        actions = ["borrow_100", "swap_200"]
        cls = _build_classification(
            technique="flash_loan_attack", confidence=0.95,
            supporting_actions=actions,
        )
        factors = pipeline._extract_causal_factors(cls)

        assert len(factors) == 2

        assert factors[0]["name"] == "flash_loan_capital"
        assert factors[0]["factor_type"] == "zero_flash_loan"
        assert factors[0]["anvil_method"] == "anvil_setBalance"
        assert factors[0]["technique"] == "flash_loan_attack"
        assert factors[0]["supporting_action_ids"] == actions
        assert "description" in factors[0] and len(factors[0]["description"]) > 0

        assert factors[1]["name"] == "dex_price_manipulation"
        assert factors[1]["factor_type"] == "patch_dex_reserves"
        assert factors[1]["anvil_method"] == "anvil_setStorageAt"
        assert factors[1]["technique"] == "flash_loan_attack"
        assert factors[1]["supporting_action_ids"] == actions

    def test_price_oracle_manipulation_factors(self, pipeline):
        cls = _build_classification(
            technique="price_oracle_manipulation", confidence=0.88,
            supporting_actions=["oracle_read_5"],
        )
        factors = pipeline._extract_causal_factors(cls)

        assert len(factors) == 2
        assert factors[0]["name"] == "oracle_price"
        assert factors[0]["factor_type"] == "patch_oracle_price"
        assert factors[1]["name"] == "dex_spot_price"
        assert factors[1]["factor_type"] == "patch_dex_reserves"
        for f in factors:
            assert f["anvil_method"] == "anvil_setStorageAt"
            assert f["technique"] == "price_oracle_manipulation"

    def test_reentrancy_factors(self, pipeline):
        cls = _build_classification(
            technique="reentrancy", confidence=0.91,
            supporting_actions=["reenter_3"],
        )
        factors = pipeline._extract_causal_factors(cls)

        assert len(factors) == 2
        assert factors[0]["name"] == "reentrancy_guard"
        assert factors[0]["factor_type"] == "set_reentrancy_guard"
        assert factors[1]["name"] == "state_update_ordering"
        assert factors[1]["factor_type"] == "precommit_state"
        for f in factors:
            assert f["anvil_method"] == "anvil_setStorageAt"

    def test_governance_attack_factors(self, pipeline):
        cls = _build_classification(
            technique="governance_attack", confidence=0.85,
            supporting_actions=["vote_1"],
        )
        factors = pipeline._extract_causal_factors(cls)

        assert len(factors) == 2
        assert factors[0]["name"] == "flash_loan_votes"
        assert factors[0]["anvil_method"] == "anvil_setBalance"
        assert factors[0]["factor_type"] == "zero_flash_loan"
        assert factors[1]["name"] == "governance_quorum"
        assert factors[1]["anvil_method"] == "anvil_setStorageAt"
        assert factors[1]["factor_type"] == "patch_governance_quorum"

    def test_delegate_call_exploit_factors(self, pipeline):
        cls = _build_classification(
            technique="delegate_call_exploit", confidence=0.87,
            supporting_actions=["delegatecall_7"],
        )
        factors = pipeline._extract_causal_factors(cls)

        assert len(factors) == 2
        assert factors[0]["name"] == "delegatecall_target"
        assert factors[0]["anvil_method"] == "anvil_setCode"
        assert factors[0]["factor_type"] == "replace_implementation_code"
        assert factors[1]["name"] == "critical_storage_slot"
        assert factors[1]["anvil_method"] == "anvil_setStorageAt"
        assert factors[1]["factor_type"] == "precommit_state"

    def test_access_control_bypass_single_factor(self, pipeline):
        cls = _build_classification(
            technique="access_control_bypass", confidence=0.80,
            supporting_actions=["sstore_9"],
        )
        factors = pipeline._extract_causal_factors(cls)

        assert len(factors) == 1
        assert factors[0]["name"] == "ownership_slot"
        assert factors[0]["factor_type"] == "patch_access_control"
        assert factors[0]["anvil_method"] == "anvil_setStorageAt"

    def test_liquidity_pool_drain_factors(self, pipeline):
        cls = _build_classification(
            technique="liquidity_pool_drain", confidence=0.82,
            supporting_actions=["deposit_2", "withdraw_8"],
        )
        factors = pipeline._extract_causal_factors(cls)

        assert len(factors) == 2
        assert factors[0]["name"] == "flash_loan_capital"
        assert factors[0]["factor_type"] == "zero_flash_loan"
        assert factors[1]["name"] == "pool_share_precision"
        assert factors[1]["factor_type"] == "patch_pool_reserves"

    def test_sandwich_attack_single_factor(self, pipeline):
        cls = _build_classification(
            technique="sandwich_attack", confidence=0.78,
            supporting_actions=["front_run_swap_0"],
        )
        factors = pipeline._extract_causal_factors(cls)

        assert len(factors) == 1
        assert factors[0]["name"] == "front_run_swap"
        assert factors[0]["factor_type"] == "patch_dex_reserves"
        assert factors[0]["anvil_method"] == "anvil_setStorageAt"

    def test_self_destruct_exploit_factors(self, pipeline):
        cls = _build_classification(
            technique="self_destruct_exploit", confidence=0.83,
            supporting_actions=["selfdestruct_4"],
        )
        factors = pipeline._extract_causal_factors(cls)

        assert len(factors) == 2
        assert factors[0]["name"] == "selfdestruct_call"
        assert factors[0]["anvil_method"] == "anvil_setCode"
        assert factors[0]["factor_type"] == "replace_implementation_code"
        assert factors[1]["name"] == "target_eth_balance"
        assert factors[1]["anvil_method"] == "anvil_setBalance"
        assert factors[1]["factor_type"] == "set_balance"

    def test_logic_bug_single_factor(self, pipeline):
        cls = _build_classification(
            technique="logic_bug", confidence=0.76,
            supporting_actions=["overflow_11"],
        )
        factors = pipeline._extract_causal_factors(cls)

        assert len(factors) == 1
        assert factors[0]["name"] == "arithmetic_state"
        assert factors[0]["factor_type"] == "precommit_state"
        assert factors[0]["anvil_method"] == "anvil_setStorageAt"

    def test_unknown_technique_with_supporting_actions_generates_fallback_factors(self, pipeline):
        cls = _build_classification(
            technique="time_travel_exploit", confidence=0.60,
            supporting_actions=["warp_block_1", "drain_vault_2", "exit_3"],
        )
        factors = pipeline._extract_causal_factors(cls)

        assert len(factors) == 3
        for i, action_id in enumerate(["warp_block_1", "drain_vault_2", "exit_3"]):
            f = factors[i]
            assert f["name"] == f"causal_action_{i}"
            assert f["factor_type"] == "block_action"
            assert f["anvil_method"] == "anvil_setStorageAt"
            assert f["technique"] == "time_travel_exploit"
            assert f["supporting_action_ids"] == [action_id]
            assert action_id in f["description"]

    def test_unknown_technique_no_supporting_actions_returns_empty(self, pipeline):
        cls = _build_classification(
            technique="completely_novel", confidence=0.50,
            supporting_actions=[],
        )
        factors = pipeline._extract_causal_factors(cls)
        assert factors == []

    def test_supporting_action_ids_attached_to_every_factor(self, pipeline):
        actions = ["step_a", "step_b", "step_c"]
        cls = _build_classification(
            technique="flash_loan_attack", confidence=0.9,
            supporting_actions=actions,
        )
        factors = pipeline._extract_causal_factors(cls)
        for f in factors:
            assert f["supporting_action_ids"] is actions


# =====================================================================
# _TECHNIQUE_FACTORS mapping integrity
# =====================================================================

class TestTechniqueFactorsMapping:
    def test_covers_all_known_techniques(self):
        expected = {
            "flash_loan_attack", "price_oracle_manipulation", "reentrancy",
            "governance_attack", "delegate_call_exploit", "access_control_bypass",
            "liquidity_pool_drain", "sandwich_attack", "self_destruct_exploit",
            "logic_bug", "donation_attack",
        }
        assert set(_TECHNIQUE_FACTORS.keys()) == expected

    def test_every_factor_has_all_required_keys(self):
        required = {"name", "description", "factor_type", "anvil_method"}
        for technique, factors in _TECHNIQUE_FACTORS.items():
            for factor in factors:
                missing = required - factor.keys()
                assert not missing, (
                    f"{technique}/{factor.get('name','?')} missing: {missing}"
                )

    def test_factor_names_unique_within_each_technique(self):
        for technique, factors in _TECHNIQUE_FACTORS.items():
            names = [f["name"] for f in factors]
            assert len(names) == len(set(names)), (
                f"Duplicate names in {technique}: {names}"
            )

    def test_anvil_methods_are_valid_rpc_calls(self):
        valid = {"anvil_setBalance", "anvil_setStorageAt", "anvil_setCode"}
        for technique, factors in _TECHNIQUE_FACTORS.items():
            for f in factors:
                assert f["anvil_method"] in valid, (
                    f"{technique}/{f['name']}: invalid anvil method {f['anvil_method']!r}"
                )

    def test_descriptions_are_nonempty_strings(self):
        for technique, factors in _TECHNIQUE_FACTORS.items():
            for f in factors:
                assert isinstance(f["description"], str)
                assert len(f["description"].strip()) > 10, (
                    f"{technique}/{f['name']}: description too short"
                )

    def test_factor_types_are_nonempty_strings(self):
        for technique, factors in _TECHNIQUE_FACTORS.items():
            for f in factors:
                assert isinstance(f["factor_type"], str)
                assert len(f["factor_type"]) > 0

    def test_every_technique_has_at_least_one_factor(self):
        for technique, factors in _TECHNIQUE_FACTORS.items():
            assert len(factors) >= 1, f"{technique} has no factors"


# =====================================================================
# Full pipeline run — happy path
# =====================================================================

class TestPipelineRunHappyPath:
    def test_returns_verdict_report_with_correct_type_and_values(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        result = pipeline.run("test_scenario")

        assert isinstance(result, VerdictReport)
        assert result.verdict == Verdict.VERIFIED
        assert result.confidence == pytest.approx(0.88)
        assert result.technique == "flash_loan_attack"

    def test_trace_fetched_with_scenario_tx_hash(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        pipeline._trace_fetcher.fetch_trace.assert_called_once_with(ids["tx_hash"])

    def test_etherscan_called_for_each_target_contract(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        pipeline._etherscan.get_source.assert_called_once_with(ids["victim"])

    def test_etherscan_called_for_multiple_targets(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        second_victim = _rand_addr()

        scenario = ids["scenario_data"].copy()
        scenario["target_contracts"].append(
            {"address": second_victim, "name": "SecondProtocol"}
        )
        path = ids["cfg"].scenario_dir / "test_scenario" / "config.yaml"
        path.write_text(yaml.dump(scenario))

        pipeline.run("test_scenario")

        assert pipeline._etherscan.get_source.call_count == 2
        called_addresses = [c.args[0] for c in pipeline._etherscan.get_source.call_args_list]
        assert ids["victim"] in called_addresses
        assert second_victim in called_addresses

    def test_lifter_receives_the_fetched_trace(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        pipeline._lifter.lift.assert_called_once_with(ids["trace"])

    def test_classifier_receives_the_lifted_ir_graph(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        passed_graph = pipeline._classifier.classify.call_args[0][0]
        assert passed_graph is ids["ir_graph"]
        assert passed_graph.tx_hash == ids["tx_hash"]
        assert len(passed_graph.actions) == 3

    def test_state_diff_receives_attacker_victim_and_attack_contract(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        call_args = pipeline._state_diff_computer.compute.call_args
        tx_hash_arg = call_args[0][0]
        addresses_arg = call_args[0][1]

        assert tx_hash_arg == ids["tx_hash"]
        lower_addrs = {a.lower() for a in addresses_arg}
        assert ids["attacker"].lower() in lower_addrs
        assert ids["victim"].lower() in lower_addrs
        assert ids["attack_contract"].lower() in lower_addrs

    def test_state_diff_receives_tokens_when_present(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        token = ids["token_a"]

        scenario = ids["scenario_data"].copy()
        scenario["tokens"] = [token]
        path = ids["cfg"].scenario_dir / "test_scenario" / "config.yaml"
        path.write_text(yaml.dump(scenario))

        pipeline.run("test_scenario")

        call_kwargs = pipeline._state_diff_computer.compute.call_args[1]
        assert call_kwargs["tokens"] == [token]

    def test_state_diff_receives_none_tokens_when_absent(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        call_kwargs = pipeline._state_diff_computer.compute.call_args[1]
        assert call_kwargs["tokens"] is None

    def test_predicates_receive_ir_graph_state_diff_and_config(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        args = pipeline._predicate_engine.evaluate_all.call_args[0]
        assert args[0] is ids["ir_graph"]
        assert args[1] is ids["state_diff"]
        assert args[2]["tx_hash"] == ids["tx_hash"]
        assert args[2]["attacker_address"] == ids["attacker"]

    def test_ablation_receives_tx_hash_block_and_factors(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        call_args = pipeline._causal_verifier.run_ablation.call_args[0]
        assert call_args[0] == ids["tx_hash"]
        assert call_args[1] == ids["fork_block"]

        factors = call_args[2]
        assert len(factors) == 2
        assert factors[0]["name"] == "flash_loan_capital"
        assert factors[0]["technique"] == "flash_loan_attack"
        assert factors[1]["name"] == "dex_price_manipulation"

    def test_verdict_engine_receives_classification_predicates_ablations(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        args = pipeline._verdict_engine.evaluate.call_args[0]
        classification_arg = args[0]
        predicate_arg = args[1]
        ablation_arg = args[2]

        assert classification_arg is ids["classification"]
        assert classification_arg.primary_hypothesis.technique == "flash_loan_attack"
        assert len(predicate_arg) == 2
        assert predicate_arg[0].name == "balance_increased"
        assert predicate_arg[0].result == PredicateResult.PASS
        assert predicate_arg[1].name == "flash_loan_detected"
        assert len(ablation_arg) == 1
        assert ablation_arg[0].factor_removed == "flash_loan_capital"
        assert ablation_arg[0].outcome == AblationOutcome.REVERTED

    def test_visualizer_receives_ir_graph(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        pipeline._visualizer.to_mermaid_flowchart.assert_called_once_with(ids["ir_graph"])

    def test_reporter_receives_all_final_artifacts(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        pipeline._reporter.render.assert_called_once()
        kw = pipeline._reporter.render.call_args[1]

        assert kw["verdict"] is ids["verdict"]
        assert kw["verdict"].verdict == Verdict.VERIFIED
        assert kw["ir_graph"] is ids["ir_graph"]
        assert kw["mermaid_diagram"] == "graph TD\nA-->B"
        assert kw["scenario_config"]["tx_hash"] == ids["tx_hash"]
        assert kw["scenario_config"]["attacker_address"] == ids["attacker"]
        assert kw["output_path"] == ids["cfg"].output_dir / "test_scenario_report.html"

    def test_report_output_path_uses_scenario_name(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        scenario = ids["scenario_data"].copy()
        path = ids["cfg"].scenario_dir / "tornado_cash"
        path.mkdir()
        (path / "config.yaml").write_text(yaml.dump(scenario))

        pipeline.run("tornado_cash")

        kw = pipeline._reporter.render.call_args[1]
        assert kw["output_path"].name == "tornado_cash_report.html"


# =====================================================================
# Pipeline step ordering
# =====================================================================

class TestPipelineStepOrdering:
    def test_all_ten_steps_execute_in_documented_order(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        call_order = []

        def tracker(name, return_value):
            def fn(*a, **kw):
                call_order.append(name)
                return return_value
            return fn

        pipeline._trace_fetcher.fetch_trace.side_effect = tracker("1_fetch_trace", ids["trace"])
        pipeline._etherscan.get_source.side_effect = tracker("2_fetch_source", ContractSource(
            address=ids["victim"], name="V", compiler_version="", source_code="", abi=[],
        ))
        pipeline._lifter.lift.side_effect = tracker("3_lift_ir", ids["ir_graph"])
        pipeline._classifier.classify.side_effect = tracker("4_classify", ids["classification"])
        pipeline._state_diff_computer.compute.side_effect = tracker("5_state_diff", ids["state_diff"])
        pipeline._predicate_engine.evaluate_all.side_effect = tracker("6_predicates", [
            PredicateCheck(name="p", result=PredicateResult.PASS),
        ])
        pipeline._causal_verifier.run_ablation.side_effect = tracker("7_ablation", [
            AblationResult(factor_removed="f", outcome=AblationOutcome.REVERTED),
        ])
        pipeline._verdict_engine.evaluate.side_effect = tracker("8_verdict", ids["verdict"])
        pipeline._visualizer.to_mermaid_flowchart.side_effect = tracker("9_mermaid", "graph TD")
        pipeline._reporter.render.side_effect = tracker("10_render", None)

        pipeline.run("test_scenario")

        assert call_order == [
            "1_fetch_trace", "2_fetch_source", "3_lift_ir", "4_classify",
            "5_state_diff", "6_predicates", "7_ablation", "8_verdict",
            "9_mermaid", "10_render",
        ]


# =====================================================================
# Skip ablation
# =====================================================================

class TestPipelineSkipAblation:
    def test_causal_verifier_not_called_when_skip_ablation_true(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        pipeline._config.skip_ablation = True

        pipeline.run("test_scenario")

        pipeline._causal_verifier.run_ablation.assert_not_called()

    def test_verdict_receives_empty_ablation_list_when_skipped(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        pipeline._config.skip_ablation = True

        pipeline.run("test_scenario")

        ablation_arg = pipeline._verdict_engine.evaluate.call_args[0][2]
        assert ablation_arg == []

    def test_all_other_steps_still_execute_when_ablation_skipped(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        pipeline._config.skip_ablation = True

        pipeline.run("test_scenario")

        pipeline._trace_fetcher.fetch_trace.assert_called_once()
        pipeline._etherscan.get_source.assert_called_once()
        pipeline._lifter.lift.assert_called_once()
        pipeline._classifier.classify.assert_called_once()
        pipeline._state_diff_computer.compute.assert_called_once()
        pipeline._predicate_engine.evaluate_all.assert_called_once()
        pipeline._verdict_engine.evaluate.assert_called_once()
        pipeline._visualizer.to_mermaid_flowchart.assert_called_once()
        pipeline._reporter.render.assert_called_once()


# =====================================================================
# State diff address collection — attack contract edge cases
# =====================================================================

class TestStateDiffAddressCollection:
    def test_attack_contract_from_ir_metadata_appended(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        addresses = pipeline._state_diff_computer.compute.call_args[0][1]
        lower_addrs = [a.lower() for a in addresses]
        assert ids["attack_contract"].lower() in lower_addrs

    def test_attack_contract_not_duplicated_when_already_in_targets(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        scenario = ids["scenario_data"].copy()
        scenario["target_contracts"].append(
            {"address": ids["attack_contract"], "name": "AttackCtx"}
        )
        path = ids["cfg"].scenario_dir / "test_scenario" / "config.yaml"
        path.write_text(yaml.dump(scenario))

        pipeline.run("test_scenario")

        addresses = pipeline._state_diff_computer.compute.call_args[0][1]
        lower_addrs = [a.lower() for a in addresses]
        assert lower_addrs.count(ids["attack_contract"].lower()) == 1

    def test_no_attack_contract_appended_when_ir_metadata_empty(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        ids["ir_graph"].metadata["tx_to"] = ""

        pipeline.run("test_scenario")

        addresses = pipeline._state_diff_computer.compute.call_args[0][1]
        assert len(addresses) == 2
        lower_addrs = {a.lower() for a in addresses}
        assert ids["attacker"].lower() in lower_addrs
        assert ids["victim"].lower() in lower_addrs

    def test_case_insensitive_dedup(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        upper_addr = ids["attack_contract"].upper().replace("0X", "0x")
        scenario = ids["scenario_data"].copy()
        scenario["target_contracts"].append(
            {"address": upper_addr, "name": "UpperCase"}
        )
        path = ids["cfg"].scenario_dir / "test_scenario" / "config.yaml"
        path.write_text(yaml.dump(scenario))

        pipeline.run("test_scenario")

        addresses = pipeline._state_diff_computer.compute.call_args[0][1]
        lower_addrs = [a.lower() for a in addresses]
        assert lower_addrs.count(ids["attack_contract"].lower()) == 1


# =====================================================================
# No target contracts
# =====================================================================

class TestPipelineNoTargetContracts:
    def test_etherscan_not_called_with_no_targets(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        scenario = ids["scenario_data"].copy()
        scenario["target_contracts"] = []
        path = ids["cfg"].scenario_dir / "test_scenario" / "config.yaml"
        path.write_text(yaml.dump(scenario))

        pipeline.run("test_scenario")

        pipeline._etherscan.get_source.assert_not_called()

    def test_state_diff_still_includes_attacker_and_attack_contract(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        scenario = ids["scenario_data"].copy()
        scenario["target_contracts"] = []
        path = ids["cfg"].scenario_dir / "test_scenario" / "config.yaml"
        path.write_text(yaml.dump(scenario))

        pipeline.run("test_scenario")

        addresses = pipeline._state_diff_computer.compute.call_args[0][1]
        lower_addrs = {a.lower() for a in addresses}
        assert ids["attacker"].lower() in lower_addrs
        assert ids["attack_contract"].lower() in lower_addrs

    def test_pipeline_still_completes_with_no_targets(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        scenario = ids["scenario_data"].copy()
        scenario["target_contracts"] = []
        path = ids["cfg"].scenario_dir / "test_scenario" / "config.yaml"
        path.write_text(yaml.dump(scenario))

        result = pipeline.run("test_scenario")
        assert isinstance(result, VerdictReport)


# =====================================================================
# Technique variants — different classifiers → different factors
# =====================================================================

class TestPipelineTechniqueVariants:
    def test_reentrancy_passes_reentrancy_factors_to_ablation(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        pipeline._classifier.classify.return_value = _build_classification(
            technique="reentrancy", confidence=0.90,
            supporting_actions=["reenter_callback_3"],
        )

        pipeline.run("test_scenario")

        factors = pipeline._causal_verifier.run_ablation.call_args[0][2]
        assert len(factors) == 2
        assert factors[0]["name"] == "reentrancy_guard"
        assert factors[0]["technique"] == "reentrancy"
        assert factors[0]["supporting_action_ids"] == ["reenter_callback_3"]
        assert factors[1]["name"] == "state_update_ordering"

    def test_delegate_call_passes_delegate_factors_to_ablation(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        pipeline._classifier.classify.return_value = _build_classification(
            technique="delegate_call_exploit", confidence=0.85,
            supporting_actions=["delegatecall_to_impl_7"],
        )

        pipeline.run("test_scenario")

        factors = pipeline._causal_verifier.run_ablation.call_args[0][2]
        assert len(factors) == 2
        assert factors[0]["name"] == "delegatecall_target"
        assert factors[0]["anvil_method"] == "anvil_setCode"
        assert factors[1]["name"] == "critical_storage_slot"

    def test_unknown_technique_with_actions_generates_fallback(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        pipeline._classifier.classify.return_value = _build_classification(
            technique="quantum_exploit", confidence=0.55,
            supporting_actions=["entangle_1", "collapse_2"],
        )

        pipeline.run("test_scenario")

        factors = pipeline._causal_verifier.run_ablation.call_args[0][2]
        assert len(factors) == 2
        assert factors[0]["name"] == "causal_action_0"
        assert factors[0]["supporting_action_ids"] == ["entangle_1"]
        assert factors[1]["name"] == "causal_action_1"
        assert factors[1]["supporting_action_ids"] == ["collapse_2"]

    def test_unknown_technique_no_actions_sends_empty_factors(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        pipeline._classifier.classify.return_value = _build_classification(
            technique="void_exploit", confidence=0.40,
            supporting_actions=[],
        )

        pipeline.run("test_scenario")

        factors = pipeline._causal_verifier.run_ablation.call_args[0][2]
        assert factors == []


# =====================================================================
# Alternative hypotheses — only primary used for ablation
# =====================================================================

class TestPipelineAlternativeHypotheses:
    def test_ablation_factors_come_from_primary_not_alternatives(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        alt = Hypothesis(
            technique="price_oracle_manipulation",
            confidence=0.35,
            reasoning="secondary hypothesis",
            supporting_actions=["oracle_read_99"],
        )
        pipeline._classifier.classify.return_value = _build_classification(
            technique="flash_loan_attack", confidence=0.92,
            supporting_actions=["borrow_0"],
            alternatives=[alt],
        )

        pipeline.run("test_scenario")

        factors = pipeline._causal_verifier.run_ablation.call_args[0][2]
        for f in factors:
            assert f["technique"] == "flash_loan_attack"

    def test_alternative_hypotheses_dont_affect_factor_count(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        alts = [
            Hypothesis(technique="reentrancy", confidence=0.3, reasoning="alt1"),
            Hypothesis(technique="logic_bug", confidence=0.2, reasoning="alt2"),
        ]
        pipeline._classifier.classify.return_value = _build_classification(
            technique="sandwich_attack", confidence=0.7,
            supporting_actions=["swap_0"],
            alternatives=alts,
        )

        pipeline.run("test_scenario")

        factors = pipeline._causal_verifier.run_ablation.call_args[0][2]
        assert len(factors) == 1
        assert factors[0]["name"] == "front_run_swap"


# =====================================================================
# Real VerdictEngine integration — no mocking the engine
# =====================================================================

class TestPipelineWithRealVerdictEngine:
    def test_all_pass_predicates_produce_verified(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline._verdict_engine = VerdictEngine()
        pipeline._predicate_engine.evaluate_all.return_value = [
            PredicateCheck(name="balance_increased", result=PredicateResult.PASS),
            PredicateCheck(name="flash_loan_detected", result=PredicateResult.PASS),
        ]
        pipeline._causal_verifier.run_ablation.return_value = [
            AblationResult(factor_removed="flash_loan_capital",
                           outcome=AblationOutcome.REVERTED),
        ]

        result = pipeline.run("test_scenario")

        assert result.verdict == Verdict.VERIFIED
        assert result.confidence >= 0.8
        assert result.technique == "flash_loan_attack"
        assert len(result.predicate_results) == 2
        assert len(result.ablation_results) == 1
        assert result.classification is ids["classification"]

    def test_all_fail_predicates_produce_refuted(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline._verdict_engine = VerdictEngine()
        pipeline._predicate_engine.evaluate_all.return_value = [
            PredicateCheck(name="balance_increased", result=PredicateResult.FAIL),
            PredicateCheck(name="flash_loan_detected", result=PredicateResult.FAIL),
        ]
        pipeline._causal_verifier.run_ablation.return_value = [
            AblationResult(factor_removed="flash_loan_capital",
                           outcome=AblationOutcome.UNCHANGED),
        ]

        result = pipeline.run("test_scenario")

        assert result.verdict == Verdict.REFUTED
        assert result.confidence <= 0.2

    def test_mixed_evidence_produces_inconclusive(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline._verdict_engine = VerdictEngine()
        pipeline._predicate_engine.evaluate_all.return_value = [
            PredicateCheck(name="balance_increased", result=PredicateResult.PASS),
            PredicateCheck(name="flash_loan_detected", result=PredicateResult.FAIL),
        ]
        pipeline._causal_verifier.run_ablation.return_value = []

        result = pipeline.run("test_scenario")

        assert result.verdict == Verdict.INCONCLUSIVE
        assert 0.2 < result.confidence < 0.8

    def test_no_predicates_no_ablation_produces_inconclusive_at_half(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline._verdict_engine = VerdictEngine()
        pipeline._config.skip_ablation = True
        pipeline._predicate_engine.evaluate_all.return_value = []

        result = pipeline.run("test_scenario")

        assert result.verdict == Verdict.INCONCLUSIVE
        assert result.confidence == pytest.approx(0.5)

    def test_verdict_reasoning_includes_technique_and_counts(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline._verdict_engine = VerdictEngine()
        pipeline._predicate_engine.evaluate_all.return_value = [
            PredicateCheck(name="bal_up", result=PredicateResult.PASS),
            PredicateCheck(name="bal_down", result=PredicateResult.FAIL),
            PredicateCheck(name="skipped", result=PredicateResult.SKIP),
        ]
        pipeline._causal_verifier.run_ablation.return_value = [
            AblationResult(factor_removed="factor_x", outcome=AblationOutcome.NO_PROFIT),
        ]

        result = pipeline.run("test_scenario")

        assert "flash_loan_attack" in result.reasoning
        assert "3 predicates" in result.reasoning
        assert "1 passed" in result.reasoning
        assert "1 failed" in result.reasoning
        assert "1 skipped" in result.reasoning
        assert "1 ablation" in result.reasoning
        assert "factor_x" in result.reasoning


# =====================================================================
# Real PredicateEngine integration — no mocking predicates
# =====================================================================

class TestPipelineWithRealPredicateEngine:
    def test_real_predicates_detect_flash_loan_and_balance_gain(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline._predicate_engine = PredicateEngine()
        pipeline._verdict_engine = VerdictEngine()

        result = pipeline.run("test_scenario")

        pred_names = [p.name for p in result.predicate_results]
        assert "balance_increased" in pred_names
        assert "flash_loan_detected" in pred_names

        bal_check = next(p for p in result.predicate_results if p.name == "balance_increased")
        assert bal_check.result == PredicateResult.PASS

        flash_check = next(p for p in result.predicate_results if p.name == "flash_loan_detected")
        assert flash_check.result == PredicateResult.PASS

    def test_real_predicates_detect_victim_balance_decrease(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        scenario = ids["scenario_data"].copy()
        scenario["victim_addresses"] = [ids["victim"]]
        path = ids["cfg"].scenario_dir / "test_scenario" / "config.yaml"
        path.write_text(yaml.dump(scenario))

        pipeline._predicate_engine = PredicateEngine()
        pipeline._verdict_engine = VerdictEngine()

        result = pipeline.run("test_scenario")

        bal_down = next(
            (p for p in result.predicate_results if p.name == "balance_decreased"),
            None,
        )
        assert bal_down is not None
        assert bal_down.result == PredicateResult.PASS


# =====================================================================
# Edge cases
# =====================================================================

class TestPipelineEdgeCases:
    def test_scenario_without_tags_key(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        scenario = ids["scenario_data"].copy()
        scenario.pop("tags", None)
        path = ids["cfg"].scenario_dir / "test_scenario" / "config.yaml"
        path.write_text(yaml.dump(scenario))

        result = pipeline.run("test_scenario")
        assert isinstance(result, VerdictReport)

    def test_scenario_without_tokens_key(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        pipeline.run("test_scenario")

        call_kwargs = pipeline._state_diff_computer.compute.call_args[1]
        assert call_kwargs["tokens"] is None

    def test_empty_tokens_list_treated_as_none(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        scenario = ids["scenario_data"].copy()
        scenario["tokens"] = []
        path = ids["cfg"].scenario_dir / "test_scenario" / "config.yaml"
        path.write_text(yaml.dump(scenario))

        pipeline.run("test_scenario")

        call_kwargs = pipeline._state_diff_computer.compute.call_args[1]
        assert call_kwargs["tokens"] is None

    def test_multiple_scenarios_use_different_output_paths(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        for name in ["hack_a", "hack_b", "hack_c"]:
            scenario = ids["scenario_data"].copy()
            path = ids["cfg"].scenario_dir / name
            path.mkdir()
            (path / "config.yaml").write_text(yaml.dump(scenario))
            pipeline.run(name)

        render_calls = pipeline._reporter.render.call_args_list
        output_paths = [c[1]["output_path"].name for c in render_calls]
        assert "hack_a_report.html" in output_paths
        assert "hack_b_report.html" in output_paths
        assert "hack_c_report.html" in output_paths

    def test_ir_graph_with_no_tx_to_metadata(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        ids["ir_graph"].metadata.clear()

        pipeline.run("test_scenario")

        addresses = pipeline._state_diff_computer.compute.call_args[0][1]
        assert len(addresses) == 2

    def test_classification_with_zero_confidence_still_runs(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline
        pipeline._classifier.classify.return_value = _build_classification(
            technique="flash_loan_attack", confidence=0.0,
            supporting_actions=["x"],
        )

        result = pipeline.run("test_scenario")
        assert isinstance(result, VerdictReport)

    def test_many_target_contracts_all_fetched(self, fresh_pipeline):
        pipeline, ids = fresh_pipeline

        targets = [{"address": _rand_addr(), "name": f"P{i}"} for i in range(10)]
        scenario = ids["scenario_data"].copy()
        scenario["target_contracts"] = targets
        path = ids["cfg"].scenario_dir / "test_scenario" / "config.yaml"
        path.write_text(yaml.dump(scenario))

        pipeline.run("test_scenario")

        assert pipeline._etherscan.get_source.call_count == 10
        fetched_addrs = {c.args[0] for c in pipeline._etherscan.get_source.call_args_list}
        expected_addrs = {t["address"] for t in targets}
        assert fetched_addrs == expected_addrs