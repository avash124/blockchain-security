"""Unit tests for BlastRadiusAnalyzer."""

import json
import pytest
from unittest.mock import MagicMock

from src.agents.blast_radius import BlastRadiusAnalyzer, AffectedProtocol
from src.ir.nodes import IRGraph, SemanticAction, ActionType
from src.verifier.state_diff import StateDiff, BalanceChange
from src.llm.client import LLMResponse


# ------------------------------------------------------------------
# Shared fixtures
# ------------------------------------------------------------------

def make_graph() -> IRGraph:
    graph = IRGraph(tx_hash="0xtest")
    graph.add_action(SemanticAction(
        action_type=ActionType.FLASH_LOAN_BORROW,
        depth=1, from_addr="0xattacker", to_addr="0xlender",
    ))
    graph.add_action(SemanticAction(
        action_type=ActionType.TOKEN_TRANSFER,
        depth=1, from_addr="0xlender", to_addr="0xpool",
    ))
    return graph


def make_diff() -> StateDiff:
    return StateDiff(balance_changes=[
        BalanceChange(address="0xattacker", token="ETH", before=0, after=int(1e18)),
        BalanceChange(address="0xvictim",   token="ETH", before=int(2e18), after=0),
    ])


def make_llm_response(content: str) -> LLMResponse:
    return LLMResponse(
        content=content,
        model="gpt-4o",
        input_tokens=100,
        output_tokens=50,
        stop_reason="stop",
    )


_VALID_LLM_JSON = json.dumps({
    "affected_protocols": [
        {
            "name": "Aave",
            "address": "0xabc",
            "relationship": "oracle dependency",
            "risk_level": "high",
            "details": "",
        }
    ],
    "cascading_risks": ["risk1"],
    "recommendations": ["rec1"],
})


def make_analyzer(llm_response: LLMResponse | None = None) -> BlastRadiusAnalyzer:
    mock_llm = MagicMock()
    if llm_response is not None:
        mock_llm.complete.return_value = llm_response
    return BlastRadiusAnalyzer(llm_client=mock_llm)


# ------------------------------------------------------------------
# _find_shared_dependencies
# ------------------------------------------------------------------

class TestFindSharedDependencies:
    def test_returns_dependency_action_to_addrs(self):
        analyzer = make_analyzer()
        deps = analyzer._find_shared_dependencies(make_graph())
        # root = actions[0].to_addr = "0xlender" → excluded
        # TOKEN_TRANSFER to "0xpool" → included
        assert "0xpool" in deps
        assert "0xlender" not in deps

    def test_excludes_root_contract(self):
        analyzer = make_analyzer()
        graph = IRGraph(tx_hash="0xtest")
        graph.add_action(SemanticAction(
            action_type=ActionType.ORACLE_READ,
            depth=1, from_addr="0xattacker", to_addr="0xoracle",
        ))
        graph.add_action(SemanticAction(
            action_type=ActionType.DEX_SWAP,
            depth=1, from_addr="0xattacker", to_addr="0xdex",
        ))
        deps = analyzer._find_shared_dependencies(graph)
        assert "0xoracle" not in deps
        assert "0xdex" in deps

    def test_includes_storage_read_and_write(self):
        analyzer = make_analyzer()
        graph = IRGraph(tx_hash="0xtest")
        graph.add_action(SemanticAction(
            action_type=ActionType.FLASH_LOAN_BORROW,
            depth=1, from_addr="0xattacker", to_addr="0xlender",
        ))
        graph.add_action(SemanticAction(
            action_type=ActionType.STORAGE_READ,
            depth=1, from_addr="0xattacker", to_addr="0xstore1",
        ))
        graph.add_action(SemanticAction(
            action_type=ActionType.STORAGE_WRITE,
            depth=1, from_addr="0xattacker", to_addr="0xstore2",
        ))
        deps = analyzer._find_shared_dependencies(graph)
        assert "0xstore1" in deps
        assert "0xstore2" in deps

    def test_no_duplicates(self):
        analyzer = make_analyzer()
        graph = IRGraph(tx_hash="0xtest")
        graph.add_action(SemanticAction(
            action_type=ActionType.ORACLE_READ,
            depth=1, from_addr="0xattacker", to_addr="0xroot",
        ))
        graph.add_action(SemanticAction(
            action_type=ActionType.DEX_SWAP,
            depth=1, from_addr="0xattacker", to_addr="0xdex",
        ))
        graph.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER,
            depth=1, from_addr="0xattacker", to_addr="0xdex",
        ))
        deps = analyzer._find_shared_dependencies(graph)
        assert deps.count("0xdex") == 1

    def test_empty_graph_returns_empty(self):
        analyzer = make_analyzer()
        deps = analyzer._find_shared_dependencies(IRGraph(tx_hash="0xtest"))
        assert deps == []

    def test_returns_sorted_list(self):
        analyzer = make_analyzer()
        graph = IRGraph(tx_hash="0xtest")
        graph.add_action(SemanticAction(
            action_type=ActionType.ORACLE_READ,
            depth=1, from_addr="0xattacker", to_addr="0xroot",
        ))
        graph.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER,
            depth=1, from_addr="0xa", to_addr="0xz",
        ))
        graph.add_action(SemanticAction(
            action_type=ActionType.DEX_SWAP,
            depth=1, from_addr="0xa", to_addr="0xb",
        ))
        deps = analyzer._find_shared_dependencies(graph)
        assert deps == sorted(deps)


# ------------------------------------------------------------------
# _estimate_cascading_loss
# ------------------------------------------------------------------

class TestEstimateCascadingLoss:
    def test_sums_negative_deltas(self):
        analyzer = make_analyzer()
        # victim: before=2e18, after=0 → delta=-2e18 → loss = 2.0
        result = analyzer._estimate_cascading_loss(make_diff())
        assert result == pytest.approx(2.0)

    def test_ignores_positive_and_zero_deltas(self):
        analyzer = make_analyzer()
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xa", token="ETH", before=0, after=int(1e18)),  # gain
            BalanceChange(address="0xb", token="ETH", before=100, after=100),       # zero
        ])
        assert analyzer._estimate_cascading_loss(diff) == 0.0

    def test_empty_state_diff_returns_zero(self):
        analyzer = make_analyzer()
        assert analyzer._estimate_cascading_loss(StateDiff()) == 0.0

    def test_multiple_losses_summed(self):
        analyzer = make_analyzer()
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xa", token="ETH", before=int(3e18), after=int(1e18)),  # -2e18
            BalanceChange(address="0xb", token="ETH", before=int(1e18), after=0),           # -1e18
        ])
        assert analyzer._estimate_cascading_loss(diff) == pytest.approx(3.0)


# ------------------------------------------------------------------
# _compute_primary_loss
# ------------------------------------------------------------------

class TestComputePrimaryLoss:
    def test_uses_token_prices_when_present(self):
        analyzer = make_analyzer()
        config = {"token_prices": {"ETH": 2000.0}}
        # victim lost 2e18 ETH at $2000 → $4000
        result = analyzer._compute_primary_loss(make_diff(), config)
        assert result == pytest.approx(4000.0)

    def test_fallback_price_when_token_not_in_map(self):
        analyzer = make_analyzer()
        config = {"token_prices": {"USDC": 1.0}}  # ETH absent → fallback $1
        result = analyzer._compute_primary_loss(make_diff(), config)
        assert result == pytest.approx(2.0)

    def test_only_sums_losses_ignores_gains(self):
        analyzer = make_analyzer()
        # attacker gained 1e18, victim lost 2e18 → only 2.0 counted
        result = analyzer._compute_primary_loss(make_diff(), {})
        assert result == pytest.approx(2.0)

    def test_no_losses_returns_zero(self):
        analyzer = make_analyzer()
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xgainer", token="ETH", before=0, after=int(5e18)),
        ])
        assert analyzer._compute_primary_loss(diff, {}) == 0.0

    def test_empty_diff_returns_zero(self):
        analyzer = make_analyzer()
        assert analyzer._compute_primary_loss(StateDiff(), {}) == 0.0


# ------------------------------------------------------------------
# analyze() end-to-end (mocked LLM)
# ------------------------------------------------------------------

class TestAnalyzeEndToEnd:
    def test_primary_loss_usd_is_correct(self):
        analyzer = make_analyzer(make_llm_response(_VALID_LLM_JSON))
        config = {"token_prices": {"ETH": 1000.0}}
        report = analyzer.analyze(make_graph(), make_diff(), config)
        # victim lost 2e18 at $1000/ETH → $2000
        assert report.primary_loss_usd == pytest.approx(2000.0)

    def test_affected_protocols_populated(self):
        analyzer = make_analyzer(make_llm_response(_VALID_LLM_JSON))
        report = analyzer.analyze(make_graph(), make_diff(), {})
        assert len(report.affected_protocols) == 1
        ap = report.affected_protocols[0]
        assert ap.name == "Aave"
        assert ap.address == "0xabc"
        assert ap.relationship == "oracle dependency"
        assert ap.risk_level == "high"

    def test_cascading_risks_prepended_when_negative_deltas(self):
        analyzer = make_analyzer(make_llm_response(_VALID_LLM_JSON))
        report = analyzer.analyze(make_graph(), make_diff(), {})
        # cascading_loss = 2.0 → prefix inserted at index 0
        assert len(report.cascading_risks) == 2
        assert "cascading" in report.cascading_risks[0].lower()
        assert "2.00" in report.cascading_risks[0]
        assert report.cascading_risks[1] == "risk1"

    def test_no_cascading_prefix_when_no_losses(self):
        analyzer = make_analyzer(make_llm_response(_VALID_LLM_JSON))
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xgainer", token="ETH", before=0, after=int(1e18)),
        ])
        report = analyzer.analyze(make_graph(), diff, {})
        assert report.cascading_risks == ["risk1"]

    def test_recommendations_populated(self):
        analyzer = make_analyzer(make_llm_response(_VALID_LLM_JSON))
        report = analyzer.analyze(make_graph(), make_diff(), {})
        assert report.recommendations == ["rec1"]

    def test_malformed_llm_json_raises_value_error(self):
        analyzer = make_analyzer(make_llm_response("not valid json"))
        with pytest.raises(ValueError, match="non-JSON"):
            analyzer.analyze(make_graph(), make_diff(), {})
