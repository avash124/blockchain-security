"""Unit tests for predicate correctness."""

import pytest

from src.ir.nodes import ActionType, IRGraph, SemanticAction
from src.verifier.predicates import PredicateEngine, PredicateResult
from src.verifier.state_diff import StateDiff, BalanceChange


def _make_graph_with_actions(actions: list[SemanticAction]) -> IRGraph:
    graph = IRGraph(tx_hash="0xtest")
    for action in actions:
        graph.add_action(action)
    return graph


class TestPredicateEngine:
    def test_flash_loan_detected_pass(self):
        engine = PredicateEngine()
        graph = _make_graph_with_actions([
            SemanticAction(
                action_type=ActionType.FLASH_LOAN_BORROW,
                depth=1, from_addr="0xa", to_addr="0xb",
            ),
            SemanticAction(
                action_type=ActionType.FLASH_LOAN_REPAY,
                depth=1, from_addr="0xa", to_addr="0xb",
            ),
        ])
        state_diff = StateDiff()
        config = {"tags": ["flash_loan"]}

        result = engine.check_flash_loan_detected(graph, state_diff, config)
        assert result is not None
        assert result.result == PredicateResult.PASS

    def test_flash_loan_detected_fail_when_expected(self):
        engine = PredicateEngine()
        graph = _make_graph_with_actions([])
        state_diff = StateDiff()
        config = {"tags": ["flash_loan"]}

        result = engine.check_flash_loan_detected(graph, state_diff, config)
        assert result is not None
        assert result.result == PredicateResult.FAIL

    def test_flash_loan_not_checked_when_not_tagged(self):
        engine = PredicateEngine()
        graph = _make_graph_with_actions([])
        state_diff = StateDiff()
        config = {"tags": []}

        result = engine.check_flash_loan_detected(graph, state_diff, config)
        assert result is None

    def test_selfdestruct_detected(self):
        engine = PredicateEngine()
        graph = _make_graph_with_actions([
            SemanticAction(
                action_type=ActionType.SELF_DESTRUCT,
                depth=2, from_addr="0xa", to_addr="0xb",
            ),
        ])
        state_diff = StateDiff()
        config = {}

        result = engine.check_selfdestruct_called(graph, state_diff, config)
        assert result is not None
        assert result.result == PredicateResult.PASS

    def test_selfdestruct_not_detected(self):
        engine = PredicateEngine()
        graph = _make_graph_with_actions([])
        state_diff = StateDiff()
        config = {}

        result = engine.check_selfdestruct_called(graph, state_diff, config)
        assert result is None
