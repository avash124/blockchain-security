"""Unit tests for predicate correctness."""

import pytest

from src.ir.nodes import ActionType, IRGraph, SemanticAction
from src.verifier.predicates import PredicateEngine, PredicateResult
from src.verifier.state_diff import StateDiff, BalanceChange, StorageChange


def _make_graph(*actions: SemanticAction) -> IRGraph:
    graph = IRGraph(tx_hash="0xtest")
    for action in actions:
        graph.add_action(action)
    return graph


def _action(atype: ActionType, depth: int = 1, from_addr: str = "0xa", to_addr: str = "0xb", **params) -> SemanticAction:
    return SemanticAction(action_type=atype, depth=depth, from_addr=from_addr, to_addr=to_addr, params=params)


# ------------------------------------------------------------------
# check_flash_loan_detected
# ------------------------------------------------------------------

class TestFlashLoanDetected:
    def test_pass_with_borrow_and_repay(self):
        engine = PredicateEngine()
        graph = _make_graph(
            _action(ActionType.FLASH_LOAN_BORROW),
            _action(ActionType.FLASH_LOAN_REPAY),
        )
        result = engine.check_flash_loan_detected(graph, StateDiff(), {"tags": ["flash_loan"]})
        assert result is not None
        assert result.result == PredicateResult.PASS
        assert "1 borrow" in result.details

    def test_multiple_borrows_and_repays(self):
        engine = PredicateEngine()
        graph = _make_graph(
            _action(ActionType.FLASH_LOAN_BORROW),
            _action(ActionType.FLASH_LOAN_BORROW),
            _action(ActionType.FLASH_LOAN_REPAY),
            _action(ActionType.FLASH_LOAN_REPAY),
        )
        result = engine.check_flash_loan_detected(graph, StateDiff(), {})
        assert result.result == PredicateResult.PASS
        assert "2 borrow" in result.details

    def test_fail_when_tagged_but_absent(self):
        engine = PredicateEngine()
        result = engine.check_flash_loan_detected(_make_graph(), StateDiff(), {"tags": ["flash_loan"]})
        assert result is not None
        assert result.result == PredicateResult.FAIL

    def test_none_when_not_tagged_and_absent(self):
        engine = PredicateEngine()
        result = engine.check_flash_loan_detected(_make_graph(), StateDiff(), {"tags": []})
        assert result is None

    def test_borrow_only_no_repay_fails_when_tagged(self):
        engine = PredicateEngine()
        graph = _make_graph(_action(ActionType.FLASH_LOAN_BORROW))
        result = engine.check_flash_loan_detected(graph, StateDiff(), {"tags": ["flash_loan"]})
        assert result.result == PredicateResult.FAIL


# ------------------------------------------------------------------
# check_selfdestruct_called
# ------------------------------------------------------------------

class TestSelfdestructCalled:
    def test_detected(self):
        engine = PredicateEngine()
        graph = _make_graph(_action(ActionType.SELF_DESTRUCT, depth=2))
        result = engine.check_selfdestruct_called(graph, StateDiff(), {})
        assert result is not None
        assert result.result == PredicateResult.PASS
        assert "depth 2" in result.details

    def test_not_detected(self):
        engine = PredicateEngine()
        result = engine.check_selfdestruct_called(_make_graph(), StateDiff(), {})
        assert result is None


# ------------------------------------------------------------------
# check_balance_increased
# ------------------------------------------------------------------

class TestBalanceIncreased:
    def test_pass_attacker_gained(self):
        engine = PredicateEngine()
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xattacker", token="ETH", before=0, after=1000),
            BalanceChange(address="0xattacker", token="0xdai", before=0, after=500),
        ])
        config = {"attacker_address": "0xattacker"}
        result = engine.check_balance_increased(_make_graph(), diff, config)
        assert result.result == PredicateResult.PASS
        assert "2 asset" in result.details
        assert result.evidence["total_profit_wei"] == "1500"

    def test_fail_no_gain(self):
        engine = PredicateEngine()
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xattacker", token="ETH", before=1000, after=500),
        ])
        config = {"attacker_address": "0xattacker"}
        result = engine.check_balance_increased(_make_graph(), diff, config)
        assert result.result == PredicateResult.FAIL

    def test_none_when_no_attacker(self):
        engine = PredicateEngine()
        result = engine.check_balance_increased(_make_graph(), StateDiff(), {})
        assert result is None

    def test_only_counts_target_address(self):
        engine = PredicateEngine()
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xother", token="ETH", before=0, after=9999),
        ])
        config = {"attacker_address": "0xattacker"}
        result = engine.check_balance_increased(_make_graph(), diff, config)
        assert result.result == PredicateResult.FAIL


# ------------------------------------------------------------------
# check_balance_decreased
# ------------------------------------------------------------------

class TestBalanceDecreased:
    def test_pass_victim_lost_funds(self):
        engine = PredicateEngine()
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xvictim", token="ETH", before=5000, after=1000),
        ])
        config = {"target_contract": "0xvictim"}
        result = engine.check_balance_decreased(_make_graph(), diff, config)
        assert result.result == PredicateResult.PASS
        assert "4000 wei" in result.details

    def test_pass_multiple_victims(self):
        engine = PredicateEngine()
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xv1", token="ETH", before=3000, after=1000),
            BalanceChange(address="0xv2", token="0xtoken", before=2000, after=0),
        ])
        config = {"victim_addresses": ["0xv1", "0xv2"]}
        result = engine.check_balance_decreased(_make_graph(), diff, config)
        assert result.result == PredicateResult.PASS
        assert result.evidence["total_lost_wei"] == "4000"

    def test_fail_no_losses(self):
        engine = PredicateEngine()
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xvictim", token="ETH", before=100, after=200),
        ])
        config = {"target_contract": "0xvictim"}
        result = engine.check_balance_decreased(_make_graph(), diff, config)
        assert result.result == PredicateResult.FAIL

    def test_none_when_no_victim(self):
        engine = PredicateEngine()
        result = engine.check_balance_decreased(_make_graph(), StateDiff(), {})
        assert result is None

    def test_target_contract_added_to_victims(self):
        engine = PredicateEngine()
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xtarget", token="ETH", before=5000, after=0),
        ])
        config = {"target_contract": "0xtarget", "victim_addresses": ["0xother"]}
        result = engine.check_balance_decreased(_make_graph(), diff, config)
        assert result.result == PredicateResult.PASS


# ------------------------------------------------------------------
# check_reentrancy_detected
# ------------------------------------------------------------------

class TestReentrancyDetected:
    def test_pass_nested_reentry(self):
        engine = PredicateEngine()
        graph = _make_graph(
            _action(ActionType.ETH_TRANSFER, depth=1, to_addr="0xvuln"),
            _action(ActionType.STORAGE_WRITE, depth=2, to_addr="0xother"),
            _action(ActionType.ETH_TRANSFER, depth=3, to_addr="0xvuln"),
        )
        result = engine.check_reentrancy_detected(graph, StateDiff(), {})
        assert result is not None
        assert result.result == PredicateResult.PASS
        assert "0xvuln" in result.details

    def test_fail_when_tagged_but_no_reentry(self):
        engine = PredicateEngine()
        graph = _make_graph(
            _action(ActionType.ETH_TRANSFER, depth=1, to_addr="0xa"),
            _action(ActionType.ETH_TRANSFER, depth=1, to_addr="0xb"),
        )
        result = engine.check_reentrancy_detected(graph, StateDiff(), {"tags": ["reentrancy"]})
        assert result.result == PredicateResult.FAIL

    def test_none_when_not_tagged_and_no_reentry(self):
        engine = PredicateEngine()
        result = engine.check_reentrancy_detected(_make_graph(), StateDiff(), {"tags": []})
        assert result is None

    def test_depth_difference_must_be_at_least_two(self):
        engine = PredicateEngine()
        graph = _make_graph(
            _action(ActionType.ETH_TRANSFER, depth=1, to_addr="0xvuln"),
            _action(ActionType.ETH_TRANSFER, depth=2, to_addr="0xvuln"),
        )
        result = engine.check_reentrancy_detected(graph, StateDiff(), {"tags": ["reentrancy"]})
        assert result.result == PredicateResult.FAIL

    def test_multiple_reentrant_contracts(self):
        engine = PredicateEngine()
        graph = _make_graph(
            _action(ActionType.ETH_TRANSFER, depth=1, to_addr="0xvuln1"),
            _action(ActionType.ETH_TRANSFER, depth=3, to_addr="0xvuln1"),
            _action(ActionType.ETH_TRANSFER, depth=1, to_addr="0xvuln2"),
            _action(ActionType.ETH_TRANSFER, depth=4, to_addr="0xvuln2"),
        )
        result = engine.check_reentrancy_detected(graph, StateDiff(), {})
        assert result.result == PredicateResult.PASS
        assert len(result.evidence["reentrant_contracts"]) == 2


# ------------------------------------------------------------------
# check_price_manipulation
# ------------------------------------------------------------------

class TestPriceManipulation:
    def test_pass_oracle_sandwiched(self):
        engine = PredicateEngine()
        graph = _make_graph(
            SemanticAction(action_type=ActionType.DEX_SWAP, depth=1, from_addr="0xa", to_addr="0xpool",
                           trace_index_start=0, trace_index_end=1),
            SemanticAction(action_type=ActionType.ORACLE_READ, depth=1, from_addr="0xa", to_addr="0xoracle",
                           trace_index_start=5, trace_index_end=6),
            SemanticAction(action_type=ActionType.DEX_SWAP, depth=1, from_addr="0xa", to_addr="0xpool",
                           trace_index_start=10, trace_index_end=11),
        )
        result = engine.check_price_manipulation(graph, StateDiff(), {})
        assert result is not None
        assert result.result == PredicateResult.PASS
        assert "sandwiched" in result.details

    def test_none_no_swaps(self):
        engine = PredicateEngine()
        graph = _make_graph(
            SemanticAction(action_type=ActionType.ORACLE_READ, depth=1, from_addr="0xa", to_addr="0xoracle",
                           trace_index_start=5, trace_index_end=6),
        )
        result = engine.check_price_manipulation(graph, StateDiff(), {})
        assert result is None

    def test_none_no_oracle(self):
        engine = PredicateEngine()
        graph = _make_graph(
            SemanticAction(action_type=ActionType.DEX_SWAP, depth=1, from_addr="0xa", to_addr="0xpool",
                           trace_index_start=0, trace_index_end=1),
        )
        result = engine.check_price_manipulation(graph, StateDiff(), {})
        assert result is None

    def test_none_oracle_not_between_swaps(self):
        engine = PredicateEngine()
        graph = _make_graph(
            SemanticAction(action_type=ActionType.DEX_SWAP, depth=1, from_addr="0xa", to_addr="0xpool",
                           trace_index_start=0, trace_index_end=1),
            SemanticAction(action_type=ActionType.DEX_SWAP, depth=1, from_addr="0xa", to_addr="0xpool",
                           trace_index_start=5, trace_index_end=6),
            SemanticAction(action_type=ActionType.ORACLE_READ, depth=1, from_addr="0xa", to_addr="0xoracle",
                           trace_index_start=10, trace_index_end=11),
        )
        result = engine.check_price_manipulation(graph, StateDiff(), {})
        assert result is None


# ------------------------------------------------------------------
# check_delegatecall_to_created
# ------------------------------------------------------------------

class TestDelegatecallToCreated:
    def test_pass_delegatecall_to_in_tx_deploy(self):
        engine = PredicateEngine()
        diff = StateDiff(created_contracts=["0xnew"])
        graph = _make_graph(
            _action(ActionType.CONTRACT_DEPLOYMENT, to_addr="0xnew"),
            _action(ActionType.DELEGATE_CALL, to_addr="0xnew"),
        )
        result = engine.check_delegatecall_to_created(graph, diff, {})
        assert result is not None
        assert result.result == PredicateResult.PASS

    def test_none_no_delegatecall(self):
        engine = PredicateEngine()
        diff = StateDiff(created_contracts=["0xnew"])
        result = engine.check_delegatecall_to_created(_make_graph(), diff, {})
        assert result is None

    def test_none_delegatecall_to_existing_contract(self):
        engine = PredicateEngine()
        diff = StateDiff()
        graph = _make_graph(_action(ActionType.DELEGATE_CALL, to_addr="0xexisting"))
        result = engine.check_delegatecall_to_created(graph, diff, {})
        assert result is None

    def test_case_insensitive_address_match(self):
        engine = PredicateEngine()
        diff = StateDiff(created_contracts=["0xAbCd0000000000000000000000000000DeAdBeEf"])
        graph = _make_graph(
            _action(ActionType.DELEGATE_CALL, to_addr="0xabcd0000000000000000000000000000deadbeef"),
        )
        result = engine.check_delegatecall_to_created(graph, diff, {})
        assert result is not None
        assert result.result == PredicateResult.PASS

    def test_created_from_ir_not_just_state_diff(self):
        engine = PredicateEngine()
        diff = StateDiff()  # no created_contracts in state diff
        graph = _make_graph(
            _action(ActionType.CONTRACT_DEPLOYMENT, to_addr="0xdeployed"),
            _action(ActionType.DELEGATE_CALL, to_addr="0xdeployed"),
        )
        result = engine.check_delegatecall_to_created(graph, diff, {})
        assert result is not None
        assert result.result == PredicateResult.PASS


# ------------------------------------------------------------------
# evaluate_all
# ------------------------------------------------------------------

class TestEvaluateAll:
    def test_runs_all_checks(self):
        engine = PredicateEngine()
        graph = _make_graph(
            _action(ActionType.FLASH_LOAN_BORROW),
            _action(ActionType.FLASH_LOAN_REPAY),
            _action(ActionType.SELF_DESTRUCT, depth=2),
        )
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xattacker", token="ETH", before=0, after=1000),
            BalanceChange(address="0xvictim", token="ETH", before=5000, after=0),
        ])
        config = {
            "attacker_address": "0xattacker",
            "target_contract": "0xvictim",
            "tags": ["flash_loan"],
        }
        results = engine.evaluate_all(graph, diff, config)
        names = {r.name for r in results}
        assert "balance_increased" in names
        assert "balance_decreased" in names
        assert "flash_loan_detected" in names
        assert "selfdestruct_called" in names

    def test_skips_inapplicable_checks(self):
        engine = PredicateEngine()
        results = engine.evaluate_all(_make_graph(), StateDiff(), {})
        assert len(results) == 0

    def test_all_results_are_predicate_checks(self):
        engine = PredicateEngine()
        diff = StateDiff(balance_changes=[
            BalanceChange(address="0xattacker", token="ETH", before=0, after=1000),
        ])
        config = {"attacker_address": "0xattacker"}
        results = engine.evaluate_all(_make_graph(), diff, config)
        for r in results:
            assert hasattr(r, "name")
            assert hasattr(r, "result")
            assert r.result in (PredicateResult.PASS, PredicateResult.FAIL, PredicateResult.SKIP)
