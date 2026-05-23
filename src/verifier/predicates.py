"""Deterministic predicate checks that don't require LLM reasoning."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from src.ir.nodes import ActionType, IRGraph
from src.verifier.state_diff import StateDiff


class PredicateResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass
class PredicateCheck:
    name: str
    result: PredicateResult
    details: str = ""
    evidence: dict[str, Any] | None = None


class PredicateEngine:
    """Evaluates deterministic predicates against IR graphs and state diffs."""

    def __init__(self, predicate_config: dict[str, Any] | None = None):
        self._config = predicate_config or {}

    def evaluate_all(
        self,
        ir_graph: IRGraph,
        state_diff: StateDiff,
        scenario_config: dict[str, Any],
    ) -> list[PredicateCheck]:
        """Run all applicable predicates and return results."""
        results = []
        checks = [
            self.check_balance_increased,
            self.check_balance_decreased,
            self.check_flash_loan_detected,
            self.check_reentrancy_detected,
            self.check_selfdestruct_called,
        ]
        for check_fn in checks:
            result = check_fn(ir_graph, state_diff, scenario_config)
            if result:
                results.append(result)
        return results

    def check_balance_increased(
        self, ir_graph: IRGraph, state_diff: StateDiff, config: dict[str, Any]
    ) -> PredicateCheck | None:
        """Check if the attacker's balance increased."""
        attacker = config.get("attacker_address")
        if not attacker:
            return None
        # TODO: compare pre/post balances from state_diff
        raise NotImplementedError

    def check_balance_decreased(
        self, ir_graph: IRGraph, state_diff: StateDiff, config: dict[str, Any]
    ) -> PredicateCheck | None:
        """Check if the victim protocol's balance decreased."""
        # TODO: compare pre/post balances for target contracts
        raise NotImplementedError

    def check_flash_loan_detected(
        self, ir_graph: IRGraph, state_diff: StateDiff, config: dict[str, Any]
    ) -> PredicateCheck | None:
        """Check if a flash loan borrow+repay pair exists in the IR."""
        borrows = ir_graph.get_actions_by_type(ActionType.FLASH_LOAN_BORROW)
        repays = ir_graph.get_actions_by_type(ActionType.FLASH_LOAN_REPAY)
        if borrows and repays:
            return PredicateCheck(
                name="flash_loan_detected",
                result=PredicateResult.PASS,
                details=f"Found {len(borrows)} borrow(s) and {len(repays)} repay(s)",
            )
        if "flash_loan" in config.get("tags", []):
            return PredicateCheck(
                name="flash_loan_detected",
                result=PredicateResult.FAIL,
                details="Expected flash loan but none detected in IR",
            )
        return None

    def check_reentrancy_detected(
        self, ir_graph: IRGraph, state_diff: StateDiff, config: dict[str, Any]
    ) -> PredicateCheck | None:
        """Check if reentrancy patterns exist in the trace."""
        # TODO: look for nested calls to the same contract at increasing depth
        raise NotImplementedError

    def check_selfdestruct_called(
        self, ir_graph: IRGraph, state_diff: StateDiff, config: dict[str, Any]
    ) -> PredicateCheck | None:
        """Check if SELFDESTRUCT was invoked."""
        selfdestructs = ir_graph.get_actions_by_type(ActionType.SELF_DESTRUCT)
        if selfdestructs:
            return PredicateCheck(
                name="selfdestruct_called",
                result=PredicateResult.PASS,
                details=f"SELFDESTRUCT found at depth {selfdestructs[0].depth}",
            )
        return None
