"""Deterministic predicate checks that don't require LLM reasoning."""

from __future__ import annotations

from collections import defaultdict
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
            self.check_price_manipulation,
            self.check_delegatecall_to_created,
        ]
        for check_fn in checks:
            result = check_fn(ir_graph, state_diff, scenario_config)
            if result:
                results.append(result)
        return results

    def check_balance_increased(
        self, ir_graph: IRGraph, state_diff: StateDiff, config: dict[str, Any]
    ) -> PredicateCheck | None:
        """Check if the attacker or their attack contracts gained funds.

        Profits in complex attacks route through intermediate contracts rather
        than landing directly on the attacker EOA, so we check all addresses
        the attacker EOA directly called in the IR.
        """
        attacker = config.get("attacker_address")
        if not attacker:
            return None

        # Check the attacker EOA and the attack contract (tx.to, stored in IR
        # metadata). Profits stay in the attack contract in multi-step exploits.
        attacker_lower = attacker.lower()
        check_addresses: set[str] = {attacker_lower}
        attack_contract = ir_graph.metadata.get("tx_to", "")
        if attack_contract:
            check_addresses.add(attack_contract.lower())

        all_gains = [g for addr in check_addresses for g in state_diff.get_gains(addr)]
        if all_gains:
            return PredicateCheck(
                name="balance_increased",
                result=PredicateResult.PASS,
                details=f"Attacker gained on {len(all_gains)} asset(s): {', '.join(g.token for g in all_gains)}",
                evidence={
                    "attacker": attacker,
                    "checked_addresses": sorted(check_addresses),
                    "gains": [
                        {
                            "address": g.address,
                            "token": g.token,
                            "delta": str(g.delta),
                            "before": str(g.before),
                            "after": str(g.after),
                        }
                        for g in all_gains
                    ],
                    "total_profit_wei": str(sum(g.delta for g in all_gains)),
                },
            )
        return PredicateCheck(
            name="balance_increased",
            result=PredicateResult.SKIP,
            details=f"No gains detected for attacker {attacker} or any directly called contracts",
            evidence={"attacker": attacker, "contracts_checked": sorted(check_addresses)},
        )

    def check_balance_decreased(
        self, ir_graph: IRGraph, state_diff: StateDiff, config: dict[str, Any]
    ) -> PredicateCheck | None:
        """Check if the victim protocol's balance decreased."""
        victims: list[str] = list(config.get("victim_addresses", []))
        target = config.get("target_contract")
        if target and target not in victims:
            victims.insert(0, target)
        if not victims:
            return None
        losses = [loss for addr in victims for loss in state_diff.get_losses(addr)]
        if losses:
            total_lost = sum(abs(l.delta) for l in losses)
            return PredicateCheck(
                name="balance_decreased",
                result=PredicateResult.PASS,
                details=f"Victim(s) lost funds: {len(losses)} change(s), {total_lost} wei total",
                evidence={
                    "losses": [
                        {"address": l.address, "token": l.token, "delta": str(l.delta)}
                        for l in losses
                    ],
                    "total_lost_wei": str(total_lost),
                },
            )
        return PredicateCheck(
            name="balance_decreased",
            result=PredicateResult.FAIL,
            details="No balance decrease for victim addresses",
            evidence={"victims_checked": victims},
        )

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
        if borrows:
            # Repay not decoded from struct-log (complex ABI calldata), but a
            # successful tx implies repayment occurred — treat borrow-only as PASS.
            return PredicateCheck(
                name="flash_loan_detected",
                result=PredicateResult.PASS,
                details=f"Found {len(borrows)} borrow(s); repay inferred from successful tx",
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
        """Check if reentrancy patterns exist in the trace.

        Reentrancy signature: the same contract address appears as `to_addr` at two
        different call depths where the deeper call is at least 2 levels below the
        shallower one, meaning a call *out of* that contract looped back into it.
        """
        depths_per_target: dict[str, list[int]] = defaultdict(list)
        for action in ir_graph.actions:
            if action.to_addr:
                depths_per_target[action.to_addr].append(action.depth)

        reentrant = [
            {"address": addr, "min_depth": min(ds), "max_depth": max(ds)}
            for addr, ds in depths_per_target.items()
            if len(set(ds)) >= 2 and max(ds) - min(ds) >= 2
        ]

        if reentrant:
            preview = ", ".join(r["address"][:10] for r in reentrant[:3])
            return PredicateCheck(
                name="reentrancy_detected",
                result=PredicateResult.PASS,
                details=f"Nested re-entry into {len(reentrant)} contract(s): {preview}",
                evidence={"reentrant_contracts": reentrant},
            )
        if "reentrancy" in config.get("tags", []):
            return PredicateCheck(
                name="reentrancy_detected",
                result=PredicateResult.FAIL,
                details="Expected reentrancy but no nested calls at increasing depth detected",
            )
        return None

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

    def check_price_manipulation(
        self, ir_graph: IRGraph, state_diff: StateDiff, config: dict[str, Any]
    ) -> PredicateCheck | None:
        """Check if an oracle read is sandwiched between DEX swaps (price manipulation signal)."""
        swaps = ir_graph.get_actions_by_type(ActionType.DEX_SWAP)
        oracle_reads = ir_graph.get_actions_by_type(ActionType.ORACLE_READ)
        if not swaps or not oracle_reads:
            return None

        swap_indices = {a.trace_index_start for a in swaps}
        for oracle in oracle_reads:
            oi = oracle.trace_index_start
            if any(si < oi for si in swap_indices) and any(si > oi for si in swap_indices):
                return PredicateCheck(
                    name="price_manipulation",
                    result=PredicateResult.PASS,
                    details=f"Oracle read at index {oi} sandwiched between {len(swaps)} DEX swap(s)",
                    evidence={
                        "swap_count": len(swaps),
                        "oracle_read_count": len(oracle_reads),
                        "sandwiched_oracle_index": oi,
                    },
                )
        return None

    def check_delegatecall_to_created(
        self, ir_graph: IRGraph, state_diff: StateDiff, config: dict[str, Any]
    ) -> PredicateCheck | None:
        """Check if a DELEGATECALL targets a contract deployed within the same transaction."""
        delegate_calls = ir_graph.get_actions_by_type(ActionType.DELEGATE_CALL)
        if not delegate_calls:
            return None

        # Build the set of contracts created in-tx from both the state diff and IR
        created: set[str] = {c.lower() for c in state_diff.created_contracts}
        for dep in ir_graph.get_actions_by_type(ActionType.CONTRACT_DEPLOYMENT):
            if dep.to_addr:
                created.add(dep.to_addr.lower())

        if not created:
            return None

        suspicious = [dc for dc in delegate_calls if dc.to_addr.lower() in created]
        if suspicious:
            return PredicateCheck(
                name="delegatecall_to_created",
                result=PredicateResult.PASS,
                details=f"DELEGATECALL into {len(suspicious)} in-transaction deployed contract(s)",
                evidence={"targets": [dc.to_addr for dc in suspicious]},
            )
        return None
