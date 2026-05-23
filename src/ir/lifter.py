"""Lifts raw EVM traces into the semantic IR graph."""

from __future__ import annotations

from typing import Any

from src.acquisition.trace_fetcher import TransactionTrace, TraceFrame
from src.ir.nodes import ActionType, IRGraph, SemanticAction
from src.ir.patterns import PatternMatcher


class IRLifter:
    """Converts raw opcode traces into high-level semantic actions."""

    def __init__(self, pattern_matcher: PatternMatcher | None = None):
        self._matcher = pattern_matcher or PatternMatcher()

    def lift(self, trace: TransactionTrace) -> IRGraph:
        """Transform a full transaction trace into an IR graph."""
        graph = IRGraph(tx_hash=trace.tx_hash)
        tx_from = trace.from_addr

        i = 0
        while i < len(trace.frames):
            frame = trace.frames[i]
            match_result = self._matcher.match(frame, trace.frames, i, tx_from=tx_from)

            if match_result:
                action, consumed = match_result
                action.trace_index_start = i
                action.trace_index_end = i + consumed
                graph.add_action(action)
                i += consumed
            else:
                i += 1

        self._build_edges(graph)
        return graph

    def _build_edges(self, graph: IRGraph) -> None:
        """Infer data-flow and control-flow edges between actions."""
        actions = graph.actions

        # Sequential control-flow spine
        for i in range(len(actions) - 1):
            graph.add_edge(actions[i].id, actions[i + 1].id, "sequence")

        # Flash-loan scope: direct borrow → repay data-flow arc
        for b_idx, r_idx in self._detect_flash_loan_scope(graph):
            graph.add_edge(actions[b_idx].id, actions[r_idx].id, "flash_loan_scope")

        # Token/ETH transfer amount matching: chain transfers that share the same value
        # to surface fund routing (e.g. receive 1 ETH then later forward 1 ETH).
        transfer_types = {ActionType.TOKEN_TRANSFER, ActionType.ETH_TRANSFER}
        amount_to_last: dict[int, str] = {}
        for action in actions:
            if action.action_type in transfer_types:
                amount: int = action.params.get("value", 0)
                if amount:
                    if amount in amount_to_last:
                        graph.add_edge(amount_to_last[amount], action.id, "amount_match")
                    amount_to_last[amount] = action.id

        # Storage slot dependency: link each SSTORE to the next SLOAD on the same slot
        slot_last_write: dict[str, str] = {}
        for action in actions:
            if action.action_type == ActionType.STORAGE_WRITE:
                slot: str = action.params.get("slot", "")
                if slot:
                    slot_last_write[slot] = action.id
            elif action.action_type == ActionType.STORAGE_READ:
                slot = action.params.get("slot", "")
                if slot and slot in slot_last_write:
                    graph.add_edge(slot_last_write[slot], action.id, "storage_dep")

    def _detect_flash_loan_scope(self, graph: IRGraph) -> list[tuple[int, int]]:
        """Find borrow/repay pairs and return index ranges of flash-loan-scoped actions.

        Matching strategy (in priority order):
        1. Explicit FLASH_LOAN_REPAY whose to_addr equals the lending protocol.
        2. ETH_TRANSFER to the lending protocol (covers ETH-denominated flash loans
           where the repay is a bare value transfer rather than a contract call).

        Token-transfer repays (ERC-20 transferred back to the pool) require calldata
        decoding to extract the recipient, which is not yet implemented in PatternMatcher.

        Returns a list of (borrow_action_index, repay_action_index) pairs in the order
        the borrows were encountered. Each repay index is used at most once.
        """
        borrows = [
            (i, a)
            for i, a in enumerate(graph.actions)
            if a.action_type == ActionType.FLASH_LOAN_BORROW
        ]
        repays = [
            (i, a)
            for i, a in enumerate(graph.actions)
            if a.action_type == ActionType.FLASH_LOAN_REPAY
        ]
        eth_transfers = [
            (i, a)
            for i, a in enumerate(graph.actions)
            if a.action_type == ActionType.ETH_TRANSFER
        ]

        scopes: list[tuple[int, int]] = []
        used: set[int] = set()

        for b_idx, borrow in borrows:
            protocol = borrow.to_addr

            # Priority 1: explicit repay action targeting the same protocol
            for r_idx, repay in repays:
                if r_idx in used or r_idx <= b_idx:
                    continue
                if repay.to_addr == protocol:
                    used.add(r_idx)
                    scopes.append((b_idx, r_idx))
                    break
            else:
                # Priority 2: ETH transfer to the lending protocol (ETH flash loans)
                for r_idx, transfer in eth_transfers:
                    if r_idx in used or r_idx <= b_idx:
                        continue
                    if transfer.to_addr == protocol:
                        used.add(r_idx)
                        scopes.append((b_idx, r_idx))
                        break

        return scopes
