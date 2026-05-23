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

        i = 0
        while i < len(trace.frames):
            frame = trace.frames[i]
            match_result = self._matcher.match(frame, trace.frames, i)

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
        # TODO: link flash_loan_borrow → payload actions → flash_loan_repay
        # TODO: link token_transfers by matching amounts
        # TODO: link storage reads to prior storage writes on same slot
        for i in range(len(graph.actions) - 1):
            current = graph.actions[i]
            next_action = graph.actions[i + 1]
            graph.add_edge(current.id, next_action.id, "sequence")

    def _detect_flash_loan_scope(self, graph: IRGraph) -> list[tuple[int, int]]:
        """Find borrow/repay pairs and return index ranges of flash-loan-scoped actions."""
        # TODO: match borrow and repay actions by protocol + amount
        raise NotImplementedError
