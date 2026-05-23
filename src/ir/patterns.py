"""Opcode-level pattern matchers that map raw frames to semantic actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.acquisition.trace_fetcher import TraceFrame
from src.ir.nodes import ActionType, SemanticAction

KNOWN_SELECTORS = {
    "0xa9059cbb": ("transfer", ActionType.TOKEN_TRANSFER),
    "0x23b872dd": ("transferFrom", ActionType.TOKEN_TRANSFER),
    "0xab9c4b5d": ("flashLoan", ActionType.FLASH_LOAN_BORROW),
    "0x022c0d9f": ("swap", ActionType.DEX_SWAP),
    "0x128acb08": ("swap", ActionType.DEX_SWAP),
    "0x5cffe9de": ("flashLoan", ActionType.FLASH_LOAN_BORROW),
}


@dataclass
class MatchResult:
    action: SemanticAction
    frames_consumed: int


class PatternMatcher:
    """Matches opcode sequences against known patterns to produce SemanticActions."""

    def __init__(self, custom_patterns: list[dict[str, Any]] | None = None):
        self._custom_patterns = custom_patterns or []

    def match(
        self,
        frame: TraceFrame,
        all_frames: list[TraceFrame],
        index: int,
    ) -> tuple[SemanticAction, int] | None:
        """Try to match the current frame against known patterns.

        Returns (SemanticAction, frames_consumed) or None.
        """
        if frame.op == "CALL":
            return self._match_call(frame, all_frames, index)
        elif frame.op == "DELEGATECALL":
            return self._match_delegatecall(frame)
        elif frame.op == "SELFDESTRUCT":
            return self._match_selfdestruct(frame)
        elif frame.op == "SSTORE":
            return self._match_sstore(frame)
        elif frame.op == "CREATE2":
            return self._match_create2(frame)
        return None

    def _match_call(
        self,
        frame: TraceFrame,
        all_frames: list[TraceFrame],
        index: int,
    ) -> tuple[SemanticAction, int] | None:
        """Match CALL opcode against known function selectors."""
        # TODO: extract calldata from memory, match selector against KNOWN_SELECTORS
        # TODO: decode params based on matched ABI
        return None

    def _match_delegatecall(self, frame: TraceFrame) -> tuple[SemanticAction, int] | None:
        target = frame.stack[-2] if len(frame.stack) >= 2 else "0x0"
        action = SemanticAction(
            action_type=ActionType.DELEGATE_CALL,
            depth=frame.depth,
            from_addr="",  # TODO: resolve from call context
            to_addr=target,
            params={"target": target},
        )
        return action, 1

    def _match_selfdestruct(self, frame: TraceFrame) -> tuple[SemanticAction, int] | None:
        beneficiary = frame.stack[-1] if frame.stack else "0x0"
        action = SemanticAction(
            action_type=ActionType.SELF_DESTRUCT,
            depth=frame.depth,
            from_addr="",
            to_addr=beneficiary,
            params={"beneficiary": beneficiary},
        )
        return action, 1

    def _match_sstore(self, frame: TraceFrame) -> tuple[SemanticAction, int] | None:
        slot = frame.stack[-1] if len(frame.stack) >= 1 else "0x0"
        value = frame.stack[-2] if len(frame.stack) >= 2 else "0x0"
        action = SemanticAction(
            action_type=ActionType.STORAGE_WRITE,
            depth=frame.depth,
            from_addr="",
            to_addr="",
            params={"slot": slot, "value": value},
        )
        return action, 1

    def _match_create2(self, frame: TraceFrame) -> tuple[SemanticAction, int] | None:
        action = SemanticAction(
            action_type=ActionType.CONTRACT_DEPLOYMENT,
            depth=frame.depth,
            from_addr="",
            to_addr="",
            params={"opcode": "CREATE2"},
        )
        return action, 1
