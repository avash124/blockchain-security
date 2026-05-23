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
        # Merge KNOWN_SELECTORS with any caller-supplied overrides at construction time
        # so _match_call doesn't rebuild the lookup on every frame.
        self._selector_map: dict[str, tuple[str, ActionType]] = dict(KNOWN_SELECTORS)
        for cp in custom_patterns or []:
            sel = cp.get("selector", "").lower()
            if sel:
                self._selector_map[sel] = (
                    cp.get("name", "unknown"),
                    cp.get("action_type", ActionType.UNKNOWN),
                )

    def match(
        self,
        frame: TraceFrame,
        all_frames: list[TraceFrame],
        index: int,
        tx_from: str = "",
    ) -> tuple[SemanticAction, int] | None:
        """Try to match the current frame against known patterns.

        Returns (SemanticAction, frames_consumed) or None.
        """
        if frame.op == "CALL":
            return self._match_call(frame, all_frames, index, tx_from)
        elif frame.op == "DELEGATECALL":
            return self._match_delegatecall(frame, all_frames, index)
        elif frame.op == "SELFDESTRUCT":
            return self._match_selfdestruct(frame, all_frames, index, tx_from)
        elif frame.op == "SSTORE":
            return self._match_sstore(frame, all_frames, index, tx_from)
        elif frame.op == "CREATE2":
            return self._match_create2(frame, all_frames, index, tx_from)
        return None

    def _match_call(
        self,
        frame: TraceFrame,
        all_frames: list[TraceFrame],
        index: int,
        tx_from: str = "",
    ) -> tuple[SemanticAction, int] | None:
        """Match CALL opcode against known function selectors.

        EVM CALL pops 7 stack items (TOS first):
          gas | addr | value | argsOffset | argsLength | retOffset | retLength
        """
        stack = frame.stack
        if len(stack) < 7:
            return None

        target_raw = stack[-2]
        value_raw = stack[-3]
        args_offset = _parse_stack_int(stack[-4])
        args_length = _parse_stack_int(stack[-5])

        target_addr = _normalize_address(target_raw)
        value = _parse_stack_int(value_raw)
        caller = _resolve_caller(all_frames, index, frame.depth, tx_from)

        # Plain ETH transfer — no calldata at all
        if args_length == 0:
            action = SemanticAction(
                action_type=ActionType.ETH_TRANSFER,
                depth=frame.depth,
                from_addr=caller,
                to_addr=target_addr,
                params={"value": value},
            )
            return action, 1

        selector = self._extract_selector(frame.memory, args_offset, args_length)

        if selector and selector in self._selector_map:
            name, action_type = self._selector_map[selector]
            action = SemanticAction(
                action_type=action_type,
                depth=frame.depth,
                from_addr=caller,
                to_addr=target_addr,
                params={
                    "selector": selector,
                    "function": name,
                    "value": value,
                    "args_offset": args_offset,
                    "args_length": args_length,
                },
            )
            return action, 1

        # Unknown selector but carries ETH value → still an ETH transfer
        if value > 0:
            action = SemanticAction(
                action_type=ActionType.ETH_TRANSFER,
                depth=frame.depth,
                from_addr=caller,
                to_addr=target_addr,
                params={"value": value, "selector": selector},
            )
            return action, 1

        return None

    def _extract_selector(
        self,
        memory: list[str] | None,
        args_offset: int,
        args_length: int,
    ) -> str | None:
        """Extract the 4-byte function selector from EVM struct-log memory.

        Memory is a list of 32-byte hex chunks (64 hex chars each, no 0x prefix).
        """
        if not memory or args_length < 4:
            return None

        flat = "".join(m.removeprefix("0x").removeprefix("0X") for m in memory)
        byte_start = args_offset * 2  # 1 byte == 2 hex chars
        selector_end = byte_start + 8  # 4 bytes == 8 hex chars

        if len(flat) < selector_end:
            return None

        return "0x" + flat[byte_start:selector_end].lower()

    def _match_delegatecall(
        self,
        frame: TraceFrame,
        all_frames: list[TraceFrame],
        index: int,
    ) -> tuple[SemanticAction, int] | None:
        target = _normalize_address(frame.stack[-2]) if len(frame.stack) >= 2 else "0x0"
        # The current executing contract is the `to` of the most recent CALL/STATICCALL
        # at depth-1 that entered this execution context.
        caller_contract = _resolve_caller_contract(all_frames, index, frame.depth)
        action = SemanticAction(
            action_type=ActionType.DELEGATE_CALL,
            depth=frame.depth,
            from_addr=caller_contract,
            to_addr=target,
            params={"target": target},
        )
        return action, 1

    def _match_selfdestruct(
        self, frame: TraceFrame, all_frames: list[TraceFrame], index: int, tx_from: str,
    ) -> tuple[SemanticAction, int] | None:
        beneficiary = frame.stack[-1] if frame.stack else "0x0"
        caller = _resolve_caller(all_frames, index, frame.depth, tx_from)
        action = SemanticAction(
            action_type=ActionType.SELF_DESTRUCT,
            depth=frame.depth,
            from_addr=caller,
            to_addr=beneficiary,
            params={"beneficiary": beneficiary},
        )
        return action, 1

    def _match_sstore(
        self, frame: TraceFrame, all_frames: list[TraceFrame], index: int, tx_from: str,
    ) -> tuple[SemanticAction, int] | None:
        slot = frame.stack[-1] if len(frame.stack) >= 1 else "0x0"
        value = frame.stack[-2] if len(frame.stack) >= 2 else "0x0"
        caller = _resolve_caller(all_frames, index, frame.depth, tx_from)
        action = SemanticAction(
            action_type=ActionType.STORAGE_WRITE,
            depth=frame.depth,
            from_addr=caller,
            to_addr=caller,
            params={"slot": slot, "value": value},
        )
        return action, 1

    def _match_create2(
        self, frame: TraceFrame, all_frames: list[TraceFrame], index: int, tx_from: str,
    ) -> tuple[SemanticAction, int] | None:
        caller = _resolve_caller(all_frames, index, frame.depth, tx_from)
        action = SemanticAction(
            action_type=ActionType.CONTRACT_DEPLOYMENT,
            depth=frame.depth,
            from_addr=caller,
            to_addr="",
            params={"opcode": "CREATE2"},
        )
        return action, 1


def _resolve_caller(
    all_frames: list[TraceFrame],
    index: int,
    current_depth: int,
    tx_from: str = "",
) -> str:
    """Resolve which address is executing at current_depth.

    At depth 1, the executor is the transaction's `to` address (the contract
    the EOA called). At deeper depths, scan backwards for the CALL/STATICCALL
    at depth-1 whose target is the contract now executing.

    For the *caller* of a CALL at depth N, we want the contract executing at
    depth N — i.e. the target of the CALL that entered depth N from depth N-1.
    At depth 1, that's the tx.to (the first contract called by the EOA).
    """
    if current_depth <= 1:
        return tx_from

    entry_ops = {"CALL", "STATICCALL", "CALLCODE", "CREATE", "CREATE2"}
    for i in range(index - 1, -1, -1):
        f = all_frames[i]
        if f.depth == current_depth - 1 and f.op in entry_ops:
            if len(f.stack) >= 2:
                return _normalize_address(f.stack[-2])
            break
    return ""


def _resolve_caller_contract(
    all_frames: list[TraceFrame],
    index: int,
    current_depth: int,
) -> str:
    """Legacy wrapper — used by DELEGATECALL matching."""
    return _resolve_caller(all_frames, index, current_depth)


def _parse_stack_int(value: str) -> int:
    """Convert a raw EVM stack word (hex string, with or without 0x) to int."""
    if not value:
        return 0
    v = value.strip()
    if not v.startswith("0x"):
        v = "0x" + v
    try:
        return int(v, 16)
    except ValueError:
        return 0


def _normalize_address(raw: str) -> str:
    """Extract the lower 20 bytes of a 32-byte stack word as a checksumless address."""
    v = raw.strip().lstrip("0x").lstrip("0X")
    addr = v[-40:] if len(v) >= 40 else v.zfill(40)
    return "0x" + addr.lower()
