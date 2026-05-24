"""Fetches and parses transaction traces via debug_traceTransaction JSON-RPC."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.acquisition.rpc_client import RpcClient, RpcError


class TraceFetchError(Exception):
    """Raised when trace acquisition fails (bad tx hash, RPC error, timeout, etc.)."""


@dataclass
class TraceFrame:
    pc: int
    op: str
    gas: int
    gas_cost: int
    depth: int
    stack: list[str]
    memory: list[str] | None = None
    storage: dict[str, str] | None = None
    return_data: str | None = None


@dataclass
class TransactionTrace:
    tx_hash: str
    from_addr: str
    to_addr: str
    value: int
    gas_used: int
    status: bool
    frames: list[TraceFrame]
    call_tree: dict[str, Any] | None = None

    @property
    def opcodes(self) -> list[str]:
        return [f.op for f in self.frames]


class TraceFetcher:
    """Fetches full EVM traces via debug_traceTransaction JSON-RPC."""

    def __init__(self, rpc_url: str):
        self._rpc = RpcClient(rpc_url, timeout=120.0)

    def fetch_trace(self, tx_hash: str) -> TransactionTrace:
        """Fetch a structured trace for a transaction.

        Uses the lightweight `callTracer` (typically <2MB, ~0.3s) rather than
        a full struct-log. We synthesize one TraceFrame per call so the
        existing opcode-based PatternMatcher works unchanged.

        Tradeoff: SSTORE, SELFDESTRUCT, and other in-frame opcode events are
        invisible. Acceptable for CALL-driven exploits (flash loans, oracle
        manipulation, reentrancy via call graph); not for pure-storage logic
        bugs. Switch to fetch_full_trace() if you need opcode resolution.
        """
        tx_hash = self._normalize_tx_hash(tx_hash)

        receipt = self._fetch_receipt(tx_hash)
        call_tree = self._fetch_call_tree_raw(tx_hash)
        frames = self._flatten_call_tree(call_tree, depth=1)

        from_addr = receipt.get("from", "")
        to_addr = receipt.get("to") or ""
        gas_used_raw = receipt.get("gasUsed", "0x0")
        status_raw = receipt.get("status", "0x1")

        return TransactionTrace(
            tx_hash=tx_hash,
            from_addr=from_addr.lower() if from_addr else "",
            to_addr=to_addr.lower() if to_addr else "",
            value=0,  # receipts don't carry value; fetch via eth_getTransactionByHash if needed
            gas_used=_parse_hex_int(gas_used_raw),
            status=_parse_hex_int(status_raw) == 1,
            frames=frames,
            call_tree=call_tree,
        )

    def fetch_call_tree(self, tx_hash: str) -> dict[str, Any]:
        """Fetch the nested call tree (debug_traceTransaction with callTracer)."""
        tx_hash = self._normalize_tx_hash(tx_hash)

        result = self._rpc_call(
            "debug_traceTransaction",
            [
                tx_hash,
                {
                    "tracer": "callTracer",
                    "tracerConfig": {"withLog": True},
                },
            ],
        )

        if not isinstance(result, dict):
            raise TraceFetchError(
                f"Unexpected call-tree response type for {tx_hash}: {type(result)}"
            )

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize_tx_hash(self, tx_hash: str) -> str:
        """Ensure the tx hash is lower-case and 0x-prefixed."""
        tx_hash = tx_hash.strip()
        if not tx_hash.startswith("0x"):
            tx_hash = "0x" + tx_hash
        # Basic sanity: 0x + 64 hex chars
        if len(tx_hash) != 66:
            raise TraceFetchError(
                f"Invalid transaction hash length ({len(tx_hash)}): {tx_hash}"
            )
        return tx_hash.lower()

    def _rpc_call(self, method: str, params: list[Any]) -> Any:
        """Delegate to shared RPC client, wrapping errors."""
        try:
            return self._rpc.call(method, params)
        except RpcError as exc:
            raise TraceFetchError(str(exc)) from exc

    def _fetch_receipt(self, tx_hash: str) -> dict[str, Any]:
        """Fetch the transaction receipt for metadata."""
        result = self._rpc_call("eth_getTransactionReceipt", [tx_hash])
        if result is None:
            raise TraceFetchError(
                f"Transaction receipt not found for {tx_hash}. "
                "The transaction may not exist or the node may not have it."
            )
        return result

    def _fetch_call_tree_raw(self, tx_hash: str) -> dict[str, Any]:
        """Fetch the nested call tree via debug_traceTransaction + callTracer."""
        result = self._rpc_call(
            "debug_traceTransaction",
            [
                tx_hash,
                {
                    "tracer": "callTracer",
                    "tracerConfig": {"withLog": True},
                },
            ],
        )
        if not isinstance(result, dict):
            raise TraceFetchError(
                f"Unexpected callTracer response type for {tx_hash}: {type(result)}"
            )
        return result

    def _flatten_call_tree(
        self, node: dict[str, Any], depth: int,
    ) -> list[TraceFrame]:
        """DFS through the call tree, emitting one synthesized TraceFrame per call.

        Stack and memory are reconstructed to match what PatternMatcher's
        opcode matchers expect, so the lifter doesn't need to know we're
        coming from callTracer instead of struct logs.
        """
        frames: list[TraceFrame] = []
        op_raw = (node.get("type") or "CALL").upper()
        # callTracer reports CREATE2 sometimes as just "CREATE" — we lose the
        # distinction but PatternMatcher only handles CREATE2 today anyway.
        if op_raw in ("CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"):
            frames.append(self._synth_call_frame(node, depth, op_raw))
        elif op_raw in ("CREATE", "CREATE2"):
            frames.append(self._synth_create_frame(node, depth))

        for child in node.get("calls", []) or []:
            frames.extend(self._flatten_call_tree(child, depth + 1))
        return frames

    def _synth_call_frame(
        self, node: dict[str, Any], depth: int, op: str,
    ) -> TraceFrame:
        """Build a CALL/STATICCALL/DELEGATECALL/CALLCODE frame from a call-tree node.

        PatternMatcher._match_call reads (TOS-last):
          stack[-2]=addr, stack[-3]=value, stack[-4]=argsOffset, stack[-5]=argsLength
        and _extract_selector reads memory[byte_start:byte_start+8] starting
        at byte_start=argsOffset*2. We place calldata at offset 0.
        """
        to_addr = (node.get("to") or "").lower()
        value = node.get("value") or "0x0"
        input_data = node.get("input") or "0x"

        calldata_hex = input_data.removeprefix("0x").removeprefix("0X")
        args_length = len(calldata_hex) // 2  # bytes

        # 32-byte address word (right-aligned, lower 20 bytes)
        addr_word = to_addr.removeprefix("0x").zfill(64)

        # Stack TOS-last: gas | addr | value | argsOff | argsLen | retOff | retLen
        stack = [
            "0x0",            # retLength
            "0x0",            # retOffset
            hex(args_length), # argsLength
            "0x0",            # argsOffset (calldata at memory[0])
            value,            # value
            "0x" + addr_word, # target address
            "0xffff",         # gas
        ]

        memory: list[str] | None = None
        if calldata_hex:
            # Pad to a multiple of 64 hex chars (32 bytes)
            padded = calldata_hex.ljust(((len(calldata_hex) + 63) // 64) * 64, "0")
            memory = [padded[i:i + 64] for i in range(0, len(padded), 64)]

        return TraceFrame(
            pc=0,
            op=op,
            gas=_parse_int(node.get("gas", "0x0")),
            gas_cost=_parse_int(node.get("gasUsed", "0x0")),
            depth=depth,
            stack=stack,
            memory=memory,
            storage=None,
            return_data=node.get("output"),
        )

    def _synth_create_frame(
        self, node: dict[str, Any], depth: int,
    ) -> TraceFrame:
        """Build a CREATE2 frame from a contract-deployment call-tree node.

        We emit op=CREATE2 regardless of whether the underlying op was CREATE
        or CREATE2 since PatternMatcher only matches CREATE2 today.
        """
        return TraceFrame(
            pc=0,
            op="CREATE2",
            gas=_parse_int(node.get("gas", "0x0")),
            gas_cost=_parse_int(node.get("gasUsed", "0x0")),
            depth=depth,
            stack=[],
            memory=None,
            storage=None,
            return_data=node.get("output"),
        )


def _parse_hex_int(value: str | int) -> int:
    """Parse a hex string (0x-prefixed) or plain int into an integer."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if value.startswith("0x") or value.startswith("0X"):
            return int(value, 16)
        # Fallback: try decimal
        return int(value)
    return 0


def _parse_int(value: Any) -> int:
    """Coerce a value to int, handling both hex strings and plain ints."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if value.startswith("0x") or value.startswith("0X"):
            return int(value, 16)
        return int(value)
    return 0