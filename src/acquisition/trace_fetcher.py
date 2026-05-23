"""Fetches and parses transaction traces via `cast run` or debug_traceTransaction."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any


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
    """Wraps `cast run` to get full EVM traces."""

    def __init__(self, rpc_url: str):
        self._rpc_url = rpc_url

    def fetch_trace(self, tx_hash: str) -> TransactionTrace:
        """Fetch a full structured trace for a transaction."""
        # TODO: call `cast run --trace-printer {tx_hash} --rpc-url {self._rpc_url}`
        # and parse the JSON output into TraceFrame objects
        raise NotImplementedError

    def fetch_call_tree(self, tx_hash: str) -> dict[str, Any]:
        """Fetch the nested call tree (debug_traceTransaction with callTracer)."""
        # TODO: use cast or direct JSON-RPC
        raise NotImplementedError

    def _parse_trace_json(self, raw: dict[str, Any]) -> TransactionTrace:
        """Parse raw JSON trace into structured dataclasses."""
        frames = []
        for log in raw.get("structLogs", []):
            frames.append(
                TraceFrame(
                    pc=log["pc"],
                    op=log["op"],
                    gas=log["gas"],
                    gas_cost=log["gasCost"],
                    depth=log["depth"],
                    stack=log.get("stack", []),
                    memory=log.get("memory"),
                    storage=log.get("storage"),
                )
            )

        return TransactionTrace(
            tx_hash=raw.get("txHash", ""),
            from_addr=raw.get("from", ""),
            to_addr=raw.get("to", ""),
            value=int(raw.get("value", "0"), 16) if isinstance(raw.get("value"), str) else 0,
            gas_used=raw.get("gasUsed", 0),
            status=raw.get("status", True),
            frames=frames,
        )
