"""Fetches and parses transaction traces via debug_traceTransaction JSON-RPC."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


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

    _RPC_TIMEOUT = 120.0  # debug_traceTransaction can be slow on complex txs

    def __init__(self, rpc_url: str):
        self._rpc_url = rpc_url

    def fetch_trace(self, tx_hash: str) -> TransactionTrace:
        """Fetch a full structured trace for a transaction.

        Makes two RPC calls:
        1. eth_getTransactionReceipt — for from/to/value/gasUsed/status
        2. debug_traceTransaction  — for the struct-log opcode trace
        """
        tx_hash = self._normalize_tx_hash(tx_hash)

        receipt = self._fetch_receipt(tx_hash)
        raw_trace = self._fetch_struct_log(tx_hash)

        return self._parse_trace_json(raw_trace, tx_hash=tx_hash, receipt=receipt)

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
        """Send a JSON-RPC 2.0 request and return the 'result' field."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }

        try:
            response = httpx.post(
                self._rpc_url,
                json=payload,
                timeout=self._RPC_TIMEOUT,
            )
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise TraceFetchError(
                f"RPC request timed out for {method}: {exc}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise TraceFetchError(
                f"RPC HTTP error for {method}: {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise TraceFetchError(
                f"RPC connection error for {method}: {exc}"
            ) from exc

        body = response.json()

        if "error" in body:
            err = body["error"]
            code = err.get("code", "?")
            message = err.get("message", str(err))
            raise TraceFetchError(f"RPC error in {method} (code {code}): {message}")

        if "result" not in body:
            raise TraceFetchError(
                f"RPC response for {method} missing 'result' field"
            )

        return body["result"]

    def _fetch_receipt(self, tx_hash: str) -> dict[str, Any]:
        """Fetch the transaction receipt for metadata."""
        result = self._rpc_call("eth_getTransactionReceipt", [tx_hash])
        if result is None:
            raise TraceFetchError(
                f"Transaction receipt not found for {tx_hash}. "
                "The transaction may not exist or the node may not have it."
            )
        return result

    def _fetch_struct_log(self, tx_hash: str) -> dict[str, Any]:
        """Fetch the struct-log trace via debug_traceTransaction."""
        result = self._rpc_call(
            "debug_traceTransaction",
            [
                tx_hash,
                {
                    "enableMemory": True,
                    "enableReturnData": True,
                },
            ],
        )

        if not isinstance(result, dict):
            raise TraceFetchError(
                f"Unexpected struct-log response type for {tx_hash}: {type(result)}"
            )

        return result

    def _parse_trace_json(
        self,
        raw: dict[str, Any],
        *,
        tx_hash: str,
        receipt: dict[str, Any],
    ) -> TransactionTrace:
        """Parse raw JSON trace and receipt into structured dataclasses."""
        frames: list[TraceFrame] = []
        for log in raw.get("structLogs", []):
            return_data = log.get("returnData")
            # Some nodes return returnData as empty string — normalize to None
            if return_data == "":
                return_data = None

            frames.append(
                TraceFrame(
                    pc=int(log.get("pc", 0)),
                    op=log.get("op", "UNKNOWN"),
                    gas=_parse_int(log.get("gas", 0)),
                    gas_cost=_parse_int(log.get("gasCost", 0)),
                    depth=int(log.get("depth", 1)),
                    stack=log.get("stack", []),
                    memory=log.get("memory") or None,
                    storage=log.get("storage") or None,
                    return_data=return_data,
                )
            )

        # Extract metadata from receipt
        from_addr = receipt.get("from", "")
        to_addr = receipt.get("to") or ""  # contract-creation txs have to=null
        value_raw = receipt.get("value")
        gas_used_raw = receipt.get("gasUsed", "0x0")
        status_raw = receipt.get("status", "0x1")

        return TransactionTrace(
            tx_hash=tx_hash,
            from_addr=from_addr.lower() if from_addr else "",
            to_addr=to_addr.lower() if to_addr else "",
            value=_parse_hex_int(value_raw) if value_raw is not None else 0,
            gas_used=_parse_hex_int(gas_used_raw),
            status=_parse_hex_int(status_raw) == 1,
            frames=frames,
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