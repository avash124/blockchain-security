"""Computes balance and storage diffs between pre- and post-exploit state."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class StateDiffError(Exception):
    """Raised when a state-diff RPC operation fails."""


@dataclass
class BalanceChange:
    address: str
    token: str  # "ETH" or token contract address
    before: int
    after: int

    @property
    def delta(self) -> int:
        return self.after - self.before

    @property
    def is_gain(self) -> bool:
        return self.delta > 0


@dataclass
class StorageChange:
    contract: str
    slot: str
    before: str
    after: str


@dataclass
class StateDiff:
    """Full state diff between pre-exploit and post-exploit snapshots."""
    balance_changes: list[BalanceChange] = field(default_factory=list)
    storage_changes: list[StorageChange] = field(default_factory=list)
    created_contracts: list[str] = field(default_factory=list)
    destroyed_contracts: list[str] = field(default_factory=list)

    def get_gains(self, address: str) -> list[BalanceChange]:
        return [b for b in self.balance_changes if b.address == address and b.is_gain]

    def get_losses(self, address: str) -> list[BalanceChange]:
        return [b for b in self.balance_changes if b.address == address and not b.is_gain]

    def total_profit(self, address: str) -> int:
        return sum(b.delta for b in self.balance_changes if b.address == address)

    def to_dict(self) -> dict[str, Any]:
        return {
            "balance_changes": [
                {
                    "address": b.address,
                    "token": b.token,
                    "before": str(b.before),
                    "after": str(b.after),
                    "delta": str(b.delta),
                }
                for b in self.balance_changes
            ],
            "storage_changes": [
                {
                    "contract": s.contract,
                    "slot": s.slot,
                    "before": s.before,
                    "after": s.after,
                }
                for s in self.storage_changes
            ],
        }


class StateDiffComputer:
    """Snapshots chain state before and after a transaction to compute diffs."""

    _RPC_TIMEOUT = 30.0
    # ERC-20 balanceOf(address) selector
    _BALANCE_OF_SELECTOR = "0x70a08231"

    def __init__(self, rpc_url: str):
        self._rpc_url = rpc_url

    def compute(
        self,
        tx_hash: str,
        addresses: list[str],
        tokens: list[str] | None = None,
        storage_slots: dict[str, list[str]] | None = None,
    ) -> StateDiff:
        """Compute the full state diff for a transaction.

        Snapshots state at block-1 (pre-attack) and block (post-attack),
        then diffs ETH balances, token balances, and storage slots.
        """
        receipt = self._get_tx_receipt(tx_hash)
        block = _parse_hex_int(receipt["blockNumber"])
        pre_block = block - 1

        balance_changes: list[BalanceChange] = []
        storage_changes: list[StorageChange] = []

        for addr in addresses:
            addr_lower = addr.lower()

            # ETH balance diff
            eth_before = self._get_balance(addr_lower, pre_block)
            eth_after = self._get_balance(addr_lower, block)
            if eth_before != eth_after:
                balance_changes.append(
                    BalanceChange(address=addr_lower, token="ETH", before=eth_before, after=eth_after)
                )

            # ERC-20 token balance diffs
            if tokens:
                for token in tokens:
                    token_lower = token.lower()
                    before = self._get_token_balance(token_lower, addr_lower, pre_block)
                    after = self._get_token_balance(token_lower, addr_lower, block)
                    if before != after:
                        balance_changes.append(
                            BalanceChange(address=addr_lower, token=token_lower, before=before, after=after)
                        )

        # Storage slot diffs
        if storage_slots:
            for contract, slots in storage_slots.items():
                contract_lower = contract.lower()
                for slot in slots:
                    before = self._get_storage(contract_lower, slot, pre_block)
                    after = self._get_storage(contract_lower, slot, block)
                    if before != after:
                        storage_changes.append(
                            StorageChange(contract=contract_lower, slot=slot, before=before, after=after)
                        )

        # Detect contract creation / destruction via code presence change
        created, destroyed = self._detect_contract_lifecycle(addresses, pre_block, block)

        return StateDiff(
            balance_changes=balance_changes,
            storage_changes=storage_changes,
            created_contracts=created,
            destroyed_contracts=destroyed,
        )

    # ------------------------------------------------------------------
    # RPC primitives
    # ------------------------------------------------------------------

    def _get_balance(self, address: str, block: int) -> int:
        """Get ETH balance at a specific block via eth_getBalance."""
        result = self._rpc_call("eth_getBalance", [address, _to_hex(block)])
        return _parse_hex_int(result)

    def _get_token_balance(self, token: str, address: str, block: int) -> int:
        """Get ERC20 token balance via eth_call to balanceOf at a specific block."""
        # ABI-encode: selector + address left-padded to 32 bytes
        calldata = self._BALANCE_OF_SELECTOR + address.removeprefix("0x").lower().zfill(64)
        result = self._rpc_call(
            "eth_call",
            [{"to": token, "data": calldata}, _to_hex(block)],
        )
        if not result or result == "0x":
            return 0
        return _parse_hex_int(result)

    def _get_storage(self, contract: str, slot: str, block: int) -> str:
        """Get storage value at a specific slot and block via eth_getStorageAt."""
        result = self._rpc_call("eth_getStorageAt", [contract, slot, _to_hex(block)])
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_tx_receipt(self, tx_hash: str) -> dict[str, Any]:
        """Fetch the transaction receipt to determine the block number."""
        result = self._rpc_call("eth_getTransactionReceipt", [tx_hash])
        if result is None:
            raise StateDiffError(f"Transaction receipt not found for {tx_hash}")
        return result

    def _get_code(self, address: str, block: int) -> str:
        """Get contract bytecode at a specific block via eth_getCode."""
        result = self._rpc_call("eth_getCode", [address, _to_hex(block)])
        return result

    def _detect_contract_lifecycle(
        self, addresses: list[str], pre_block: int, post_block: int
    ) -> tuple[list[str], list[str]]:
        """Detect contracts created or destroyed between two blocks."""
        created: list[str] = []
        destroyed: list[str] = []
        for addr in addresses:
            addr_lower = addr.lower()
            code_before = self._get_code(addr_lower, pre_block)
            code_after = self._get_code(addr_lower, post_block)
            had_code = code_before not in (None, "0x", "0x0", "")
            has_code = code_after not in (None, "0x", "0x0", "")
            if not had_code and has_code:
                created.append(addr_lower)
            elif had_code and not has_code:
                destroyed.append(addr_lower)
        return created, destroyed

    def _rpc_call(self, method: str, params: list[Any]) -> Any:
        """Send a JSON-RPC 2.0 request and return the 'result' field."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }
        try:
            response = httpx.post(self._rpc_url, json=payload, timeout=self._RPC_TIMEOUT)
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise StateDiffError(f"RPC timeout for {method}: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise StateDiffError(
                f"RPC HTTP error for {method}: {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise StateDiffError(f"RPC connection error for {method}: {exc}") from exc

        body = response.json()
        if "error" in body:
            err = body["error"]
            code = err.get("code", "?")
            message = err.get("message", str(err))
            raise StateDiffError(f"RPC error in {method} (code {code}): {message}")
        if "result" not in body:
            raise StateDiffError(f"RPC response for {method} missing 'result' field")
        return body["result"]


def _to_hex(value: int) -> str:
    """Convert an integer to a 0x-prefixed hex string."""
    return hex(value)


def _parse_hex_int(value: str | int) -> int:
    """Parse a hex string (0x-prefixed) or plain int into an integer."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if value.startswith(("0x", "0X")):
            return int(value, 16)
        return int(value)
    return 0
