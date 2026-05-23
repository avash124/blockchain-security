"""Computes balance and storage diffs between pre- and post-exploit state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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

    def __init__(self, rpc_url: str):
        self._rpc_url = rpc_url

    def compute(
        self,
        tx_hash: str,
        addresses: list[str],
        tokens: list[str] | None = None,
        storage_slots: dict[str, list[str]] | None = None,
    ) -> StateDiff:
        """Compute the full state diff for a transaction."""
        # TODO:
        # 1. Get block number from tx receipt
        # 2. Snapshot balances at block - 1 and block
        # 3. Snapshot storage slots at block - 1 and block
        # 4. Compare and build StateDiff
        raise NotImplementedError

    def _get_balance(self, address: str, block: int) -> int:
        """Get ETH balance at a specific block."""
        # TODO: eth_getBalance RPC call
        raise NotImplementedError

    def _get_token_balance(self, token: str, address: str, block: int) -> int:
        """Get ERC20 token balance at a specific block."""
        # TODO: eth_call to balanceOf at specific block
        raise NotImplementedError

    def _get_storage(self, contract: str, slot: str, block: int) -> str:
        """Get storage value at a specific slot and block."""
        # TODO: eth_getStorageAt RPC call
        raise NotImplementedError
