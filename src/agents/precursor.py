"""Walks attacker address history to find reconnaissance and setup transactions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PrecursorTx:
    tx_hash: str
    block_number: int
    timestamp: int
    description: str
    relevance: str  # "funding", "deployment", "test_run", "reconnaissance"


@dataclass
class AttackerProfile:
    address: str
    funding_source: str | None = None
    precursor_txs: list[PrecursorTx] = field(default_factory=list)
    deployed_contracts: list[str] = field(default_factory=list)
    estimated_preparation_time_hours: float | None = None


class PrecursorAnalyzer:
    """Analyzes attacker address history to build a timeline of preparation."""

    def __init__(self, rpc_url: str, etherscan_api_key: str | None = None):
        self._rpc_url = rpc_url
        self._etherscan_key = etherscan_api_key

    def analyze(self, attacker_address: str, exploit_block: int) -> AttackerProfile:
        """Walk backward from the exploit to find setup transactions."""
        # TODO:
        # 1. Fetch all txs from attacker address via Etherscan
        # 2. Filter to txs before exploit_block
        # 3. Identify funding source (CEX, tornado, bridge)
        # 4. Find contract deployments (attack contracts)
        # 5. Detect test runs (failed txs to same target)
        raise NotImplementedError

    def _fetch_address_history(self, address: str) -> list[dict[str, Any]]:
        """Get all transactions for an address."""
        # TODO: Etherscan txlist API
        raise NotImplementedError

    def _classify_precursor(self, tx: dict[str, Any]) -> PrecursorTx | None:
        """Classify a transaction as a precursor type or None if irrelevant."""
        # TODO: heuristic classification based on tx characteristics
        raise NotImplementedError

    def _identify_funding_source(self, txs: list[dict[str, Any]]) -> str | None:
        """Determine where the attacker's initial ETH came from."""
        # TODO: check known CEX hot wallets, Tornado Cash, bridges
        raise NotImplementedError
