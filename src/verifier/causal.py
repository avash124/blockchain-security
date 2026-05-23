"""Ablation testing — re-run the exploit with individual factors removed to verify causality."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from src.acquisition.fork_manager import ForkManager


class AblationOutcome(Enum):
    REVERTED = "REVERTED"
    NO_PROFIT = "NO_PROFIT"
    REDUCED_PROFIT = "REDUCED_PROFIT"
    UNCHANGED = "UNCHANGED"
    ERROR = "ERROR"


@dataclass
class AblationResult:
    factor_removed: str
    outcome: AblationOutcome
    details: str = ""
    profit_delta: float | None = None


class CausalVerifier:
    """Runs ablation tests by replaying the exploit with individual causal factors removed."""

    def __init__(self, fork_manager: ForkManager, rpc_url: str):
        self._fork_manager = fork_manager
        self._rpc_url = rpc_url

    def run_ablation(
        self,
        tx_hash: str,
        fork_block: int,
        causal_factors: list[dict[str, Any]],
    ) -> list[AblationResult]:
        """For each causal factor, fork the chain and replay without that factor."""
        results = []
        for factor in causal_factors:
            result = self._test_without_factor(tx_hash, fork_block, factor)
            results.append(result)
        return results

    def _test_without_factor(
        self,
        tx_hash: str,
        fork_block: int,
        factor: dict[str, Any],
    ) -> AblationResult:
        """Fork, apply the counterfactual modification, and replay."""
        # TODO:
        # 1. Start a fresh Anvil fork at fork_block
        # 2. Apply counterfactual state change (e.g., remove flash loan, patch storage)
        # 3. Replay the transaction
        # 4. Compare outcome to baseline
        raise NotImplementedError

    def _apply_counterfactual(
        self,
        factor: dict[str, Any],
        anvil_rpc: str,
    ) -> None:
        """Modify chain state to remove one causal factor."""
        # TODO: use anvil_setStorageAt, anvil_setBalance, etc.
        raise NotImplementedError
