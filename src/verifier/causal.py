"""Ablation testing — re-run the exploit with individual factors removed to verify causality."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

from src.acquisition.fork_manager import AnvilInstance, ForkError, ForkManager
from src.acquisition.rpc_client import RpcClient, RpcError

logger = logging.getLogger(__name__)

# Thresholds for bucketing replay-vs-baseline profit ratios into outcomes.
_NO_PROFIT_RATIO = 0.10
_REDUCED_RATIO = 0.90

# Default gas top-up handed to the impersonated attacker on the fork so a
# previously-empty account can still cover replay gas.
_REPLAY_GAS_FUEL_WEI = 10 * 10**18


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


@dataclass
class _BaselineOutcome:
    succeeded: bool
    profit_wei: int
    attacker: str


class CausalVerifier:
    """Runs ablation tests by replaying the exploit with individual causal factors removed."""

    def __init__(self, fork_manager: ForkManager, rpc_url: str):
        self._fork_manager = fork_manager
        self._rpc_url = rpc_url
        self._upstream_rpc = RpcClient(rpc_url, timeout=60.0)
        # Keyed by (tx_hash, fork_block) so multiple factors share one baseline replay.
        self._baseline_cache: dict[tuple[str, int], _BaselineOutcome] = {}

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
        """Fork, apply the counterfactual modification, replay the tx, and bucket the outcome."""
        factor_name = factor.get("name") or factor.get("factor_type") or "unknown_factor"

        try:
            tx = self._fetch_transaction(tx_hash)
        except RpcError as exc:
            return AblationResult(factor_name, AblationOutcome.ERROR, f"failed to fetch tx: {exc}")

        try:
            baseline = self._get_or_compute_baseline(tx_hash, fork_block, tx)
        except (ForkError, RpcError) as exc:
            return AblationResult(factor_name, AblationOutcome.ERROR, f"baseline replay failed: {exc}")

        try:
            instance = self._fork_manager.start_fork(self._rpc_url, fork_block - 1)
        except ForkError as exc:
            return AblationResult(factor_name, AblationOutcome.ERROR, f"fork failed: {exc}")

        try:
            try:
                self._apply_counterfactual(factor, instance.rpc_url)
            except (RpcError, ForkError, ValueError) as exc:
                return AblationResult(
                    factor_name,
                    AblationOutcome.ERROR,
                    f"counterfactual could not be applied: {exc}",
                )

            try:
                replay_status, replay_profit, replay_msg = self._replay(tx, instance)
            except (RpcError, ForkError) as exc:
                return AblationResult(
                    factor_name,
                    AblationOutcome.ERROR,
                    f"replay failed: {exc}",
                )
        finally:
            self._fork_manager.stop_fork(instance)

        return self._classify(factor_name, baseline, replay_status, replay_profit, replay_msg)

    def _apply_counterfactual(
        self,
        factor: dict[str, Any],
        anvil_rpc: str,
    ) -> None:
        """Modify chain state to remove one causal factor.

        Routes on ``factor["anvil_method"]`` and consumes concrete params
        (address/slot/value/balance/code) from the factor dict. Raises
        ``ValueError`` when a required field is missing — the caller turns
        that into an ERROR ``AblationResult`` so the verdict engine still
        gets a neutral data point rather than crashing the whole pipeline.
        """
        method = factor.get("anvil_method")
        if not method:
            raise ValueError("factor missing 'anvil_method'")

        address = factor.get("address") or factor.get("target_address")
        rpc = RpcClient(anvil_rpc, timeout=30.0)

        if method == "anvil_setBalance":
            if not address:
                raise ValueError(f"{factor.get('name')!r} missing 'address' for anvil_setBalance")
            balance = factor.get("balance", 0)
            balance_hex = balance if isinstance(balance, str) else hex(balance)
            rpc.call("anvil_setBalance", [address, balance_hex])

        elif method == "anvil_setStorageAt":
            if not address:
                raise ValueError(f"{factor.get('name')!r} missing 'address' for anvil_setStorageAt")
            slot = factor.get("slot")
            if slot is None:
                raise ValueError(f"{factor.get('name')!r} missing 'slot' for anvil_setStorageAt")
            value = factor.get("value", 0)
            slot_hex = slot if isinstance(slot, str) else _to_32byte_hex(slot)
            value_hex = value if isinstance(value, str) else _to_32byte_hex(value)
            rpc.call("anvil_setStorageAt", [address, slot_hex, value_hex])

        elif method == "anvil_setCode":
            if not address:
                raise ValueError(f"{factor.get('name')!r} missing 'address' for anvil_setCode")
            code = factor.get("code", "0x")
            rpc.call("anvil_setCode", [address, code])

        else:
            raise ValueError(f"unsupported anvil_method: {method!r}")

    # ------------------------------------------------------------------
    # Baseline + replay
    # ------------------------------------------------------------------

    def _get_or_compute_baseline(
        self,
        tx_hash: str,
        fork_block: int,
        tx: dict[str, Any],
    ) -> _BaselineOutcome:
        key = (tx_hash.lower(), fork_block)
        cached = self._baseline_cache.get(key)
        if cached is not None:
            return cached

        instance = self._fork_manager.start_fork(self._rpc_url, fork_block - 1)
        try:
            status, profit, _msg = self._replay(tx, instance)
        finally:
            self._fork_manager.stop_fork(instance)

        baseline = _BaselineOutcome(
            succeeded=status,
            profit_wei=profit,
            attacker=(tx.get("from") or "").lower(),
        )
        self._baseline_cache[key] = baseline
        return baseline

    def _replay(
        self,
        tx: dict[str, Any],
        instance: AnvilInstance,
    ) -> tuple[bool, int, str]:
        """Replay ``tx`` on ``instance`` and return (status_ok, attacker_eth_delta_wei, msg)."""
        rpc = RpcClient(instance.rpc_url, timeout=120.0)
        attacker = (tx.get("from") or "").lower()
        if not attacker:
            raise RpcError("tx data missing 'from' address")

        try:
            rpc.call("anvil_impersonateAccount", [attacker])
        except RpcError as exc:
            raise ForkError(f"impersonation failed: {exc}") from exc

        # Top up so a previously-empty fork balance doesn't OOG.
        try:
            rpc.call("anvil_setBalance", [attacker, hex(_REPLAY_GAS_FUEL_WEI)])
        except RpcError as exc:
            logger.debug("anvil_setBalance top-up failed (non-fatal): %s", exc)

        pre_balance = int(rpc.call("eth_getBalance", [attacker, "latest"]), 16)
        params = self._build_replay_params(tx, attacker)

        try:
            sent_hash = rpc.call("eth_sendTransaction", [params])
        except RpcError as exc:
            return False, 0, f"send rejected: {exc}"

        # Anvil forks are launched with --no-mining, so mine the queued tx.
        try:
            rpc.call("evm_mine", [])
        except RpcError as exc:
            raise ForkError(f"evm_mine failed: {exc}") from exc

        receipt = rpc.call("eth_getTransactionReceipt", [sent_hash])
        if receipt is None:
            return False, 0, "no receipt — replay never mined"
        if int(receipt.get("status", "0x0"), 16) != 1:
            return False, 0, "tx reverted on replay"

        post_balance = int(rpc.call("eth_getBalance", [attacker, "latest"]), 16)
        return True, post_balance - pre_balance, "tx succeeded on replay"

    @staticmethod
    def _build_replay_params(tx: dict[str, Any], attacker: str) -> dict[str, Any]:
        """Build eth_sendTransaction params from the original mainnet tx data."""
        params: dict[str, Any] = {
            "from": attacker,
            "data": tx.get("input", "0x"),
            "value": tx.get("value", "0x0"),
            "gas": tx.get("gas", hex(15_000_000)),
        }
        to = tx.get("to")
        if to:
            params["to"] = to
        return params

    def _fetch_transaction(self, tx_hash: str) -> dict[str, Any]:
        """Fetch the raw mainnet tx so we can rebuild it on the fork."""
        result = self._upstream_rpc.call("eth_getTransactionByHash", [tx_hash])
        if result is None:
            raise RpcError(f"transaction {tx_hash} not found upstream")
        return result

    # ------------------------------------------------------------------
    # Outcome classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify(
        factor_name: str,
        baseline: _BaselineOutcome,
        replay_status: bool,
        replay_profit: int,
        replay_msg: str,
    ) -> AblationResult:
        delta_wei = replay_profit - baseline.profit_wei
        delta_eth = delta_wei / 1e18
        details = (
            f"{replay_msg} "
            f"(baseline_profit={baseline.profit_wei} wei, replay_profit={replay_profit} wei)"
        )

        if not replay_status:
            return AblationResult(factor_name, AblationOutcome.REVERTED, details, profit_delta=delta_eth)

        if baseline.profit_wei <= 0:
            # No baseline profit to compare against → call the outcome unchanged
            # if both succeeded with the same (non-positive) profit, otherwise
            # surface it as ERROR rather than silently inventing a ratio.
            outcome = (
                AblationOutcome.UNCHANGED
                if baseline.succeeded == replay_status
                else AblationOutcome.ERROR
            )
            return AblationResult(factor_name, outcome, details, profit_delta=delta_eth)

        ratio = replay_profit / baseline.profit_wei
        if ratio < _NO_PROFIT_RATIO:
            outcome = AblationOutcome.NO_PROFIT
        elif ratio < _REDUCED_RATIO:
            outcome = AblationOutcome.REDUCED_PROFIT
        else:
            outcome = AblationOutcome.UNCHANGED
        return AblationResult(factor_name, outcome, details, profit_delta=delta_eth)


def _to_32byte_hex(value: int) -> str:
    return "0x" + format(value, "064x")
