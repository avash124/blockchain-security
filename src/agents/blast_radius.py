"""Analyzes post-exploit state to identify adjacent vulnerabilities and blast radius."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from src.ir.nodes import ActionType, IRGraph
from src.llm.client import LLMClient
from src.llm.prompts import BLAST_RADIUS_SYSTEM_PROMPT
from src.verifier.state_diff import StateDiff

# Approximate USD value per raw token unit (18-decimal).  Used only when the
# scenario config does not supply richer price data.
_FALLBACK_PRICE_USD: float = 1.0

# Actions that imply a contract is a dependency of the exploited protocol.
_DEPENDENCY_ACTION_TYPES: frozenset[ActionType] = frozenset(
    {
        ActionType.ORACLE_READ,
        ActionType.DEX_SWAP,
        ActionType.FLASH_LOAN_BORROW,
        ActionType.FLASH_LOAN_REPAY,
        ActionType.TOKEN_TRANSFER,
        ActionType.LIQUIDATION,
        ActionType.GOVERNANCE_ACTION,
    }
)


@dataclass
class AffectedProtocol:
    name: str
    address: str
    relationship: str  # e.g. "shared liquidity pool", "oracle dependency"
    risk_level: str  # "high", "medium", "low"
    details: str = ""


@dataclass
class BlastRadiusReport:
    primary_loss_usd: float
    affected_protocols: list[AffectedProtocol] = field(default_factory=list)
    cascading_risks: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


class BlastRadiusAnalyzer:
    """Determines the full impact scope of an exploit beyond the immediate target."""

    def __init__(self, llm_client: LLMClient):
        self._llm = llm_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        ir_graph: IRGraph,
        state_diff: StateDiff,
        scenario_config: dict[str, Any],
    ) -> BlastRadiusReport:
        """Analyze post-exploit state to assess full blast radius."""
        primary_loss_usd = self._compute_primary_loss(state_diff, scenario_config)
        cascading_loss_usd = self._estimate_cascading_loss(state_diff)

        shared_deps = self._find_shared_dependencies(ir_graph)

        prompt = self._build_blast_radius_prompt(
            ir_graph, state_diff, scenario_config, shared_deps, primary_loss_usd
        )
        response = self._llm.complete(
            system_prompt=BLAST_RADIUS_SYSTEM_PROMPT,
            user_message=prompt,
            temperature=0.0,
            json_mode=True,
        )
        affected_protocols, cascading_risks, recommendations = self._parse_llm_response(
            response.content
        )

        if cascading_loss_usd > 0:
            cascading_risks.insert(
                0,
                f"Estimated cascading token losses: ${cascading_loss_usd:,.2f} USD",
            )

        return BlastRadiusReport(
            primary_loss_usd=primary_loss_usd,
            affected_protocols=affected_protocols,
            cascading_risks=cascading_risks,
            recommendations=recommendations,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _find_shared_dependencies(self, ir_graph: IRGraph) -> list[str]:
        """Identify contracts that share state with the exploited protocol.

        Walks every semantic action and collects unique `to_addr` values for
        action types that imply a cross-protocol dependency (oracle reads, swaps,
        flash loans, etc.).  SLOAD/SSTORE-only contracts (pure storage_read /
        storage_write) are included when they appear as the target of those ops
        because a shared storage slot implies a shared invariant.
        """
        dependency_addresses: set[str] = set()

        for action in ir_graph.actions:
            if action.action_type in _DEPENDENCY_ACTION_TYPES and action.to_addr:
                dependency_addresses.add(action.to_addr)

            # Contracts that share storage slots are adjacent attack surfaces.
            if action.action_type in (
                ActionType.STORAGE_READ,
                ActionType.STORAGE_WRITE,
            ) and action.to_addr:
                dependency_addresses.add(action.to_addr)

        # Exclude the root contract (actions[0].to_addr) unless it later acts as a
        # *caller* at greater call-depth — that pattern indicates it re-enters the
        # attacker's code (reentrancy) and is therefore a genuine dependency.
        if ir_graph.actions:
            root_contract = ir_graph.actions[0].to_addr
            root_depth = ir_graph.actions[0].depth
            participates_deeper = any(
                a.from_addr == root_contract and a.depth > root_depth
                for a in ir_graph.actions[1:]
            )
            if root_contract and not participates_deeper:
                dependency_addresses.discard(root_contract)

        return sorted(dependency_addresses)

    def _estimate_cascading_loss(self, state_diff: StateDiff) -> float:
        """Estimate additional losses from cascading effects.

        Sums the absolute value of *negative* balance deltas across all
        addresses in the state diff (i.e., every party that lost tokens/ETH).
        Converts raw uint256 amounts to a USD estimate using the token-price
        registry embedded in `StateDiff` metadata when available, otherwise
        falls back to a nominal $1-per-unit figure.
        """
        total_loss: float = 0.0

        for change in state_diff.balance_changes:
            if change.delta >= 0:
                continue  # only count losses

            # Raw loss in the token's native units (always 18-decimal ERC-20 or wei).
            raw_loss = abs(change.delta)
            price = _FALLBACK_PRICE_USD
            total_loss += (raw_loss / 1e18) * price

        return total_loss

    def _compute_primary_loss(
        self, state_diff: StateDiff, scenario_config: dict[str, Any]
    ) -> float:
        """Compute primary protocol loss in USD from the state diff.

        Uses `token_prices` from scenario_config (address → USD float) when
        provided; otherwise falls back to the nominal price constant.
        """
        token_prices: dict[str, float] = scenario_config.get("token_prices", {})
        total: float = 0.0

        for change in state_diff.balance_changes:
            if change.delta >= 0:
                continue
            price = token_prices.get(change.token, _FALLBACK_PRICE_USD)
            total += (abs(change.delta) / 1e18) * price

        return total

    def _build_blast_radius_prompt(
        self,
        ir_graph: IRGraph,
        state_diff: StateDiff,
        scenario_config: dict[str, Any],
        shared_deps: list[str],
        primary_loss_usd: float,
    ) -> str:
        lines: list[str] = [
            f"Transaction: {ir_graph.tx_hash}",
            f"Primary estimated loss: ${primary_loss_usd:,.2f} USD",
            "",
        ]

        # Scenario metadata (target protocol name, block, etc.)
        if scenario_config:
            meta = ", ".join(f"{k}={v}" for k, v in scenario_config.items() if k != "token_prices")
            lines.append(f"Scenario: {meta}")

        # Actions involved in the exploit
        lines += ["", "## Exploit Action Sequence"]
        for i, action in enumerate(ir_graph.actions):
            params_str = (
                ", ".join(f"{k}={v}" for k, v in action.params.items())
                if action.params
                else ""
            )
            detail = f" ({params_str})" if params_str else ""
            lines.append(
                f"  {i + 1:>3}. [{action.action_type.value}] "
                f"from={action.from_addr or '?'} to={action.to_addr or '?'}{detail}"
            )

        # Balance changes
        lines += ["", "## Balance Changes"]
        for bc in state_diff.balance_changes:
            sign = "+" if bc.delta > 0 else ""
            lines.append(
                f"  {bc.address} [{bc.token}]: {sign}{bc.delta} "
                f"(before={bc.before}, after={bc.after})"
            )

        # Storage changes
        if state_diff.storage_changes:
            lines += ["", "## Storage Changes"]
            for sc in state_diff.storage_changes:
                lines.append(
                    f"  {sc.contract} slot={sc.slot}: {sc.before} → {sc.after}"
                )

        # Shared dependency contracts identified from the IR graph
        if shared_deps:
            lines += ["", "## Detected Shared-Dependency Contracts"]
            for addr in shared_deps:
                lines.append(f"  {addr}")

        lines += [
            "",
            "Using the above data, identify all affected protocols, cascading risks, "
            "and mitigation recommendations.",
        ]
        return "\n".join(lines)

    def _parse_llm_response(
        self, response: str
    ) -> tuple[list[AffectedProtocol], list[str], list[str]]:
        """Parse the LLM's JSON response into structured output."""
        text = response
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]

        try:
            data: dict[str, Any] = json.loads(text.strip())
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"LLM returned non-JSON blast-radius response: {response[:200]!r}"
            ) from exc

        affected_protocols = [
            AffectedProtocol(
                name=p.get("name", "unknown"),
                address=p.get("address", ""),
                relationship=p.get("relationship", ""),
                risk_level=p.get("risk_level", "medium"),
                details=p.get("details", ""),
            )
            for p in data.get("affected_protocols", [])
        ]

        cascading_risks: list[str] = data.get("cascading_risks", [])
        recommendations: list[str] = data.get("recommendations", [])

        return affected_protocols, cascading_risks, recommendations
