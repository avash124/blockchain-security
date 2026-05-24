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

    # Token-budget caps for the prompt. Large exploits (e.g. Cream at ~14.9M
    # gas) lift into thousands of IR actions; sending every one blows past
    # provider TPM limits. We send a representative arc instead — the head
    # captures setup/flash-loan, the tail captures drainage/repay.
    _MAX_HEAD_ACTIONS = 25
    _MAX_TAIL_ACTIONS = 15
    _MAX_BALANCE_GAINS = 8
    _MAX_BALANCE_LOSSES = 8
    _MAX_STORAGE_CHANGES = 10
    _MAX_SHARED_DEPS = 15
    _MAX_SCENARIO_FIELDS = {
        "scenario", "name", "chain", "tx_hash", "fork_block",
        "attacker_address", "exploit_technique", "estimated_loss_usd", "tags",
    }

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

        # Scenario metadata — whitelist the small, high-signal fields only
        # (full configs can carry verbose target_contracts arrays).
        if scenario_config:
            meta = ", ".join(
                f"{k}={v}"
                for k, v in scenario_config.items()
                if k in self._MAX_SCENARIO_FIELDS
            )
            if meta:
                lines.append(f"Scenario: {meta}")

        # Action distribution: a compact frequency table tells the LLM the
        # exploit shape ("4 flash loans, 200 transfers, 50 swaps") without
        # listing every action individually.
        type_counts: dict[str, int] = {}
        for action in ir_graph.actions:
            key = action.action_type.value
            type_counts[key] = type_counts.get(key, 0) + 1
        if type_counts:
            dist = ", ".join(
                f"{k}={v}" for k, v in sorted(type_counts.items(), key=lambda kv: -kv[1])
            )
            lines += ["", f"## Action Distribution ({len(ir_graph.actions)} total)", f"  {dist}"]

        # Representative action arc: head (setup) + tail (drainage).
        lines += ["", "## Exploit Action Arc (head + tail)"]
        head, tail = self._sample_actions(ir_graph.actions)
        for i, action in head:
            lines.append(self._format_action_line(i, action))
        if tail and len(ir_graph.actions) > self._MAX_HEAD_ACTIONS + self._MAX_TAIL_ACTIONS:
            skipped = len(ir_graph.actions) - self._MAX_HEAD_ACTIONS - self._MAX_TAIL_ACTIONS
            lines.append(f"  ... ({skipped} actions omitted) ...")
        for i, action in tail:
            lines.append(self._format_action_line(i, action))

        # Top balance movements only — gainers and losers ranked by magnitude.
        gains, losses = self._top_balance_changes(state_diff)
        if gains or losses:
            lines += ["", "## Top Balance Movements"]
            for bc in gains:
                lines.append(
                    f"  + {self._short_addr(bc.address)} [{self._short_token(bc.token)}]: "
                    f"+{bc.delta}"
                )
            for bc in losses:
                lines.append(
                    f"  - {self._short_addr(bc.address)} [{self._short_token(bc.token)}]: "
                    f"{bc.delta}"
                )

        # Storage changes — capped.
        if state_diff.storage_changes:
            lines += ["", "## Storage Changes (capped)"]
            for sc in state_diff.storage_changes[: self._MAX_STORAGE_CHANGES]:
                lines.append(
                    f"  {self._short_addr(sc.contract)} slot={sc.slot[:10]}…: "
                    f"{sc.before[:10]}… → {sc.after[:10]}…"
                )
            if len(state_diff.storage_changes) > self._MAX_STORAGE_CHANGES:
                lines.append(
                    f"  ... ({len(state_diff.storage_changes) - self._MAX_STORAGE_CHANGES} more) ..."
                )

        # Shared-dependency contracts — capped, shortened.
        if shared_deps:
            lines += ["", "## Detected Shared-Dependency Contracts"]
            for addr in shared_deps[: self._MAX_SHARED_DEPS]:
                lines.append(f"  {self._short_addr(addr)}")
            if len(shared_deps) > self._MAX_SHARED_DEPS:
                lines.append(f"  ... ({len(shared_deps) - self._MAX_SHARED_DEPS} more) ...")

        lines += [
            "",
            "Using the above data, identify all affected protocols, cascading risks, "
            "and mitigation recommendations.",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Prompt-trimming helpers
    # ------------------------------------------------------------------

    def _sample_actions(
        self, actions: list[Any],
    ) -> tuple[list[tuple[int, Any]], list[tuple[int, Any]]]:
        """Return (head, tail) representative slices with original indices."""
        if len(actions) <= self._MAX_HEAD_ACTIONS + self._MAX_TAIL_ACTIONS:
            return list(enumerate(actions)), []
        head = list(enumerate(actions[: self._MAX_HEAD_ACTIONS]))
        tail_start = len(actions) - self._MAX_TAIL_ACTIONS
        tail = [(tail_start + i, a) for i, a in enumerate(actions[tail_start:])]
        return head, tail

    def _format_action_line(self, idx: int, action: Any) -> str:
        """Compact one-line representation of an IR action.

        Only the highest-signal params (value, function, token, amount) survive
        — the full params dict is dropped because individual flash-loan calls
        can carry 5+ fields and we have thousands of them.
        """
        keep_keys = ("function", "value", "amount", "token", "slot")
        kept = {k: action.params[k] for k in keep_keys if k in action.params}
        detail = (
            " (" + ", ".join(f"{k}={self._compact_value(v)}" for k, v in kept.items()) + ")"
            if kept
            else ""
        )
        return (
            f"  {idx + 1:>4}. [{action.action_type.value}] d={action.depth} "
            f"to={self._short_addr(action.to_addr)}{detail}"
        )

    def _top_balance_changes(
        self, state_diff: StateDiff,
    ) -> tuple[list[Any], list[Any]]:
        """Top N gainers and losers by absolute delta."""
        gains = sorted(
            (b for b in state_diff.balance_changes if b.is_gain),
            key=lambda b: -b.delta,
        )[: self._MAX_BALANCE_GAINS]
        losses = sorted(
            (b for b in state_diff.balance_changes if not b.is_gain and b.delta != 0),
            key=lambda b: b.delta,
        )[: self._MAX_BALANCE_LOSSES]
        return gains, losses

    @staticmethod
    def _short_addr(addr: str) -> str:
        if not addr:
            return "?"
        a = addr.lower()
        if len(a) <= 12:
            return a
        return f"{a[:8]}…{a[-4:]}"

    @staticmethod
    def _short_token(token: str) -> str:
        if not token or token == "ETH":
            return token or "?"
        # Token contract addresses get the same short treatment as addresses
        return BlastRadiusAnalyzer._short_addr(token)

    @staticmethod
    def _compact_value(value: Any) -> str:
        s = str(value)
        if len(s) > 24:
            return s[:10] + "…" + s[-6:]
        return s

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
