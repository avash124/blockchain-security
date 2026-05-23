"""Analyzes post-exploit state to identify adjacent vulnerabilities and blast radius."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.ir.nodes import IRGraph
from src.llm.client import LLMClient
from src.verifier.state_diff import StateDiff


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

    def analyze(
        self,
        ir_graph: IRGraph,
        state_diff: StateDiff,
        scenario_config: dict[str, Any],
    ) -> BlastRadiusReport:
        """Analyze post-exploit state to assess full blast radius."""
        # TODO:
        # 1. Identify all contracts interacted with during the exploit
        # 2. Check which protocols share state (liquidity pools, oracles)
        # 3. Use LLM to reason about cascading effects
        # 4. Produce recommendations for affected parties
        raise NotImplementedError

    def _find_shared_dependencies(self, ir_graph: IRGraph) -> list[str]:
        """Identify contracts that share state with the exploited protocol."""
        # TODO: analyze SLOAD/SSTORE patterns + known protocol registries
        raise NotImplementedError

    def _estimate_cascading_loss(self, state_diff: StateDiff) -> float:
        """Estimate additional losses from cascading effects."""
        # TODO: use token price data + affected pool sizes
        raise NotImplementedError
