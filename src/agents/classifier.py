"""Classifies exploit technique from the IR graph using LLM reasoning."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from src.ir.nodes import IRGraph
from src.llm.client import LLMClient
from src.llm.prompts import CLASSIFIER_SYSTEM_PROMPT

DEFAULT_TECHNIQUES: dict[str, dict[str, Any]] = {
    "flash_loan_attack": {
        "description": "Borrows a flash loan to amplify capital and manipulate protocol state within a single transaction.",
        "indicators": ["flash_loan_borrow", "dex_swap", "flash_loan_repay"],
    },
    "price_oracle_manipulation": {
        "description": "Moves spot price on a DEX to corrupt an on-chain oracle reading used by a lending/derivatives protocol.",
        "indicators": ["dex_swap", "oracle_read", "storage_write"],
    },
    "reentrancy": {
        "description": "Exploits a missing or incorrectly ordered reentrancy guard — makes a recursive call before state is updated.",
        "indicators": ["eth_transfer", "storage_write", "recursive_call_pattern"],
    },
    "governance_attack": {
        "description": "Passes a malicious governance proposal (often via vote-buying or flash-borrowed governance tokens) to seize protocol funds.",
        "indicators": ["governance_action", "token_transfer", "flash_loan_borrow"],
    },
    "delegate_call_exploit": {
        "description": "Exploits a delegatecall into an untrusted implementation contract to overwrite critical storage slots.",
        "indicators": ["delegate_call", "storage_write"],
    },
    "access_control_bypass": {
        "description": "Calls a privileged function without proper authorization — misconfigured modifier or missing ownership check.",
        "indicators": ["storage_write", "token_transfer"],
    },
    "liquidity_pool_drain": {
        "description": "Drains a liquidity pool via arithmetic precision errors, rounding bugs, or donation-based share inflation.",
        "indicators": ["token_transfer", "dex_swap", "flash_loan_borrow"],
    },
    "sandwich_attack": {
        "description": "MEV sandwich: front-run a victim swap to move price, then back-run to profit from the slippage.",
        "indicators": ["dex_swap", "token_transfer"],
    },
    "self_destruct_exploit": {
        "description": "Uses SELFDESTRUCT to force-send ETH to a contract that cannot handle unexpected balance changes.",
        "indicators": ["self_destruct", "eth_transfer"],
    },
    "logic_bug": {
        "description": "Exploits an arithmetic overflow/underflow, incorrect state machine transition, or other logic error.",
        "indicators": ["storage_write", "token_transfer"],
    },
}


@dataclass
class Hypothesis:
    technique: str
    confidence: float
    reasoning: str
    supporting_actions: list[str] = field(default_factory=list)


@dataclass
class ClassificationResult:
    primary_hypothesis: Hypothesis
    alternative_hypotheses: list[Hypothesis] = field(default_factory=list)
    raw_llm_response: str = ""


class ExploitClassifier:
    """Uses the IR graph + LLM to classify the exploit technique."""

    def __init__(self, llm_client: LLMClient, techniques_config: dict[str, Any] | None = None):
        self._llm = llm_client
        self._techniques = techniques_config if techniques_config is not None else DEFAULT_TECHNIQUES

    def classify(self, ir_graph: IRGraph) -> ClassificationResult:
        """Analyze the IR graph and produce a ranked list of technique hypotheses."""
        prompt = self._build_classification_prompt(ir_graph)
        response = self._llm.complete(
            system_prompt=CLASSIFIER_SYSTEM_PROMPT,
            user_message=prompt,
            temperature=0.0,
            json_mode=True,
        )
        result = self._parse_classification_response(response.content)
        result.raw_llm_response = response.content
        return result

    def _build_classification_prompt(self, ir_graph: IRGraph) -> str:
        """Build the prompt that feeds the IR summary to the LLM."""
        lines: list[str] = [
            f"Transaction: {ir_graph.tx_hash}",
            f"Total semantic actions: {len(ir_graph.actions)}",
        ]

        # Action-type frequency summary — fast signal for the model
        type_counts: dict[str, int] = {}
        for action in ir_graph.actions:
            key = action.action_type.value
            type_counts[key] = type_counts.get(key, 0) + 1

        if type_counts:
            distribution = ", ".join(f"{k}={v}" for k, v in type_counts.items())
            lines.append(f"Action distribution: {distribution}")

        # Metadata from the IR graph (block number, gas, etc.)
        if ir_graph.metadata:
            meta_str = ", ".join(f"{k}={v}" for k, v in ir_graph.metadata.items())
            lines.append(f"Metadata: {meta_str}")

        # Ordered action list — omit high-volume noise types from the body;
        # they are already captured in the distribution summary above.
        _NOISE = {"storage_write", "storage_read", "unknown"}
        _MAX_ACTIONS = 80
        notable = [a for a in ir_graph.actions if a.action_type.value not in _NOISE]
        noise_count = len(ir_graph.actions) - len(notable)
        display = notable[:_MAX_ACTIONS]

        lines += ["", "## Action Sequence"]
        if noise_count:
            lines.append(
                f"  [+{noise_count} storage_read/write ops omitted — see distribution above]"
            )
        if len(notable) > _MAX_ACTIONS:
            lines.append(f"  [showing first {_MAX_ACTIONS} of {len(notable)} notable actions]")
        for i, action in enumerate(display):
            params_str = (
                ", ".join(f"{k}={v}" for k, v in action.params.items())
                if action.params
                else ""
            )
            addr_info = f"from={action.from_addr or '?'} to={action.to_addr or '?'}"
            depth_info = f"depth={action.depth}"
            detail = f" ({params_str})" if params_str else ""
            lines.append(
                f"  {i + 1:>3}. [{action.action_type.value}] {depth_info} {addr_info}{detail}"
            )

        # Control/data flow edges — only non-sequence edges carry semantic signal
        _MAX_EDGES = 60
        semantic_edges = [
            (f, t, l) for f, t, l in ir_graph.edges if l != "sequence"
        ]
        if semantic_edges:
            lines += ["", "## Semantic Edges (flash_loan_scope / amount_match / storage_dep)"]
            for from_id, to_id, label in semantic_edges[:_MAX_EDGES]:
                lines.append(f"  {from_id} --[{label}]--> {to_id}")

        # Techniques taxonomy for grounded classification
        if self._techniques:
            lines += ["", "## Known Technique Taxonomy (use these names when possible)"]
            for name, details in self._techniques.items():
                if isinstance(details, dict):
                    desc = details.get("description", "")
                    indicators = details.get("indicators", [])
                    lines.append(f"- {name}: {desc}")
                    if indicators:
                        lines.append(f"  Key indicators: {', '.join(indicators)}")
                else:
                    lines.append(f"- {name}: {details}")

        return "\n".join(lines)

    def _parse_classification_response(self, response: str) -> ClassificationResult:
        """Parse the LLM's structured JSON response into a ClassificationResult."""
        text = response
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]

        try:
            data: dict[str, Any] = json.loads(text.strip())
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"LLM returned non-JSON response: {response[:200]!r}"
            ) from exc

        required = {"primary_technique", "confidence", "reasoning"}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"LLM response missing required fields: {missing}")

        primary = Hypothesis(
            technique=data["primary_technique"],
            confidence=float(data["confidence"]),
            reasoning=data["reasoning"],
            supporting_actions=data.get("causal_chain", []),
        )

        alternatives = [
            Hypothesis(
                technique=alt["technique"],
                confidence=float(alt["confidence"]),
                reasoning=alt.get("reasoning", ""),
                supporting_actions=alt.get("causal_chain", []),
            )
            for alt in data.get("alternative_hypotheses", [])
        ]

        return ClassificationResult(
            primary_hypothesis=primary,
            alternative_hypotheses=alternatives,
        )
