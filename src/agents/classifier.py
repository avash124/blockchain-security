"""Classifies exploit technique from the IR graph using LLM reasoning."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.ir.nodes import IRGraph
from src.llm.client import LLMClient


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
        self._techniques = techniques_config or {}

    def classify(self, ir_graph: IRGraph) -> ClassificationResult:
        """Analyze the IR graph and produce a ranked list of technique hypotheses."""
        # TODO:
        # 1. Summarize IR graph into a structured prompt
        # 2. Include techniques taxonomy for grounded classification
        # 3. Ask LLM to produce ranked hypotheses with confidence scores
        # 4. Parse structured output into ClassificationResult
        raise NotImplementedError

    def _build_classification_prompt(self, ir_graph: IRGraph) -> str:
        """Build the prompt that feeds the IR summary to the LLM."""
        # TODO: serialize IR graph actions + edges into a concise textual representation
        raise NotImplementedError

    def _parse_classification_response(self, response: str) -> ClassificationResult:
        """Parse the LLM's structured JSON response into a ClassificationResult."""
        # TODO: json.loads → ClassificationResult
        raise NotImplementedError
