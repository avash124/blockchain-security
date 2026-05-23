"""Combines predicate checks, ablation results, and LLM analysis into a final verdict."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.agents.classifier import ClassificationResult
from src.verifier.causal import AblationResult
from src.verifier.predicates import PredicateCheck, PredicateResult


class Verdict(Enum):
    VERIFIED = "VERIFIED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class VerdictReport:
    verdict: Verdict
    confidence: float
    technique: str
    reasoning: str
    predicate_results: list[PredicateCheck] = field(default_factory=list)
    ablation_results: list[AblationResult] = field(default_factory=list)
    classification: ClassificationResult | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "technique": self.technique,
            "reasoning": self.reasoning,
            "predicates": [
                {"name": p.name, "result": p.result.value, "details": p.details}
                for p in self.predicate_results
            ],
            "ablations": [
                {"factor": a.factor_removed, "outcome": a.outcome.value, "details": a.details}
                for a in self.ablation_results
            ],
        }


class VerdictEngine:
    """Produces the final VERIFIED/REFUTED/INCONCLUSIVE verdict."""

    CONFIDENCE_THRESHOLDS = {
        Verdict.VERIFIED: 0.8,
        Verdict.REFUTED: 0.2,
    }

    def evaluate(
        self,
        classification: ClassificationResult,
        predicate_results: list[PredicateCheck],
        ablation_results: list[AblationResult],
    ) -> VerdictReport:
        """Combine all evidence into a final verdict."""
        confidence = self._compute_confidence(predicate_results, ablation_results)

        if confidence >= self.CONFIDENCE_THRESHOLDS[Verdict.VERIFIED]:
            verdict = Verdict.VERIFIED
        elif confidence <= self.CONFIDENCE_THRESHOLDS[Verdict.REFUTED]:
            verdict = Verdict.REFUTED
        else:
            verdict = Verdict.INCONCLUSIVE

        reasoning = self._build_reasoning(
            classification, predicate_results, ablation_results, verdict
        )

        return VerdictReport(
            verdict=verdict,
            confidence=confidence,
            technique=classification.primary_hypothesis.technique,
            reasoning=reasoning,
            predicate_results=predicate_results,
            ablation_results=ablation_results,
            classification=classification,
        )

    def _compute_confidence(
        self,
        predicates: list[PredicateCheck],
        ablations: list[AblationResult],
    ) -> float:
        """Score confidence from 0.0 to 1.0 based on evidence."""
        if not predicates and not ablations:
            return 0.5

        passing = sum(1 for p in predicates if p.result == PredicateResult.PASS)
        total = sum(1 for p in predicates if p.result != PredicateResult.SKIP)

        predicate_score = passing / total if total > 0 else 0.5

        # TODO: factor in ablation results (each successful ablation adds confidence)
        ablation_score = 0.5  # placeholder

        return 0.6 * predicate_score + 0.4 * ablation_score

    def _build_reasoning(
        self,
        classification: ClassificationResult,
        predicates: list[PredicateCheck],
        ablations: list[AblationResult],
        verdict: Verdict,
    ) -> str:
        """Generate human-readable reasoning for the verdict."""
        # TODO: synthesize evidence into a clear explanation
        return f"Verdict {verdict.value} based on {len(predicates)} predicates and {len(ablations)} ablation tests."
