"""Combines predicate checks, ablation results, and LLM analysis into a final verdict."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.agents.classifier import ClassificationResult
from src.verifier.causal import AblationOutcome, AblationResult
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

    # How strongly each ablation outcome supports the causal hypothesis.
    # REVERTED/NO_PROFIT: removing the factor broke the exploit → strong evidence.
    # REDUCED_PROFIT: factor contributed but wasn't sole cause.
    # UNCHANGED: factor was irrelevant → evidence against the hypothesis.
    # ERROR: unknown → neutral.
    _ABLATION_OUTCOME_SCORES: dict[AblationOutcome, float] = {
        AblationOutcome.REVERTED: 1.0,
        AblationOutcome.NO_PROFIT: 0.9,
        AblationOutcome.REDUCED_PROFIT: 0.6,
        AblationOutcome.UNCHANGED: 0.1,
        AblationOutcome.ERROR: 0.5,
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

        if ablations:
            ablation_score = sum(
                self._ABLATION_OUTCOME_SCORES.get(a.outcome, 0.5) for a in ablations
            ) / len(ablations)
        else:
            ablation_score = 0.5

        return 0.6 * predicate_score + 0.4 * ablation_score

    def _build_reasoning(
        self,
        classification: ClassificationResult,
        predicates: list[PredicateCheck],
        ablations: list[AblationResult],
        verdict: Verdict,
    ) -> str:
        """Generate human-readable reasoning for the verdict."""
        technique = classification.primary_hypothesis.technique
        llm_conf = classification.primary_hypothesis.confidence

        pass_count = sum(1 for p in predicates if p.result == PredicateResult.PASS)
        fail_count = sum(1 for p in predicates if p.result == PredicateResult.FAIL)
        skip_count = sum(1 for p in predicates if p.result == PredicateResult.SKIP)

        lines = [
            f"Verdict: {verdict.value} for technique '{technique}' (LLM confidence {llm_conf:.0%}).",
            f"Evaluated {len(predicates)} predicates: {pass_count} passed, {fail_count} failed, {skip_count} skipped.",
        ]

        if pass_count:
            names = [p.name for p in predicates if p.result == PredicateResult.PASS]
            lines.append(f"  Confirmed: {', '.join(names)}.")
        if fail_count:
            names = [p.name for p in predicates if p.result == PredicateResult.FAIL]
            lines.append(f"  Failed: {', '.join(names)}.")

        if ablations:
            summary = "; ".join(f"{a.factor_removed} -> {a.outcome.value}" for a in ablations)
            lines.append(f"Ran {len(ablations)} ablation test(s): {summary}.")
            causal = [a for a in ablations if a.outcome in (AblationOutcome.REVERTED, AblationOutcome.NO_PROFIT)]
            non_causal = [a for a in ablations if a.outcome == AblationOutcome.UNCHANGED]
            if causal:
                lines.append(f"  Causal factors confirmed: {', '.join(a.factor_removed for a in causal)}.")
            if non_causal:
                lines.append(f"  Non-causal factors: {', '.join(a.factor_removed for a in non_causal)}.")
        else:
            lines.append("No ablation tests were run.")

        if classification.alternative_hypotheses:
            alts = [h.technique for h in classification.alternative_hypotheses[:2]]
            lines.append(f"Alternative hypotheses considered: {', '.join(alts)}.")

        return "\n".join(lines)
