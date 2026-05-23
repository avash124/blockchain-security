"""Unit tests for VerdictEngine — confidence scoring and verdict emission."""

import pytest

from src.agents.classifier import ClassificationResult, Hypothesis
from src.verifier.causal import AblationResult, AblationOutcome
from src.verifier.predicates import PredicateCheck, PredicateResult
from src.verifier.verdict import Verdict, VerdictEngine, VerdictReport


def _classification(technique: str = "flash_loan_attack", confidence: float = 0.9) -> ClassificationResult:
    return ClassificationResult(
        primary_hypothesis=Hypothesis(
            technique=technique, confidence=confidence, reasoning="test",
        ),
    )


def _pred(name: str, result: PredicateResult) -> PredicateCheck:
    return PredicateCheck(name=name, result=result, details=f"{name} {result.value}")


def _ablation(factor: str, outcome: AblationOutcome) -> AblationResult:
    return AblationResult(factor_removed=factor, outcome=outcome)


# ------------------------------------------------------------------
# Confidence scoring
# ------------------------------------------------------------------

class TestConfidenceScoring:
    def test_all_pass_predicates(self):
        engine = VerdictEngine()
        preds = [_pred("a", PredicateResult.PASS), _pred("b", PredicateResult.PASS)]
        score = engine._compute_confidence(preds, [])
        # predicate_score=1.0, ablation_score=0.5 → 0.6*1.0 + 0.4*0.5 = 0.8
        assert score == pytest.approx(0.8)

    def test_all_fail_predicates(self):
        engine = VerdictEngine()
        preds = [_pred("a", PredicateResult.FAIL), _pred("b", PredicateResult.FAIL)]
        score = engine._compute_confidence(preds, [])
        # predicate_score=0.0 → 0.6*0.0 + 0.4*0.5 = 0.2
        assert score == pytest.approx(0.2)

    def test_mixed_predicates(self):
        engine = VerdictEngine()
        preds = [
            _pred("a", PredicateResult.PASS),
            _pred("b", PredicateResult.FAIL),
        ]
        score = engine._compute_confidence(preds, [])
        # predicate_score=0.5 → 0.6*0.5 + 0.4*0.5 = 0.5
        assert score == pytest.approx(0.5)

    def test_skip_predicates_excluded_from_scoring(self):
        engine = VerdictEngine()
        preds = [
            _pred("a", PredicateResult.PASS),
            _pred("b", PredicateResult.SKIP),
            _pred("c", PredicateResult.SKIP),
        ]
        score = engine._compute_confidence(preds, [])
        # only 1 non-SKIP, 1 PASS → predicate_score=1.0
        assert score == pytest.approx(0.8)

    def test_all_skip_predicates(self):
        engine = VerdictEngine()
        preds = [_pred("a", PredicateResult.SKIP)]
        score = engine._compute_confidence(preds, [])
        # total=0, predicate_score=0.5 (fallback) → 0.6*0.5 + 0.4*0.5 = 0.5
        assert score == pytest.approx(0.5)

    def test_no_evidence_at_all(self):
        engine = VerdictEngine()
        score = engine._compute_confidence([], [])
        assert score == 0.5

    def test_one_pass_one_fail_one_skip(self):
        engine = VerdictEngine()
        preds = [
            _pred("a", PredicateResult.PASS),
            _pred("b", PredicateResult.FAIL),
            _pred("c", PredicateResult.SKIP),
        ]
        score = engine._compute_confidence(preds, [])
        # 1 PASS / 2 non-SKIP = 0.5 → 0.6*0.5 + 0.4*0.5 = 0.5
        assert score == pytest.approx(0.5)


# ------------------------------------------------------------------
# Verdict thresholds
# ------------------------------------------------------------------

class TestVerdictThresholds:
    def test_verified_when_all_pass(self):
        engine = VerdictEngine()
        preds = [_pred("a", PredicateResult.PASS), _pred("b", PredicateResult.PASS)]
        report = engine.evaluate(_classification(), preds, [])
        assert report.verdict == Verdict.VERIFIED
        assert report.confidence >= 0.8

    def test_refuted_when_all_fail(self):
        engine = VerdictEngine()
        preds = [_pred("a", PredicateResult.FAIL), _pred("b", PredicateResult.FAIL)]
        report = engine.evaluate(_classification(), preds, [])
        assert report.verdict == Verdict.REFUTED
        assert report.confidence <= 0.2

    def test_inconclusive_when_mixed(self):
        engine = VerdictEngine()
        preds = [_pred("a", PredicateResult.PASS), _pred("b", PredicateResult.FAIL)]
        report = engine.evaluate(_classification(), preds, [])
        assert report.verdict == Verdict.INCONCLUSIVE
        assert 0.2 < report.confidence < 0.8

    def test_inconclusive_when_no_evidence(self):
        engine = VerdictEngine()
        report = engine.evaluate(_classification(), [], [])
        assert report.verdict == Verdict.INCONCLUSIVE
        assert report.confidence == 0.5

    def test_verified_boundary_exactly_0_8(self):
        engine = VerdictEngine()
        preds = [_pred("a", PredicateResult.PASS)]
        report = engine.evaluate(_classification(), preds, [])
        assert report.confidence == pytest.approx(0.8)
        assert report.verdict == Verdict.VERIFIED

    def test_refuted_boundary_exactly_0_2(self):
        engine = VerdictEngine()
        preds = [_pred("a", PredicateResult.FAIL)]
        report = engine.evaluate(_classification(), preds, [])
        assert report.confidence == pytest.approx(0.2)
        assert report.verdict == Verdict.REFUTED


# ------------------------------------------------------------------
# VerdictReport fields
# ------------------------------------------------------------------

class TestVerdictReport:
    def test_technique_from_classification(self):
        engine = VerdictEngine()
        report = engine.evaluate(_classification(technique="reentrancy"), [], [])
        assert report.technique == "reentrancy"

    def test_predicate_results_preserved(self):
        engine = VerdictEngine()
        preds = [_pred("balance_increased", PredicateResult.PASS)]
        report = engine.evaluate(_classification(), preds, [])
        assert len(report.predicate_results) == 1
        assert report.predicate_results[0].name == "balance_increased"

    def test_ablation_results_preserved(self):
        engine = VerdictEngine()
        ablations = [_ablation("flash_loan", AblationOutcome.REVERTED)]
        report = engine.evaluate(_classification(), [], ablations)
        assert len(report.ablation_results) == 1
        assert report.ablation_results[0].factor_removed == "flash_loan"

    def test_classification_preserved(self):
        engine = VerdictEngine()
        cls = _classification(technique="delegate_call_exploit")
        report = engine.evaluate(cls, [], [])
        assert report.classification is cls

    def test_reasoning_includes_counts(self):
        engine = VerdictEngine()
        preds = [_pred("a", PredicateResult.PASS), _pred("b", PredicateResult.FAIL)]
        ablations = [_ablation("x", AblationOutcome.REVERTED)]
        report = engine.evaluate(_classification(), preds, ablations)
        assert "2 predicates" in report.reasoning
        assert "1 ablation" in report.reasoning


# ------------------------------------------------------------------
# VerdictReport.to_dict
# ------------------------------------------------------------------

class TestVerdictReportToDict:
    def test_basic_structure(self):
        report = VerdictReport(
            verdict=Verdict.VERIFIED,
            confidence=0.85,
            technique="flash_loan_attack",
            reasoning="All checks passed.",
            predicate_results=[_pred("balance_increased", PredicateResult.PASS)],
            ablation_results=[_ablation("flash_loan", AblationOutcome.REVERTED)],
        )
        d = report.to_dict()
        assert d["verdict"] == "VERIFIED"
        assert d["confidence"] == 0.85
        assert d["technique"] == "flash_loan_attack"
        assert d["reasoning"] == "All checks passed."
        assert len(d["predicates"]) == 1
        assert d["predicates"][0]["name"] == "balance_increased"
        assert d["predicates"][0]["result"] == "PASS"
        assert len(d["ablations"]) == 1
        assert d["ablations"][0]["factor"] == "flash_loan"
        assert d["ablations"][0]["outcome"] == "REVERTED"

    def test_empty_results(self):
        report = VerdictReport(
            verdict=Verdict.INCONCLUSIVE,
            confidence=0.5,
            technique="unknown",
            reasoning="No evidence.",
        )
        d = report.to_dict()
        assert d["predicates"] == []
        assert d["ablations"] == []
