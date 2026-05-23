"""Unit tests for CausalVerifier and AblationResult dataclasses."""

import pytest
from unittest.mock import MagicMock

from src.acquisition.fork_manager import ForkManager
from src.verifier.causal import AblationOutcome, AblationResult, CausalVerifier


# ------------------------------------------------------------------
# AblationResult dataclass
# ------------------------------------------------------------------

class TestAblationResult:
    def test_basic_construction(self):
        r = AblationResult(
            factor_removed="flash_loan",
            outcome=AblationOutcome.REVERTED,
            details="Tx reverted without flash loan",
            profit_delta=-1000.0,
        )
        assert r.factor_removed == "flash_loan"
        assert r.outcome == AblationOutcome.REVERTED
        assert r.details == "Tx reverted without flash loan"
        assert r.profit_delta == -1000.0

    def test_defaults(self):
        r = AblationResult(factor_removed="x", outcome=AblationOutcome.ERROR)
        assert r.details == ""
        assert r.profit_delta is None

    def test_all_outcome_values(self):
        expected = {"REVERTED", "NO_PROFIT", "REDUCED_PROFIT", "UNCHANGED", "ERROR"}
        actual = {o.value for o in AblationOutcome}
        assert actual == expected


# ------------------------------------------------------------------
# AblationOutcome enum
# ------------------------------------------------------------------

class TestAblationOutcome:
    def test_reverted(self):
        assert AblationOutcome.REVERTED.value == "REVERTED"

    def test_no_profit(self):
        assert AblationOutcome.NO_PROFIT.value == "NO_PROFIT"

    def test_reduced_profit(self):
        assert AblationOutcome.REDUCED_PROFIT.value == "REDUCED_PROFIT"

    def test_unchanged(self):
        assert AblationOutcome.UNCHANGED.value == "UNCHANGED"

    def test_error(self):
        assert AblationOutcome.ERROR.value == "ERROR"


# ------------------------------------------------------------------
# CausalVerifier.run_ablation
# ------------------------------------------------------------------

class TestCausalVerifierRunAblation:
    def test_empty_factors_returns_empty(self):
        fm = MagicMock(spec=ForkManager)
        verifier = CausalVerifier(fork_manager=fm, rpc_url="http://fake:8545")
        results = verifier.run_ablation("0xdeadbeef", 12345, [])
        assert results == []

    def test_calls_test_without_factor_per_factor(self):
        fm = MagicMock(spec=ForkManager)
        verifier = CausalVerifier(fork_manager=fm, rpc_url="http://fake:8545")

        factors = [
            {"type": "flash_loan", "action_id": "flash_loan_borrow_0"},
            {"type": "dex_swap", "action_id": "dex_swap_5"},
        ]
        with pytest.raises(NotImplementedError):
            verifier.run_ablation("0xdeadbeef", 12345, factors)

    def test_test_without_factor_is_stub(self):
        fm = MagicMock(spec=ForkManager)
        verifier = CausalVerifier(fork_manager=fm, rpc_url="http://fake:8545")
        with pytest.raises(NotImplementedError):
            verifier._test_without_factor("0xdeadbeef", 12345, {"type": "flash_loan"})

    def test_apply_counterfactual_is_stub(self):
        fm = MagicMock(spec=ForkManager)
        verifier = CausalVerifier(fork_manager=fm, rpc_url="http://fake:8545")
        with pytest.raises(NotImplementedError):
            verifier._apply_counterfactual({"type": "flash_loan"}, "http://fake:8545")
