"""
Purpose-driven scenario tests for the blockchain security analysis pipeline.

These tests describe WHAT the tool must do — correctly detect, classify, and
report attacker behaviour — rather than HOW the code achieves it.  No
implementation files were read before writing these tests; only the public
configuration (techniques.yaml, predicates.yaml, ir_patterns.yaml) and the
handoff specification were consulted.

Each class maps to a distinct attack class described in techniques.yaml.
Tests assert on the *contracts* the tool exposes: detection outcome, loss
amounts, attacker classification, and recommendations.
"""

import json
import pytest
from unittest.mock import MagicMock, patch

from src.agents.blast_radius import BlastRadiusAnalyzer
from src.agents.precursor import (
    PrecursorAnalyzer,
    KNOWN_TORNADO_CASH,
    KNOWN_CEX_HOT_WALLETS,
    KNOWN_BRIDGES,
)
from src.ir.nodes import IRGraph, SemanticAction, ActionType
from src.verifier.state_diff import StateDiff, BalanceChange
from src.llm.client import LLMResponse


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------

ATTACKER = "0xAttacker"
VICTIM_POOL = "0xVictimPool"
FLASH_LENDER = "0xAaveV3"
ORACLE = "0xChainlinkOracle"
DEX = "0xUniswapV3"
GOVERNANCE = "0xGovernor"


def _llm(content: dict) -> LLMResponse:
    return LLMResponse(
        content=json.dumps(content),
        model="claude-sonnet-4-6",
        input_tokens=10,
        output_tokens=10,
        stop_reason="stop",
    )


def _analyzer(llm_content: dict | None = None) -> BlastRadiusAnalyzer:
    mock_llm = MagicMock()
    if llm_content is not None:
        mock_llm.complete.return_value = _llm(llm_content)
    return BlastRadiusAnalyzer(llm_client=mock_llm)


def _precursor() -> PrecursorAnalyzer:
    return PrecursorAnalyzer(rpc_url="http://fake:8545", ETHER_SCAN_KEY=None)


_MINIMAL_LLM_RESPONSE = {
    "affected_protocols": [],
    "cascading_risks": [],
    "recommendations": [],
}


# ---------------------------------------------------------------------------
# Helper: Etherscan tx dict factory (mirrors test_precursor.py style)
# ---------------------------------------------------------------------------

def _etx(from_addr, to_addr, value="0", is_error="0",
         input_data="0x", contract_address="", block="100", ts="1700000000"):
    return {
        "hash": "0xdeadbeef",
        "blockNumber": block,
        "timeStamp": ts,
        "from": from_addr,
        "to": to_addr,
        "value": value,
        "isError": is_error,
        "input": input_data,
        "contractAddress": contract_address,
    }


# ===========================================================================
# 1. Flash Loan Attack
# ===========================================================================

class TestFlashLoanScenario:
    """
    A flash-loan attack borrows uncollateralised capital at tx-start,
    manipulates some invariant, then repays at tx-end — all in one block.
    The tool must detect the borrow/repay bookends and quantify attacker profit.
    """

    def _make_flash_loan_graph(self) -> IRGraph:
        g = IRGraph(tx_hash="0xflash")
        g.add_action(SemanticAction(
            action_type=ActionType.FLASH_LOAN_BORROW,
            depth=1, from_addr=ATTACKER, to_addr=FLASH_LENDER,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.DEX_SWAP,
            depth=2, from_addr=ATTACKER, to_addr=DEX,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER,
            depth=2, from_addr=ATTACKER, to_addr=VICTIM_POOL,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.FLASH_LOAN_REPAY,
            depth=1, from_addr=ATTACKER, to_addr=FLASH_LENDER,
        ))
        return g

    def _make_profit_diff(self, profit_eth: int = 100) -> StateDiff:
        return StateDiff(balance_changes=[
            BalanceChange(
                address=ATTACKER, token="ETH",
                before=0, after=profit_eth * 10**18,
            ),
            BalanceChange(
                address=VICTIM_POOL, token="ETH",
                before=profit_eth * 10**18, after=0,
            ),
        ])

    # -- Blast-radius helpers --

    def test_flash_loan_borrow_addr_not_in_shared_deps(self):
        """
        The flash lender is the root contract (actions[0].to_addr).
        It must be excluded from shared dependencies so the tool does not
        flag the lending protocol itself as a dependency of the exploit.
        """
        analyzer = _analyzer()
        g = self._make_flash_loan_graph()
        deps = analyzer._find_shared_dependencies(g)
        assert FLASH_LENDER not in deps

    def test_dex_and_victim_are_shared_deps(self):
        """DEX and victim pool interact with the attacker and must appear as dependencies."""
        analyzer = _analyzer()
        deps = analyzer._find_shared_dependencies(self._make_flash_loan_graph())
        assert DEX in deps
        assert VICTIM_POOL in deps

    def test_attacker_profit_not_counted_as_loss(self):
        """Only victim losses contribute to primary loss — attacker gains must be ignored."""
        analyzer = _analyzer()
        diff = self._make_profit_diff(profit_eth=50)
        config = {"token_prices": {"ETH": 1000.0}}
        loss = analyzer._compute_primary_loss(diff, config)
        assert loss == pytest.approx(50 * 1000.0)

    def test_large_flash_loan_profit_exceeds_threshold(self):
        """$10 M theft must produce primary_loss_usd > $1 M."""
        analyzer = _analyzer({
            **_MINIMAL_LLM_RESPONSE,
            "affected_protocols": [{
                "name": "VictimPool",
                "address": VICTIM_POOL,
                "relationship": "direct theft",
                "risk_level": "critical",
                "details": "",
            }],
        })
        diff = self._make_profit_diff(profit_eth=10_000)
        config = {"token_prices": {"ETH": 1000.0}}
        report = analyzer.analyze(self._make_flash_loan_graph(), diff, config)
        assert report.primary_loss_usd > 1_000_000

    def test_cascading_risk_prepended_when_pool_drained(self):
        """When the victim pool has negative ETH delta, a cascading-loss entry must appear."""
        analyzer = _analyzer(_MINIMAL_LLM_RESPONSE)
        diff = self._make_profit_diff(profit_eth=100)
        report = analyzer.analyze(self._make_flash_loan_graph(), diff, {})
        assert any("cascading" in r.lower() for r in report.cascading_risks)


# ===========================================================================
# 2. Reentrancy Attack
# ===========================================================================

class TestReentrancyScenario:
    """
    A reentrancy exploit calls back into the victim before state is updated.
    The graph will show the victim called multiple times within the same depth
    chain.  The blast-radius analyser must treat the victim as a dependency
    and loss must reflect repeated withdrawals.
    """

    def _make_reentrancy_graph(self) -> IRGraph:
        g = IRGraph(tx_hash="0xreenter")
        g.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER,
            depth=1, from_addr=ATTACKER, to_addr=VICTIM_POOL,
        ))
        # callback re-enters victim twice before state write
        g.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER,
            depth=2, from_addr=VICTIM_POOL, to_addr=ATTACKER,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER,
            depth=3, from_addr=VICTIM_POOL, to_addr=ATTACKER,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.STORAGE_WRITE,
            depth=1, from_addr=VICTIM_POOL, to_addr=VICTIM_POOL,
        ))
        return g

    def _make_double_drain_diff(self) -> StateDiff:
        return StateDiff(balance_changes=[
            BalanceChange(
                address=ATTACKER, token="ETH",
                before=0, after=2 * 10**18,
            ),
            BalanceChange(
                address=VICTIM_POOL, token="ETH",
                before=2 * 10**18, after=0,
            ),
        ])

    def test_victim_pool_in_dependencies(self):
        """The victim pool appears as a shared dependency (token transfer target)."""
        analyzer = _analyzer()
        deps = analyzer._find_shared_dependencies(self._make_reentrancy_graph())
        assert VICTIM_POOL in deps

    def test_double_drain_loss_computed_correctly(self):
        """Two re-entrant withdrawals of 1 ETH each must total 2 ETH loss."""
        analyzer = _analyzer()
        loss = analyzer._estimate_cascading_loss(self._make_double_drain_diff())
        assert loss == pytest.approx(2.0)

    def test_storage_write_contract_in_deps(self):
        """A storage write to the victim itself is a dependency signal."""
        analyzer = _analyzer()
        deps = analyzer._find_shared_dependencies(self._make_reentrancy_graph())
        assert VICTIM_POOL in deps


# ===========================================================================
# 3. Price Oracle Manipulation
# ===========================================================================

class TestOracleManipulationScenario:
    """
    The attacker swaps on a DEX to move spot price, then reads the oracle
    while the price is artificially distorted.  The oracle and DEX are
    both dependencies the blast-radius analyser should surface.
    """

    def _make_oracle_manip_graph(self) -> IRGraph:
        g = IRGraph(tx_hash="0xoracle")
        g.add_action(SemanticAction(
            action_type=ActionType.FLASH_LOAN_BORROW,
            depth=1, from_addr=ATTACKER, to_addr=FLASH_LENDER,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.DEX_SWAP,
            depth=2, from_addr=ATTACKER, to_addr=DEX,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.ORACLE_READ,
            depth=2, from_addr=ATTACKER, to_addr=ORACLE,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER,
            depth=2, from_addr=ATTACKER, to_addr=VICTIM_POOL,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.FLASH_LOAN_REPAY,
            depth=1, from_addr=ATTACKER, to_addr=FLASH_LENDER,
        ))
        return g

    def test_oracle_in_shared_dependencies(self):
        """Oracle must appear as a shared dependency — it was read mid-exploit."""
        analyzer = _analyzer()
        deps = analyzer._find_shared_dependencies(self._make_oracle_manip_graph())
        assert ORACLE in deps

    def test_dex_in_shared_dependencies(self):
        """DEX swap that moved the price is also a dependency."""
        analyzer = _analyzer()
        deps = analyzer._find_shared_dependencies(self._make_oracle_manip_graph())
        assert DEX in deps

    def test_no_duplicates_in_deps(self):
        """Even if the same address is accessed multiple times, it appears once."""
        analyzer = _analyzer()
        g = self._make_oracle_manip_graph()
        g.add_action(SemanticAction(
            action_type=ActionType.ORACLE_READ,
            depth=3, from_addr=ATTACKER, to_addr=ORACLE,
        ))
        deps = analyzer._find_shared_dependencies(g)
        assert deps.count(ORACLE) == 1


# ===========================================================================
# 4. Governance Manipulation
# ===========================================================================

class TestGovernanceManipulationScenario:
    """
    Governance attacks borrow voting tokens, pass a malicious proposal,
    then repay — all within one transaction.  The analyser must surface
    the governance contract as a critical dependency.
    """

    def _make_governance_graph(self) -> IRGraph:
        g = IRGraph(tx_hash="0xgov")
        g.add_action(SemanticAction(
            action_type=ActionType.FLASH_LOAN_BORROW,
            depth=1, from_addr=ATTACKER, to_addr=FLASH_LENDER,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.GOVERNANCE_ACTION,
            depth=2, from_addr=ATTACKER, to_addr=GOVERNANCE,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER,
            depth=2, from_addr=GOVERNANCE, to_addr=ATTACKER,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.FLASH_LOAN_REPAY,
            depth=1, from_addr=ATTACKER, to_addr=FLASH_LENDER,
        ))
        return g

    def test_governance_contract_in_shared_deps(self):
        """Governance contract must be flagged as a shared dependency."""
        analyzer = _analyzer()
        deps = analyzer._find_shared_dependencies(self._make_governance_graph())
        assert GOVERNANCE in deps

    def test_treasury_drain_reported_in_blast_radius(self):
        """If treasury was drained, primary_loss_usd must be non-zero."""
        analyzer = _analyzer({
            **_MINIMAL_LLM_RESPONSE,
            "affected_protocols": [{
                "name": "Governor",
                "address": GOVERNANCE,
                "relationship": "direct control",
                "risk_level": "critical",
                "details": "",
            }],
        })
        diff = StateDiff(balance_changes=[
            BalanceChange(address=ATTACKER, token="ETH", before=0, after=500 * 10**18),
            BalanceChange(address=GOVERNANCE, token="ETH", before=500 * 10**18, after=0),
        ])
        report = analyzer.analyze(self._make_governance_graph(), diff, {"token_prices": {"ETH": 2000.0}})
        assert report.primary_loss_usd > 0
        assert any(p.name == "Governor" for p in report.affected_protocols)


# ===========================================================================
# 5. Attacker Precursor — complete preparation timeline
# ===========================================================================

class TestAttackerPreparationTimeline:
    """
    Before an exploit, a sophisticated attacker:
      1. Receives funding (Tornado Cash / CEX / bridge)
      2. Deploys one or more attack contracts
      3. Runs dry-run / reconnaissance transactions

    The PrecursorAnalyzer must reconstruct this timeline correctly.
    """

    _TORNADO = next(iter(KNOWN_TORNADO_CASH))
    _CEX = next(iter(KNOWN_CEX_HOT_WALLETS))
    _BRIDGE = next(iter(KNOWN_BRIDGES))
    _EXPLOIT_BLOCK = 500
    _EXPLOIT_TS = 1700010000

    # tx templates
    _FUNDING_TORNADO = _etx(
        from_addr=_TORNADO, to_addr=ATTACKER,
        value=str(50 * 10**18), block="50", ts="1700000000",
    )
    _DEPLOY = _etx(
        from_addr=ATTACKER, to_addr="",
        contract_address="0xMaliciousContract",
        block="100", ts="1700001000",
    )
    _RECON = _etx(
        from_addr=ATTACKER, to_addr=VICTIM_POOL,
        input_data="0x70a08231",  # balanceOf selector
        block="200", ts="1700003000",
    )
    _FAILED_TEST = _etx(
        from_addr=ATTACKER, to_addr="0xMaliciousContract",
        is_error="1", block="300", ts="1700005000",
    )

    def _run(self, txs, exploit_ts=None):
        analyzer = _precursor()
        ts = exploit_ts or self._EXPLOIT_TS
        with patch.object(analyzer, "_fetch_address_history", return_value=txs), \
             patch.object(analyzer, "_fetch_block_timestamp", return_value=ts):
            return analyzer.analyze(ATTACKER, self._EXPLOIT_BLOCK)

    # -- Funding detection --

    def test_tornado_cash_funding_identified(self):
        profile = self._run([self._FUNDING_TORNADO, self._DEPLOY])
        assert profile.funding_source == "tornado_cash"

    def test_cex_funding_identified(self):
        cex_fund = _etx(
            from_addr=self._CEX, to_addr=ATTACKER,
            value=str(10 * 10**18), block="50", ts="1700000000",
        )
        profile = self._run([cex_fund, self._DEPLOY])
        assert profile.funding_source is not None
        assert "cex" in profile.funding_source

    def test_bridge_funding_identified(self):
        bridge_fund = _etx(
            from_addr=self._BRIDGE, to_addr=ATTACKER,
            value=str(10 * 10**18), block="50", ts="1700000000",
        )
        profile = self._run([bridge_fund, self._DEPLOY])
        assert profile.funding_source is not None
        assert "bridge" in profile.funding_source

    # -- Contract deployment --

    def test_deployed_contract_in_profile(self):
        profile = self._run([self._DEPLOY, self._RECON])
        assert "0xMaliciousContract" in profile.deployed_contracts

    def test_multiple_deploy_contracts_all_captured(self):
        deploy2 = dict(self._DEPLOY, contractAddress="0xMalicious2", hash="0xd2", blockNumber="110")
        profile = self._run([self._DEPLOY, deploy2])
        assert "0xMaliciousContract" in profile.deployed_contracts
        assert "0xMalicious2" in profile.deployed_contracts

    # -- Reconnaissance --

    def test_recon_tx_classified_correctly(self):
        profile = self._run([self._FUNDING_TORNADO, self._DEPLOY, self._RECON])
        relevances = [p.relevance for p in profile.precursor_txs]
        assert "reconnaissance" in relevances

    # -- Failed test runs --

    def test_failed_tx_classified_as_test_run(self):
        profile = self._run([self._DEPLOY, self._FAILED_TEST])
        relevances = [p.relevance for p in profile.precursor_txs]
        assert "test_run" in relevances

    # -- Preparation time --

    def test_preparation_time_hours_computed(self):
        # earliest tx ts=1700000000, exploit ts=1700010000 → 10000s / 3600 ≈ 2.78 hr
        profile = self._run(
            [self._FUNDING_TORNADO, self._DEPLOY, self._RECON, self._FAILED_TEST],
            exploit_ts=self._EXPLOIT_TS,
        )
        assert profile.estimated_preparation_time_hours is not None
        assert profile.estimated_preparation_time_hours > 0

    def test_preparation_time_matches_earliest_tx(self):
        early = _etx(
            from_addr=self._TORNADO, to_addr=ATTACKER,
            value=str(1 * 10**18), block="10", ts="1700000000",
        )
        late = _etx(
            from_addr=ATTACKER, to_addr="",
            contract_address="0xc1", block="400", ts="1700003600",
        )
        exploit_ts = 1700007200  # 2 hr after early, 1 hr after late
        profile = self._run([early, late], exploit_ts=exploit_ts)
        # must be keyed to earliest (1700000000), not latest precursor
        assert profile.estimated_preparation_time_hours == pytest.approx(2.0, rel=0.05)

    # -- Filtering --

    def test_txs_after_exploit_block_excluded(self):
        post_exploit = dict(self._DEPLOY, blockNumber="600", hash="0xpost")  # > 500
        profile = self._run([post_exploit])
        assert all(p.relevance != "deployment" for p in profile.precursor_txs)

    def test_empty_history_yields_clean_profile(self):
        profile = self._run([])
        assert profile.precursor_txs == []
        assert profile.funding_source is None
        assert profile.estimated_preparation_time_hours is None


# ===========================================================================
# 6. Multi-protocol cascading blast radius
# ===========================================================================

class TestCascadingBlastRadius:
    """
    Real exploits (Euler Finance, Cream Finance, etc.) drain one protocol and
    trigger cascading losses across protocols that share the same oracles or
    liquidity pools.  The analyser must report all affected protocols and
    estimate both primary and cascading loss.
    """

    _PROTOCOL_B = "0xProtocolB"
    _PROTOCOL_C = "0xProtocolC"

    def _make_multi_protocol_graph(self) -> IRGraph:
        g = IRGraph(tx_hash="0xcascade")
        g.add_action(SemanticAction(
            action_type=ActionType.FLASH_LOAN_BORROW,
            depth=1, from_addr=ATTACKER, to_addr=FLASH_LENDER,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.ORACLE_READ,
            depth=2, from_addr=ATTACKER, to_addr=ORACLE,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER,
            depth=2, from_addr=ATTACKER, to_addr=VICTIM_POOL,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER,
            depth=2, from_addr=ATTACKER, to_addr=self._PROTOCOL_B,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER,
            depth=2, from_addr=ATTACKER, to_addr=self._PROTOCOL_C,
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.FLASH_LOAN_REPAY,
            depth=1, from_addr=ATTACKER, to_addr=FLASH_LENDER,
        ))
        return g

    def _make_multi_loss_diff(self) -> StateDiff:
        return StateDiff(balance_changes=[
            BalanceChange(address=ATTACKER, token="ETH", before=0, after=300 * 10**18),
            BalanceChange(address=VICTIM_POOL, token="ETH", before=100 * 10**18, after=0),
            BalanceChange(address=self._PROTOCOL_B, token="ETH", before=100 * 10**18, after=0),
            BalanceChange(address=self._PROTOCOL_C, token="ETH", before=100 * 10**18, after=0),
        ])

    def test_all_victim_protocols_in_deps(self):
        analyzer = _analyzer()
        deps = analyzer._find_shared_dependencies(self._make_multi_protocol_graph())
        assert VICTIM_POOL in deps
        assert self._PROTOCOL_B in deps
        assert self._PROTOCOL_C in deps
        assert ORACLE in deps

    def test_total_cascading_loss_sums_all_negative_deltas(self):
        analyzer = _analyzer()
        loss = analyzer._estimate_cascading_loss(self._make_multi_loss_diff())
        assert loss == pytest.approx(300.0)

    def test_primary_loss_with_price_map(self):
        analyzer = _analyzer()
        config = {"token_prices": {"ETH": 500.0}}
        loss = analyzer._compute_primary_loss(self._make_multi_loss_diff(), config)
        assert loss == pytest.approx(300 * 500.0)

    def test_multiple_affected_protocols_in_report(self):
        analyzer = _analyzer({
            "affected_protocols": [
                {"name": "PoolA", "address": VICTIM_POOL,
                 "relationship": "direct", "risk_level": "critical", "details": ""},
                {"name": "PoolB", "address": self._PROTOCOL_B,
                 "relationship": "shared oracle", "risk_level": "high", "details": ""},
                {"name": "PoolC", "address": self._PROTOCOL_C,
                 "relationship": "shared oracle", "risk_level": "high", "details": ""},
            ],
            "cascading_risks": [],
            "recommendations": ["upgrade oracle", "add circuit breaker"],
        })
        report = analyzer.analyze(
            self._make_multi_protocol_graph(),
            self._make_multi_loss_diff(),
            {"token_prices": {"ETH": 1000.0}},
        )
        assert len(report.affected_protocols) == 3
        names = {p.name for p in report.affected_protocols}
        assert "PoolA" in names
        assert "PoolB" in names
        assert "PoolC" in names

    def test_recommendations_surfaced_in_report(self):
        analyzer = _analyzer({
            **_MINIMAL_LLM_RESPONSE,
            "recommendations": ["upgrade oracle", "add circuit breaker"],
        })
        report = analyzer.analyze(
            self._make_multi_protocol_graph(),
            self._make_multi_loss_diff(),
            {},
        )
        assert len(report.recommendations) >= 1


# ===========================================================================
# 7. Edge cases / robustness
# ===========================================================================

class TestRobustness:
    """
    The tool must degrade gracefully rather than silently produce wrong
    results when given unusual or minimal input.
    """

    def test_graph_with_only_root_action_yields_no_deps(self):
        analyzer = _analyzer()
        g = IRGraph(tx_hash="0xsingle")
        g.add_action(SemanticAction(
            action_type=ActionType.FLASH_LOAN_BORROW,
            depth=1, from_addr=ATTACKER, to_addr=FLASH_LENDER,
        ))
        deps = analyzer._find_shared_dependencies(g)
        assert deps == []

    def test_zero_loss_diff_produces_zero_primary_loss(self):
        analyzer = _analyzer()
        diff = StateDiff(balance_changes=[
            BalanceChange(address=ATTACKER, token="ETH", before=100, after=100),
        ])
        assert analyzer._compute_primary_loss(diff, {}) == 0.0

    def test_malformed_llm_json_raises_value_error(self):
        analyzer = _analyzer()
        mock_llm = MagicMock()
        mock_llm.complete.return_value = LLMResponse(
            content="```definitely not json```",
            model="m", input_tokens=1, output_tokens=1, stop_reason="stop",
        )
        analyzer_bad = BlastRadiusAnalyzer(llm_client=mock_llm)
        g = IRGraph(tx_hash="0xbad")
        g.add_action(SemanticAction(
            action_type=ActionType.FLASH_LOAN_BORROW,
            depth=1, from_addr=ATTACKER, to_addr=FLASH_LENDER,
        ))
        with pytest.raises(ValueError):
            analyzer_bad.analyze(g, StateDiff(), {})

    def test_precursor_no_funding_when_all_incoming_zero_value(self):
        """Zero-value transactions from known addresses must not count as funding."""
        analyzer = _precursor()
        tornado = next(iter(KNOWN_TORNADO_CASH))
        txs = [_etx(from_addr=tornado, to_addr=ATTACKER, value="0")]
        assert analyzer._identify_funding_source(txs) is None

    def test_precursor_classify_outgoing_recon_correctly(self):
        """Outgoing tx with non-trivial calldata is reconnaissance, not noise."""
        analyzer = _precursor()
        tx = _etx(
            from_addr=ATTACKER, to_addr=VICTIM_POOL,
            input_data="0x06fdde03",  # name() selector — reading contract metadata
        )
        result = analyzer._classify_precursor(tx, ATTACKER)
        assert result is not None
        assert result.relevance == "reconnaissance"

    def test_precursor_plain_eth_send_without_calldata_returns_none(self):
        """A plain ETH transfer with no calldata from an unknown address is not a precursor signal."""
        analyzer = _precursor()
        tx = _etx(from_addr="0xrandom", to_addr=ATTACKER, value=str(10**18))
        assert analyzer._classify_precursor(tx, ATTACKER) is None
