"""Unit tests for PrecursorAnalyzer."""

import pytest
from unittest.mock import patch

from src.agents.precursor import (
    PrecursorAnalyzer,
    KNOWN_TORNADO_CASH,
    KNOWN_CEX_HOT_WALLETS,
    KNOWN_BRIDGES,
)


# ------------------------------------------------------------------
# Shared fixtures / constants
# ------------------------------------------------------------------

ATTACKER = "0xattacker"

_TORNADO_ADDR = next(iter(KNOWN_TORNADO_CASH))
_CEX_ADDR = next(iter(KNOWN_CEX_HOT_WALLETS))
_BRIDGE_ADDR = next(iter(KNOWN_BRIDGES))


def make_etherscan_tx(
    from_addr, to_addr, value="0", is_error="0",
    input_data="0x", contract_address=""
):
    return {
        "hash": "0xabc",
        "blockNumber": "100",
        "timeStamp": "1700000000",
        "from": from_addr,
        "to": to_addr,
        "value": value,
        "isError": is_error,
        "input": input_data,
        "contractAddress": contract_address,
    }


def make_analyzer() -> PrecursorAnalyzer:
    return PrecursorAnalyzer(rpc_url="http://fake:8545", ETHER_SCAN_KEY=None)


# ------------------------------------------------------------------
# _classify_precursor — no network, tests each branch directly
# ------------------------------------------------------------------

class TestClassifyPrecursor:
    def setup_method(self):
        self.analyzer = make_analyzer()

    def test_deployment(self):
        tx = make_etherscan_tx(
            from_addr=ATTACKER, to_addr="", contract_address="0xcontract"
        )
        result = self.analyzer._classify_precursor(tx, ATTACKER)
        assert result is not None
        assert result.relevance == "deployment"
        assert "0xcontract" in result.description

    def test_test_run(self):
        tx = make_etherscan_tx(
            from_addr=ATTACKER, to_addr="0xtarget", is_error="1"
        )
        result = self.analyzer._classify_precursor(tx, ATTACKER)
        assert result is not None
        assert result.relevance == "test_run"

    def test_funding_from_tornado_cash(self):
        tx = make_etherscan_tx(
            from_addr=_TORNADO_ADDR, to_addr=ATTACKER, value=str(int(1e18))
        )
        result = self.analyzer._classify_precursor(tx, ATTACKER)
        assert result is not None
        assert result.relevance == "funding"
        assert "tornado_cash" in result.description

    def test_funding_from_cex(self):
        tx = make_etherscan_tx(
            from_addr=_CEX_ADDR, to_addr=ATTACKER, value=str(int(1e18))
        )
        result = self.analyzer._classify_precursor(tx, ATTACKER)
        assert result is not None
        assert result.relevance == "funding"
        assert "cex" in result.description

    def test_funding_from_bridge(self):
        tx = make_etherscan_tx(
            from_addr=_BRIDGE_ADDR, to_addr=ATTACKER, value=str(int(1e18))
        )
        result = self.analyzer._classify_precursor(tx, ATTACKER)
        assert result is not None
        assert result.relevance == "funding"
        assert "bridge" in result.description

    def test_reconnaissance_with_calldata(self):
        tx = make_etherscan_tx(
            from_addr=ATTACKER, to_addr="0xtarget",
            value="0", input_data="0x70a08231"
        )
        result = self.analyzer._classify_precursor(tx, ATTACKER)
        assert result is not None
        assert result.relevance == "reconnaissance"

    def test_outgoing_zero_value_no_calldata_returns_none(self):
        tx = make_etherscan_tx(
            from_addr=ATTACKER, to_addr="0xtarget",
            value="0", input_data="0x"
        )
        assert self.analyzer._classify_precursor(tx, ATTACKER) is None

    def test_incoming_from_unknown_address_returns_none(self):
        tx = make_etherscan_tx(
            from_addr="0xunknown", to_addr=ATTACKER, value=str(int(1e18))
        )
        assert self.analyzer._classify_precursor(tx, ATTACKER) is None


# ------------------------------------------------------------------
# _identify_funding_source
# ------------------------------------------------------------------

class TestIdentifyFundingSource:
    def setup_method(self):
        self.analyzer = make_analyzer()

    def test_tornado_cash(self):
        txs = [make_etherscan_tx(from_addr=_TORNADO_ADDR, to_addr=ATTACKER, value=str(int(1e18)))]
        assert self.analyzer._identify_funding_source(txs) == "tornado_cash"

    def test_cex(self):
        txs = [make_etherscan_tx(from_addr=_CEX_ADDR, to_addr=ATTACKER, value=str(int(1e18)))]
        assert self.analyzer._identify_funding_source(txs) == f"cex:{_CEX_ADDR}"

    def test_bridge(self):
        txs = [make_etherscan_tx(from_addr=_BRIDGE_ADDR, to_addr=ATTACKER, value=str(int(1e18)))]
        assert self.analyzer._identify_funding_source(txs) == f"bridge:{_BRIDGE_ADDR}"

    def test_returns_none_for_empty_list(self):
        assert self.analyzer._identify_funding_source([]) is None

    def test_returns_none_when_no_known_incoming_eth(self):
        txs = [make_etherscan_tx(from_addr="0xunknown", to_addr=ATTACKER, value=str(int(1e18)))]
        assert self.analyzer._identify_funding_source(txs) is None

    def test_skips_zero_value_transactions(self):
        # from a known tornado address but value=0 → skipped → None
        txs = [make_etherscan_tx(from_addr=_TORNADO_ADDR, to_addr=ATTACKER, value="0")]
        assert self.analyzer._identify_funding_source(txs) is None

    def test_returns_first_match(self):
        txs = [
            make_etherscan_tx(from_addr=_TORNADO_ADDR, to_addr=ATTACKER, value=str(int(1e18))),
            make_etherscan_tx(from_addr=_CEX_ADDR, to_addr=ATTACKER, value=str(int(1e18))),
        ]
        assert self.analyzer._identify_funding_source(txs) == "tornado_cash"


# ------------------------------------------------------------------
# analyze() end-to-end (mocked _fetch_address_history / _fetch_block_timestamp)
# ------------------------------------------------------------------

class TestAnalyzeEndToEnd:
    _ATTACKER = "0xattacker"
    _EXPLOIT_BLOCK = 200
    _EXPLOIT_TIMESTAMP = 1700003600  # earliest_ts = 1700000000 → 1.0 hr prep

    _DEPLOY_TX = {
        "hash": "0xdeploy",
        "blockNumber": "100",
        "timeStamp": "1700000000",
        "from": "0xattacker",
        "to": "",
        "value": "0",
        "isError": "0",
        "input": "0x",
        "contractAddress": "0xcontract",
    }
    _TEST_RUN_TX = {
        "hash": "0xtestrun",
        "blockNumber": "150",
        "timeStamp": "1700001800",
        "from": "0xattacker",
        "to": "0xtarget",
        "value": "0",
        "isError": "1",
        "input": "0x",
        "contractAddress": "",
    }

    def _run_analyze(self, txs, exploit_timestamp=_EXPLOIT_TIMESTAMP):
        analyzer = make_analyzer()
        with patch.object(analyzer, "_fetch_address_history", return_value=txs), \
             patch.object(analyzer, "_fetch_block_timestamp", return_value=exploit_timestamp):
            return analyzer.analyze(self._ATTACKER, self._EXPLOIT_BLOCK)

    def test_precursor_txs_count_and_relevance(self):
        profile = self._run_analyze([self._DEPLOY_TX, self._TEST_RUN_TX])
        assert len(profile.precursor_txs) == 2
        relevances = {p.relevance for p in profile.precursor_txs}
        assert relevances == {"deployment", "test_run"}

    def test_deployed_contracts_populated(self):
        profile = self._run_analyze([self._DEPLOY_TX, self._TEST_RUN_TX])
        assert "0xcontract" in profile.deployed_contracts

    def test_estimated_preparation_time_hours(self):
        profile = self._run_analyze([self._DEPLOY_TX, self._TEST_RUN_TX])
        # earliest_ts=1700000000, exploit_ts=1700003600 → (3600s)/3600 = 1.0 hr
        assert profile.estimated_preparation_time_hours == pytest.approx(1.0)

    def test_funding_source_none_when_no_known_sources(self):
        profile = self._run_analyze([self._DEPLOY_TX, self._TEST_RUN_TX])
        assert profile.funding_source is None

    def test_empty_history_returns_empty_profile(self):
        profile = self._run_analyze([])
        assert profile.precursor_txs == []
        assert profile.funding_source is None
        assert profile.estimated_preparation_time_hours is None

    def test_txs_after_exploit_block_excluded(self):
        after_tx = dict(self._DEPLOY_TX, blockNumber="300")  # > EXPLOIT_BLOCK=200
        profile = self._run_analyze([after_tx])
        assert profile.precursor_txs == []
