"""Unit tests for state_diff balance/storage diffing."""

import pytest
from unittest.mock import patch, MagicMock

from src.verifier.state_diff import (
    BalanceChange,
    StorageChange,
    StateDiff,
    StateDiffComputer,
    StateDiffError,
    _parse_hex_int,
    _to_hex,
)


# ------------------------------------------------------------------
# BalanceChange dataclass
# ------------------------------------------------------------------

class TestBalanceChange:
    def test_positive_delta(self):
        bc = BalanceChange(address="0xaaa", token="ETH", before=100, after=500)
        assert bc.delta == 400
        assert bc.is_gain is True

    def test_negative_delta(self):
        bc = BalanceChange(address="0xbbb", token="ETH", before=500, after=100)
        assert bc.delta == -400
        assert bc.is_gain is False

    def test_zero_delta(self):
        bc = BalanceChange(address="0xccc", token="ETH", before=100, after=100)
        assert bc.delta == 0
        assert bc.is_gain is False


# ------------------------------------------------------------------
# StateDiff helpers
# ------------------------------------------------------------------

class TestStateDiff:
    def _make_diff(self) -> StateDiff:
        return StateDiff(
            balance_changes=[
                BalanceChange(address="0xattacker", token="ETH", before=0, after=1000),
                BalanceChange(address="0xattacker", token="0xtoken", before=0, after=500),
                BalanceChange(address="0xvictim", token="ETH", before=2000, after=1000),
            ],
            storage_changes=[
                StorageChange(contract="0xvictim", slot="0x0", before="0x01", after="0x00"),
            ],
            created_contracts=["0xnew"],
            destroyed_contracts=["0xdead"],
        )

    def test_get_gains(self):
        diff = self._make_diff()
        gains = diff.get_gains("0xattacker")
        assert len(gains) == 2
        assert all(g.is_gain for g in gains)

    def test_get_gains_empty(self):
        diff = self._make_diff()
        assert diff.get_gains("0xvictim") == []

    def test_get_losses(self):
        diff = self._make_diff()
        losses = diff.get_losses("0xvictim")
        assert len(losses) == 1
        assert losses[0].delta == -1000

    def test_get_losses_empty(self):
        diff = self._make_diff()
        assert diff.get_losses("0xattacker") == []

    def test_total_profit(self):
        diff = self._make_diff()
        assert diff.total_profit("0xattacker") == 1500
        assert diff.total_profit("0xvictim") == -1000

    def test_total_profit_unknown_address(self):
        diff = self._make_diff()
        assert diff.total_profit("0xunknown") == 0

    def test_to_dict(self):
        diff = self._make_diff()
        d = diff.to_dict()
        assert len(d["balance_changes"]) == 3
        assert len(d["storage_changes"]) == 1
        assert d["balance_changes"][0]["delta"] == "1000"
        assert d["storage_changes"][0]["before"] == "0x01"

    def test_empty_diff(self):
        diff = StateDiff()
        assert diff.get_gains("0xany") == []
        assert diff.get_losses("0xany") == []
        assert diff.total_profit("0xany") == 0
        assert diff.to_dict() == {"balance_changes": [], "storage_changes": []}


# ------------------------------------------------------------------
# Hex helpers
# ------------------------------------------------------------------

class TestHexHelpers:
    def test_to_hex(self):
        assert _to_hex(0) == "0x0"
        assert _to_hex(255) == "0xff"
        assert _to_hex(17000000) == hex(17000000)

    def test_parse_hex_int_from_hex(self):
        assert _parse_hex_int("0xff") == 255
        assert _parse_hex_int("0x0") == 0
        assert _parse_hex_int("0x103a6e7") == 0x103a6e7

    def test_parse_hex_int_from_int(self):
        assert _parse_hex_int(42) == 42

    def test_parse_hex_int_from_decimal_string(self):
        assert _parse_hex_int("100") == 100

    def test_parse_hex_int_non_string(self):
        assert _parse_hex_int(None) == 0


# ------------------------------------------------------------------
# StateDiffComputer (mocked RPC)
# ------------------------------------------------------------------

def _mock_rpc_responses(responses: dict[str, object]):
    """Return a side_effect function that dispatches on RPC method name."""
    def side_effect(method, params):
        if method in responses:
            val = responses[method]
            if callable(val):
                return val(params)
            return val
        raise StateDiffError(f"Unexpected RPC method: {method}")
    return side_effect


class TestStateDiffComputer:
    def test_compute_eth_balance_diff(self):
        computer = StateDiffComputer(rpc_url="http://fake:8545")

        def rpc(method, params):
            if method == "eth_getTransactionReceipt":
                return {"blockNumber": "0xa"}  # block 10
            if method == "eth_getBalance":
                addr, block_hex = params
                block = int(block_hex, 16)
                if addr == "0xattacker" and block == 9:
                    return "0x0"
                if addr == "0xattacker" and block == 10:
                    return "0x3e8"  # 1000
                return "0x0"
            if method == "eth_getCode":
                return "0x"
            raise StateDiffError(f"Unexpected: {method}")

        with patch.object(computer, "_rpc_call", side_effect=rpc):
            diff = computer.compute("0xdeadbeef", ["0xattacker"])

        assert len(diff.balance_changes) == 1
        bc = diff.balance_changes[0]
        assert bc.address == "0xattacker"
        assert bc.token == "ETH"
        assert bc.before == 0
        assert bc.after == 1000

    def test_compute_no_change_skipped(self):
        computer = StateDiffComputer(rpc_url="http://fake:8545")

        def rpc(method, params):
            if method == "eth_getTransactionReceipt":
                return {"blockNumber": "0xa"}
            if method == "eth_getBalance":
                return "0x64"  # same balance at both blocks
            if method == "eth_getCode":
                return "0x"
            raise StateDiffError(f"Unexpected: {method}")

        with patch.object(computer, "_rpc_call", side_effect=rpc):
            diff = computer.compute("0xdeadbeef", ["0xaddr"])

        assert len(diff.balance_changes) == 0

    def test_compute_with_token_balances(self):
        computer = StateDiffComputer(rpc_url="http://fake:8545")

        def rpc(method, params):
            if method == "eth_getTransactionReceipt":
                return {"blockNumber": "0xa"}
            if method == "eth_getBalance":
                return "0x0"
            if method == "eth_call":
                call_obj, block_hex = params
                block = int(block_hex, 16)
                if block == 9:
                    return "0x0"
                return "0x2710"  # 10000
            if method == "eth_getCode":
                return "0x"
            raise StateDiffError(f"Unexpected: {method}")

        with patch.object(computer, "_rpc_call", side_effect=rpc):
            diff = computer.compute("0xdeadbeef", ["0xattacker"], tokens=["0xtoken"])

        token_changes = [b for b in diff.balance_changes if b.token == "0xtoken"]
        assert len(token_changes) == 1
        assert token_changes[0].delta == 10000

    def test_compute_with_storage_slots(self):
        computer = StateDiffComputer(rpc_url="http://fake:8545")

        def rpc(method, params):
            if method == "eth_getTransactionReceipt":
                return {"blockNumber": "0xa"}
            if method == "eth_getBalance":
                return "0x0"
            if method == "eth_getStorageAt":
                _, _, block_hex = params
                block = int(block_hex, 16)
                return "0x01" if block == 9 else "0x02"
            if method == "eth_getCode":
                return "0x"
            raise StateDiffError(f"Unexpected: {method}")

        with patch.object(computer, "_rpc_call", side_effect=rpc):
            diff = computer.compute(
                "0xdeadbeef", ["0xaddr"],
                storage_slots={"0xcontract": ["0x0"]},
            )

        assert len(diff.storage_changes) == 1
        sc = diff.storage_changes[0]
        assert sc.contract == "0xcontract"
        assert sc.before == "0x01"
        assert sc.after == "0x02"

    def test_compute_detects_contract_creation(self):
        computer = StateDiffComputer(rpc_url="http://fake:8545")

        def rpc(method, params):
            if method == "eth_getTransactionReceipt":
                return {"blockNumber": "0xa"}
            if method == "eth_getBalance":
                return "0x0"
            if method == "eth_getCode":
                addr, block_hex = params
                block = int(block_hex, 16)
                if block == 9:
                    return "0x"
                return "0x6080604052"  # bytecode after creation
            raise StateDiffError(f"Unexpected: {method}")

        with patch.object(computer, "_rpc_call", side_effect=rpc):
            diff = computer.compute("0xdeadbeef", ["0xnewcontract"])

        assert "0xnewcontract" in diff.created_contracts
        assert len(diff.destroyed_contracts) == 0

    def test_compute_detects_contract_destruction(self):
        computer = StateDiffComputer(rpc_url="http://fake:8545")

        def rpc(method, params):
            if method == "eth_getTransactionReceipt":
                return {"blockNumber": "0xa"}
            if method == "eth_getBalance":
                return "0x0"
            if method == "eth_getCode":
                addr, block_hex = params
                block = int(block_hex, 16)
                if block == 9:
                    return "0x6080604052"
                return "0x"  # destroyed
            raise StateDiffError(f"Unexpected: {method}")

        with patch.object(computer, "_rpc_call", side_effect=rpc):
            diff = computer.compute("0xdeadbeef", ["0xdead"])

        assert "0xdead" in diff.destroyed_contracts
        assert len(diff.created_contracts) == 0

    def test_compute_receipt_not_found(self):
        computer = StateDiffComputer(rpc_url="http://fake:8545")

        with patch.object(computer, "_rpc_call", return_value=None):
            with pytest.raises(StateDiffError, match="receipt not found"):
                computer.compute("0xbadtx", ["0xaddr"])

    def test_compute_multiple_addresses(self):
        computer = StateDiffComputer(rpc_url="http://fake:8545")

        def rpc(method, params):
            if method == "eth_getTransactionReceipt":
                return {"blockNumber": "0xa"}
            if method == "eth_getBalance":
                addr, block_hex = params
                block = int(block_hex, 16)
                balances = {
                    ("0xattacker", 9): "0x0",
                    ("0xattacker", 10): "0x3e8",
                    ("0xvictim", 9): "0x3e8",
                    ("0xvictim", 10): "0x0",
                }
                return balances.get((addr, block), "0x0")
            if method == "eth_getCode":
                return "0x"
            raise StateDiffError(f"Unexpected: {method}")

        with patch.object(computer, "_rpc_call", side_effect=rpc):
            diff = computer.compute("0xdeadbeef", ["0xattacker", "0xvictim"])

        assert len(diff.balance_changes) == 2
        assert diff.total_profit("0xattacker") == 1000
        assert diff.total_profit("0xvictim") == -1000

    def test_get_token_balance_empty_response(self):
        computer = StateDiffComputer(rpc_url="http://fake:8545")
        with patch.object(computer, "_rpc_call", return_value="0x"):
            result = computer._get_token_balance("0xtoken", "0xaddr", 10)
        assert result == 0

    def test_rpc_call_timeout(self):
        computer = StateDiffComputer(rpc_url="http://fake:8545")
        import httpx
        with patch("httpx.post", side_effect=httpx.TimeoutException("timed out")):
            with pytest.raises(StateDiffError, match="RPC timeout"):
                computer._rpc_call("eth_getBalance", ["0xaddr", "0xa"])

    def test_rpc_call_error_response(self):
        computer = StateDiffComputer(rpc_url="http://fake:8545")
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32601, "message": "Method not found"},
        }
        with patch("httpx.post", return_value=mock_resp):
            with pytest.raises(StateDiffError, match="Method not found"):
                computer._rpc_call("bad_method", [])
