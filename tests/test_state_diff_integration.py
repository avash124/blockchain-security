"""Integration tests for StateDiffComputer against a local Anvil fork.

Requires: anvil binary, MAINNET_RPC_URL env var (archive node).
Run with:  pytest tests/test_state_diff_integration.py -v
"""

from __future__ import annotations

import os

import httpx
import pytest

from src.acquisition.fork_manager import ForkManager, ForkError
from src.verifier.state_diff import StateDiffComputer

MAINNET_RPC = os.environ.get("MAINNET_RPC_URL", "")

# Euler Finance exploit — 2023-03-13
EULER_BLOCK = 16817995
EULER_PROTOCOL = "0x27182842E098f60e3D576794A5bFFb0777E025d3"
DAI = "0x6B175474E89094C44Da98b954EedeAC495271d0F"

# Anvil default prefunded accounts (10000 ETH each)
SENDER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
SENDER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
RECEIVER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

needs_rpc = pytest.mark.skipif(not MAINNET_RPC, reason="MAINNET_RPC_URL not set")


def _anvil_rpc(url: str, method: str, params: list) -> object:
    """Quick JSON-RPC helper for test setup calls."""
    resp = httpx.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=30)
    body = resp.json()
    if "error" in body:
        raise RuntimeError(f"RPC error: {body['error']}")
    return body.get("result")


def _send_eth_and_mine(rpc_url: str) -> str:
    """Send 1 ETH from SENDER to RECEIVER on the Anvil fork, mine it, return tx hash."""
    _anvil_rpc(rpc_url, "evm_setAutomine", [True])

    tx_hash = _anvil_rpc(rpc_url, "eth_sendTransaction", [{
        "from": SENDER,
        "to": RECEIVER,
        "value": "0xDE0B6B3A7640000",  # 1 ETH
    }])
    return tx_hash


@pytest.fixture(scope="module")
def anvil():
    """Spin up a single Anvil fork for the whole module."""
    if not MAINNET_RPC:
        pytest.skip("MAINNET_RPC_URL not set")

    fm = ForkManager(base_port=18545)
    try:
        instance = fm.start_fork(MAINNET_RPC, EULER_BLOCK)
    except ForkError as exc:
        pytest.skip(f"Could not start Anvil fork: {exc}")

    yield instance
    fm.stop_all()


@pytest.fixture(scope="module")
def local_tx(anvil) -> str:
    """Send a simple ETH transfer on the fork and return the tx hash."""
    return _send_eth_and_mine(anvil.rpc_url)


@pytest.fixture()
def computer(anvil):
    return StateDiffComputer(rpc_url=anvil.rpc_url)


# ------------------------------------------------------------------
# RPC primitive tests (query forked mainnet state)
# ------------------------------------------------------------------

@needs_rpc
class TestRPCPrimitives:

    def test_get_balance_known_contract(self, computer):
        """Euler protocol held significant ETH at the exploit block."""
        bal = computer._get_balance(EULER_PROTOCOL.lower(), EULER_BLOCK)
        assert isinstance(bal, int)
        assert bal >= 0

    def test_token_balance_consistent_at_same_block(self, computer):
        """Querying the same block twice should return identical results."""
        bal1 = computer._get_token_balance(DAI.lower(), EULER_PROTOCOL.lower(), EULER_BLOCK)
        bal2 = computer._get_token_balance(DAI.lower(), EULER_PROTOCOL.lower(), EULER_BLOCK)
        assert bal1 == bal2
        assert bal1 > 0, "Euler protocol should hold DAI at this block"

    def test_get_token_balance(self, computer):
        """DAI balanceOf should return a valid integer."""
        bal = computer._get_token_balance(DAI.lower(), EULER_PROTOCOL.lower(), EULER_BLOCK)
        assert isinstance(bal, int)
        assert bal >= 0

    def test_get_storage_returns_hex(self, computer):
        """Reading a storage slot should return a 0x-prefixed hex string."""
        val = computer._get_storage(EULER_PROTOCOL.lower(), "0x0", EULER_BLOCK)
        assert isinstance(val, str)
        assert val.startswith("0x")


# ------------------------------------------------------------------
# Full compute() tests (against a local tx on the fork)
# ------------------------------------------------------------------

@needs_rpc
class TestComputeIntegration:

    def test_compute_detects_eth_transfer(self, computer, local_tx):
        """compute() on a local ETH transfer should show balance changes."""
        diff = computer.compute(
            local_tx,
            [SENDER.lower(), RECEIVER.lower()],
        )
        assert len(diff.balance_changes) > 0

        receiver_gains = diff.get_gains(RECEIVER.lower())
        assert len(receiver_gains) == 1, "Receiver should have exactly one ETH gain"
        assert receiver_gains[0].token == "ETH"
        assert receiver_gains[0].delta == 10**18  # 1 ETH

    def test_compute_sender_spent_eth(self, computer, local_tx):
        """Sender should have lost ETH (transfer + gas)."""
        diff = computer.compute(local_tx, [SENDER.lower()])
        losses = diff.get_losses(SENDER.lower())
        assert len(losses) == 1
        assert abs(losses[0].delta) >= 10**18  # at least the 1 ETH sent

    def test_compute_total_profit(self, computer, local_tx):
        """Receiver profit should be exactly 1 ETH."""
        diff = computer.compute(local_tx, [RECEIVER.lower()])
        assert diff.total_profit(RECEIVER.lower()) == 10**18

    def test_compute_no_tokens_no_storage(self, computer, local_tx):
        """A plain ETH transfer should produce no token or storage changes."""
        diff = computer.compute(local_tx, [SENDER.lower(), RECEIVER.lower()])
        assert len(diff.storage_changes) == 0
        token_changes = [b for b in diff.balance_changes if b.token != "ETH"]
        assert len(token_changes) == 0

    def test_compute_to_dict_roundtrip(self, computer, local_tx):
        """to_dict() output should have parseable delta strings."""
        diff = computer.compute(local_tx, [RECEIVER.lower()])
        d = diff.to_dict()
        assert len(d["balance_changes"]) > 0
        for bc in d["balance_changes"]:
            int(bc["delta"])  # should not raise

    def test_compute_no_lifecycle_for_eoas(self, computer, local_tx):
        """EOAs should not appear in created or destroyed lists."""
        diff = computer.compute(local_tx, [SENDER.lower(), RECEIVER.lower()])
        assert diff.created_contracts == []
        assert diff.destroyed_contracts == []
