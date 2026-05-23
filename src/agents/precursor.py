"""Walks attacker address history to find reconnaissance and setup transactions."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx


KNOWN_TORNADO_CASH: set[str] = {
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",
    "0x833481186f16cece3f1eeea1a694c42034c3a0db",
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3",
    "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144",
    "0x07687e702b410fa43f4cb4af7fa097918ffd2730",
    "0x23773e65ed146a459667dd6e2af86b11819a9e4d",
    "0x22aaa7720ddd5388a3c0a3333430953c68f1849b",
    "0x03893a7c7463ae47d46bc7f091665f1893656003",
    "0x2717c5e28cf931547b621a5dddb772ab6a35b701",
    "0x58e8dcc13be9780fc42e8723d8ead4cf46943df2",
}

KNOWN_CEX_HOT_WALLETS: set[str] = {
    "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be",  # Binance
    "0xd551234ae421e3bcba99a0da6d736074f22192ff",
    "0x564286362092d8e7936f0549571a803b203aaced",
    "0x0681d8db095565fe8a346fa0277bffde9c0edbbf",
    "0x4e9ce36e442e55ecd9025b9a6e0d88485d628a67",
    "0xa090e606e30bd747d4e6245a1517ebe430f0057e",  # Coinbase
    "0x71660c4005ba85c37ccec55d0c4493e66fe775d3",
    "0x503828976d22510aad0201ac7ec88293211d23da",
    "0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740",
    "0x3cd751e6b0078be393132286c442345e5dc49699",
    "0xb5d85cbf7cb3ee0d56b3bb207d5fc4b82f43f511",
    "0xeb2629a2734e272bcc07bda959863f316f4bd4cf",
    "0x2910543af39aba0cd09dbb2d50200b3e800a63d2",  # Kraken
    "0xae2d4617c862309a3d75a0ffb358c7a5009c673f",
    "0x43984d578803891dfa9706bdeee6078d80cfc79e",
    "0x66c57bf505a85a74609d2c83e7f8b4a4a13bc89d",
    "0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0",  # Huobi
    "0x6748f50f686bfbca6fe8ad62b22228b87f31ff2b",
    "0xeee28d484628d41a82d01e21d12e2e78d69920da",
}

KNOWN_BRIDGES: set[str] = {
    "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1",  # Optimism bridge
    "0x8484ef722627bf18ca5ae6bcf031c23e6e922b30",  # Arbitrum bridge
    "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f",  # Arbitrum Inbox
    "0xa0c68c638235ee32657e8f720a23cec1bfc77c77",  # Polygon bridge
    "0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf",  # Polygon ERC20 bridge
    "0x1116898dda4015ed8ddefb84b6e8bc24528af2d8",  # Stargate Finance
    "0xb4d5dce1e2a5f880efa67ac6a8dfeae3f79f3ecf",  # Across Protocol
}

ETHERSCAN_BASE_URL = "https://api.etherscan.io/api"
_PAGE_SIZE = 1000


@dataclass
class PrecursorTx:
    tx_hash: str
    block_number: int
    timestamp: int
    description: str
    relevance: str  # "funding", "deployment", "test_run", "reconnaissance"


@dataclass
class AttackerProfile:
    address: str
    funding_source: str | None = None
    precursor_txs: list[PrecursorTx] = field(default_factory=list)
    deployed_contracts: list[str] = field(default_factory=list)
    estimated_preparation_time_hours: float | None = None


class PrecursorAnalyzer:
    """Analyzes attacker address history to build a timeline of preparation."""

    def __init__(self, rpc_url: str, ETHER_SCAN_KEY: str | None = None):
        self._rpc_url = rpc_url
        self._etherscan_key = ETHER_SCAN_KEY

    def analyze(self, attacker_address: str, exploit_block: int) -> AttackerProfile:
        """Walk backward from the exploit to find setup transactions."""
        profile = AttackerProfile(address=attacker_address)
        attacker_lower = attacker_address.lower()

        # 1. Fetch all txs from attacker address via Etherscan
        all_txs = self._fetch_address_history(attacker_address)

        # 2. Filter to txs before exploit_block
        pre_exploit_txs = [
            tx for tx in all_txs if int(tx.get("blockNumber", 0)) < exploit_block
        ]

        # 3. Identify funding source (CEX, tornado, bridge)
        profile.funding_source = self._identify_funding_source(pre_exploit_txs)

        # 4 & 5. Classify each tx; collect deployments and test runs
        for tx in pre_exploit_txs:
            precursor = self._classify_precursor(tx, attacker_lower)
            if precursor is None:
                continue
            profile.precursor_txs.append(precursor)
            if precursor.relevance == "deployment":
                contract_addr = tx.get("contractAddress", "")
                if contract_addr:
                    profile.deployed_contracts.append(contract_addr)

        # Estimate preparation window from earliest precursor to exploit block
        if profile.precursor_txs:
            earliest_ts = min(p.timestamp for p in profile.precursor_txs)
            exploit_ts = self._fetch_block_timestamp(exploit_block)
            if exploit_ts is not None:
                profile.estimated_preparation_time_hours = (
                    exploit_ts - earliest_ts
                ) / 3600.0

        return profile

    def _fetch_address_history(self, address: str) -> list[dict[str, Any]]:
        """Get all transactions for an address via Etherscan txlist (paginated)."""
        all_txs: list[dict[str, Any]] = []
        page = 1

        while True:
            params: dict[str, str] = {
                "module": "account",
                "action": "txlist",
                "address": address,
                "sort": "asc",
                "page": str(page),
                "offset": str(_PAGE_SIZE),
            }
            if self._etherscan_key:
                params["apikey"] = self._etherscan_key

            resp = httpx.get(ETHERSCAN_BASE_URL, params=params, timeout=30)
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()

            if data.get("status") != "1":
                break

            batch: list[dict[str, Any]] = data.get("result", [])
            all_txs.extend(batch)

            if len(batch) < _PAGE_SIZE:
                break

            page += 1
            time.sleep(0.2)  # stay within Etherscan free-tier rate limit

        return all_txs

    def _classify_precursor(
        self, tx: dict[str, Any], attacker_address: str
    ) -> PrecursorTx | None:
        """Classify a transaction as a precursor type or None if irrelevant."""
        from_addr = tx.get("from", "").lower()
        to_addr = tx.get("to", "").lower()
        is_error = tx.get("isError", "0") == "1"
        value = int(tx.get("value", "0"))
        input_data = tx.get("input", "0x")

        block = int(tx.get("blockNumber", 0))
        ts = int(tx.get("timeStamp", 0))
        tx_hash = tx.get("hash", "")

        # 4. Contract deployment — attacker deployed an attack contract
        if from_addr == attacker_address and not to_addr:
            contract_addr = tx.get("contractAddress", "unknown")
            return PrecursorTx(
                tx_hash=tx_hash,
                block_number=block,
                timestamp=ts,
                description=f"Deployed attack contract at {contract_addr}",
                relevance="deployment",
            )

        # 5. Test run — outgoing failed tx (attacker probing the target)
        if from_addr == attacker_address and is_error:
            return PrecursorTx(
                tx_hash=tx_hash,
                block_number=block,
                timestamp=ts,
                description=f"Failed probe tx to {to_addr}",
                relevance="test_run",
            )

        # 3. Funding — incoming ETH from a known source
        all_known = KNOWN_TORNADO_CASH | KNOWN_CEX_HOT_WALLETS | KNOWN_BRIDGES
        if to_addr == attacker_address and value > 0 and from_addr in all_known:
            eth_amount = value / 1e18
            source_type = (
                "tornado_cash"
                if from_addr in KNOWN_TORNADO_CASH
                else "bridge"
                if from_addr in KNOWN_BRIDGES
                else "cex"
            )
            return PrecursorTx(
                tx_hash=tx_hash,
                block_number=block,
                timestamp=ts,
                description=f"Received {eth_amount:.4f} ETH from {source_type} ({from_addr})",
                relevance="funding",
            )

        # Reconnaissance — outgoing zero-value call with calldata (reading state)
        if (
            from_addr == attacker_address
            and not is_error
            and value == 0
            and len(input_data) > 2  # has calldata beyond "0x"
        ):
            return PrecursorTx(
                tx_hash=tx_hash,
                block_number=block,
                timestamp=ts,
                description=f"Reconnaissance call to {to_addr}",
                relevance="reconnaissance",
            )

        return None

    def _identify_funding_source(self, txs: list[dict[str, Any]]) -> str | None:
        """Determine where the attacker's initial ETH came from."""
        for tx in txs:  # already sorted ascending by block
            from_addr = tx.get("from", "").lower()
            value = int(tx.get("value", "0"))
            if value == 0:
                continue
            if from_addr in KNOWN_TORNADO_CASH:
                return "tornado_cash"
            if from_addr in KNOWN_CEX_HOT_WALLETS:
                return f"cex:{from_addr}"
            if from_addr in KNOWN_BRIDGES:
                return f"bridge:{from_addr}"
        return None

    def _fetch_block_timestamp(self, block_number: int) -> int | None:
        """Fetch a block's Unix timestamp via JSON-RPC."""
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [hex(block_number), False],
            "id": 1,
        }
        try:
            resp = httpx.post(self._rpc_url, json=payload, timeout=30)
            resp.raise_for_status()
            result = resp.json().get("result") or {}
            ts_hex = result.get("timestamp")
            if ts_hex:
                return int(ts_hex, 16)
        except Exception:
            return None
        return None
