"""Etherscan V2 API client for source code retrieval and ABI fetching."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any

import httpx


class EtherscanError(Exception):
    """Raised when an Etherscan API call fails."""


@dataclass
class ContractSource:
    address: str
    name: str
    compiler_version: str
    source_code: str
    abi: list[dict[str, Any]]
    is_proxy: bool = False
    implementation_address: str | None = None


class EtherscanClient:
    """Fetches contract source code and ABIs from Etherscan V2 API."""

    BASE_URL = "https://api.etherscan.io/v2/api"

    # EIP-1967 implementation storage slot
    _EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

    def __init__(self, api_key: str | None = None, chain_id: int = 1):
        self._api_key = api_key or os.getenv("ETHERSCAN_API_KEY", "")
        self._chain_id = chain_id
        self._last_request_time = 0.0
        self._min_interval = 0.35  # ~3 req/s for free tier

    def get_source(self, address: str) -> ContractSource:
        """Fetch verified source code for a contract address."""
        data = self._get({
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
        })

        if not data or not isinstance(data, list) or len(data) == 0:
            raise EtherscanError(f"No source data returned for {address}")

        entry = data[0]

        abi_raw = entry.get("ABI", "")
        if abi_raw and abi_raw != "Contract source code not verified":
            abi = json.loads(abi_raw)
        else:
            abi = []

        is_proxy = entry.get("Proxy") == "1"
        impl_address = entry.get("Implementation") or None

        return ContractSource(
            address=address,
            name=entry.get("ContractName", ""),
            compiler_version=entry.get("CompilerVersion", ""),
            source_code=entry.get("SourceCode", ""),
            abi=abi,
            is_proxy=is_proxy,
            implementation_address=impl_address,
        )

    def get_abi(self, address: str) -> list[dict[str, Any]]:
        """Fetch the ABI for a verified contract."""
        data = self._get({
            "module": "contract",
            "action": "getabi",
            "address": address,
        })

        if not data or data == "Contract source code not verified":
            raise EtherscanError(f"ABI not available for {address} (unverified)")

        if isinstance(data, str):
            return json.loads(data)
        return data

    def is_contract(self, address: str) -> bool:
        """Check if an address is a contract (has code deployed)."""
        data = self._get({
            "module": "proxy",
            "action": "eth_getCode",
            "address": address,
            "tag": "latest",
        })

        return bool(data) and data != "0x"

    def get_creation_tx(self, address: str) -> str | None:
        """Get the transaction hash that created a contract."""
        data = self._get({
            "module": "contract",
            "action": "getcontractcreation",
            "contractaddresses": address,
        })

        if not data or not isinstance(data, list) or len(data) == 0:
            return None

        return data[0].get("txHash")

    def resolve_proxy(self, address: str) -> str | None:
        """If the address is a proxy, return the implementation address.

        Tries Etherscan's Proxy field first, then reads the EIP-1967
        implementation slot directly.
        """
        source = self.get_source(address)
        if source.implementation_address:
            return source.implementation_address

        slot_value = self._get({
            "module": "proxy",
            "action": "eth_getStorageAt",
            "address": address,
            "position": self._EIP1967_IMPL_SLOT,
            "tag": "latest",
        })

        if not slot_value or slot_value == "0x" + "0" * 64:
            return None

        # Address is stored in the lower 20 bytes of the 32-byte slot
        impl = "0x" + slot_value[-40:]
        return impl if impl != "0x" + "0" * 40 else None

    def _get(self, params: dict[str, str]) -> Any:
        """Make an authenticated GET request to Etherscan V2 API."""
        params["apikey"] = self._api_key
        params["chainid"] = str(self._chain_id)

        self._rate_limit()

        try:
            response = httpx.get(self.BASE_URL, params=params, timeout=30.0)
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise EtherscanError(f"Etherscan request timed out: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise EtherscanError(
                f"Etherscan HTTP error: {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise EtherscanError(f"Etherscan connection error: {exc}") from exc

        body = response.json()

        status = body.get("status")
        message = body.get("message", "")

        if status == "0" and "NOTOK" in message:
            raise EtherscanError(
                f"Etherscan API error: {body.get('result', message)}"
            )

        return body.get("result")

    def _rate_limit(self) -> None:
        """Enforce minimum interval between requests."""
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request_time = time.monotonic()
