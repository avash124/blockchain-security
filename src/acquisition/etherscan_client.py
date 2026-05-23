"""Etherscan API client for source code retrieval and ABI fetching."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


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
    """Fetches contract source code and ABIs from Etherscan."""

    BASE_URL = "https://api.etherscan.io/api"

    def __init__(self, api_key: str | None = None):
        self._api_key = api_key or os.getenv("ETHERSCAN_API_KEY", "")

    def get_source(self, address: str) -> ContractSource:
        """Fetch verified source code for a contract address."""
        # TODO: GET /api?module=contract&action=getsourcecode&address={address}
        raise NotImplementedError

    def get_abi(self, address: str) -> list[dict[str, Any]]:
        """Fetch the ABI for a verified contract."""
        # TODO: GET /api?module=contract&action=getabi&address={address}
        raise NotImplementedError

    def is_contract(self, address: str) -> bool:
        """Check if an address is a contract (has code)."""
        # TODO: GET /api?module=proxy&action=eth_getCode&address={address}
        raise NotImplementedError

    def get_creation_tx(self, address: str) -> str | None:
        """Get the transaction hash that created a contract."""
        # TODO: GET /api?module=contract&action=getcontractcreation&contractaddresses={address}
        raise NotImplementedError

    def resolve_proxy(self, address: str) -> str | None:
        """If the address is a proxy, return the implementation address."""
        # TODO: read EIP-1967 storage slot or use Etherscan proxy detection
        raise NotImplementedError

    def _get(self, params: dict[str, str]) -> dict[str, Any]:
        """Make an authenticated GET request to Etherscan."""
        params["apikey"] = self._api_key
        # TODO: httpx.get(self.BASE_URL, params=params) with rate limiting
        raise NotImplementedError
