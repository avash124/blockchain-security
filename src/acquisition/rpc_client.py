"""Shared JSON-RPC 2.0 client for Ethereum node communication."""

from __future__ import annotations

from typing import Any

import httpx


class RpcError(Exception):
    """Raised when a JSON-RPC call fails."""


class RpcClient:
    """Lightweight JSON-RPC 2.0 client over HTTP."""

    def __init__(self, rpc_url: str, timeout: float = 30.0):
        self._rpc_url = rpc_url
        self._timeout = timeout

    @property
    def rpc_url(self) -> str:
        return self._rpc_url

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        """Send a JSON-RPC request and return the 'result' field."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or [],
        }

        try:
            response = httpx.post(
                self._rpc_url, json=payload, timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise RpcError(f"RPC timeout for {method}: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise RpcError(
                f"RPC HTTP error for {method}: {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise RpcError(f"RPC connection error for {method}: {exc}") from exc

        body = response.json()

        if "error" in body:
            err = body["error"]
            code = err.get("code", "?")
            message = err.get("message", str(err))
            raise RpcError(f"RPC error in {method} (code {code}): {message}")

        if "result" not in body:
            raise RpcError(f"RPC response for {method} missing 'result' field")

        return body["result"]