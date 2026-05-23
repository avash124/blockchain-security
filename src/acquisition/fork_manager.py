"""Manages Anvil fork instances for transaction replay and ablation testing."""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.acquisition.rpc_client import RpcClient, RpcError


class ForkError(Exception):
    """Raised when an Anvil fork operation fails."""


@dataclass
class AnvilInstance:
    port: int
    fork_url: str
    fork_block: int
    process: subprocess.Popen | None = field(default=None, repr=False)

    @property
    def rpc_url(self) -> str:
        return f"http://localhost:{self.port}"

    @property
    def is_alive(self) -> bool:
        return self.process is not None and self.process.poll() is None


class ForkManager:
    """Spins up and tears down Anvil fork instances."""

    def __init__(self, base_port: int = 8546):
        self._base_port = base_port
        self._instances: dict[int, AnvilInstance] = {}
        self._next_port = base_port

    def start_fork(self, fork_url: str, fork_block: int) -> AnvilInstance:
        """Start a new Anvil instance forked at the given block."""
        port = self._next_port
        self._next_port += 1

        instance = AnvilInstance(
            port=port,
            fork_url=fork_url,
            fork_block=fork_block,
        )

        anvil_bin = self._find_anvil()
        cmd = [
            anvil_bin,
            "--fork-url", fork_url,
            "--fork-block-number", str(fork_block),
            "--port", str(port),
            "--no-mining",
            "--silent",
        ]
        instance.process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self._wait_ready(instance)

        self._instances[port] = instance
        return instance

    def stop_fork(self, instance: AnvilInstance) -> None:
        """Terminate an Anvil instance."""
        if instance.process is None:
            self._instances.pop(instance.port, None)
            return

        if instance.is_alive:
            instance.process.terminate()
            try:
                instance.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                instance.process.kill()
                instance.process.wait(timeout=5)

        self._instances.pop(instance.port, None)

    def stop_all(self) -> None:
        """Tear down all running instances."""
        for instance in list(self._instances.values()):
            self.stop_fork(instance)

    def snapshot(self, instance: AnvilInstance) -> str:
        """Create an EVM snapshot and return the snapshot ID."""
        result = self._rpc_call(instance, "evm_snapshot", [])
        return result

    def revert(self, instance: AnvilInstance, snapshot_id: str) -> bool:
        """Revert the EVM state to a previous snapshot."""
        result = self._rpc_call(instance, "evm_revert", [snapshot_id])
        return result

    def _rpc_call(self, instance: AnvilInstance, method: str, params: list[Any]) -> Any:
        """Send a JSON-RPC call to an Anvil instance."""
        rpc = RpcClient(instance.rpc_url, timeout=10.0)
        try:
            return rpc.call(method, params)
        except RpcError as exc:
            raise ForkError(str(exc)) from exc

    @staticmethod
    def _find_anvil() -> str:
        """Locate the anvil binary, checking ~/.foundry/bin if not on PATH."""
        found = shutil.which("anvil")
        if found:
            return found
        foundry_bin = Path.home() / ".foundry" / "bin" / "anvil"
        if foundry_bin.exists():
            return str(foundry_bin)
        raise ForkError("anvil not found. Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup")

    def _wait_ready(self, instance: AnvilInstance, timeout: float = 30.0) -> None:
        """Poll until Anvil is accepting RPC connections."""
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            # Check if process died early
            if instance.process is not None and instance.process.poll() is not None:
                stderr_output = instance.process.stderr.read().decode() if instance.process.stderr else ""
                raise ForkError(
                    f"Anvil process exited with code {instance.process.returncode}: {stderr_output}"
                )

            try:
                self._rpc_call(instance, "eth_chainId", [])
                return
            except (ForkError, RpcError):
                time.sleep(0.25)

        raise ForkError(f"Anvil on port {instance.port} not ready after {timeout}s")

    def __enter__(self) -> ForkManager:
        return self

    def __exit__(self, *exc) -> None:
        self.stop_all()