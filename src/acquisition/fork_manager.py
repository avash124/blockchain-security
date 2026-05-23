"""Manages Anvil fork instances for transaction replay and ablation testing."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field


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

        # TODO: spawn anvil subprocess
        # cmd = [
        #     "anvil",
        #     "--fork-url", fork_url,
        #     "--fork-block-number", str(fork_block),
        #     "--port", str(port),
        #     "--no-mining",
        # ]
        # instance.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # self._wait_ready(instance)

        self._instances[port] = instance
        return instance

    def stop_fork(self, instance: AnvilInstance) -> None:
        """Terminate an Anvil instance."""
        if instance.process and instance.is_alive:
            instance.process.terminate()
            instance.process.wait(timeout=5)
        self._instances.pop(instance.port, None)

    def stop_all(self) -> None:
        """Tear down all running instances."""
        for instance in list(self._instances.values()):
            self.stop_fork(instance)

    def _wait_ready(self, instance: AnvilInstance, timeout: float = 10.0) -> None:
        """Poll until Anvil is accepting RPC connections."""
        # TODO: implement health check loop
        raise NotImplementedError

    def __enter__(self) -> ForkManager:
        return self

    def __exit__(self, *exc) -> None:
        self.stop_all()
