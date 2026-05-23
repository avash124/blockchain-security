"""Semantic action dataclasses for the intermediate representation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ActionType(Enum):
    TOKEN_TRANSFER = "token_transfer"
    ETH_TRANSFER = "eth_transfer"
    FLASH_LOAN_BORROW = "flash_loan_borrow"
    FLASH_LOAN_REPAY = "flash_loan_repay"
    DEX_SWAP = "dex_swap"
    STORAGE_WRITE = "storage_write"
    STORAGE_READ = "storage_read"
    DELEGATE_CALL = "delegate_call"
    SELF_DESTRUCT = "self_destruct"
    CONTRACT_DEPLOYMENT = "contract_deployment"
    GOVERNANCE_ACTION = "governance_action"
    ORACLE_READ = "oracle_read"
    LIQUIDATION = "liquidation"
    UNKNOWN = "unknown"


@dataclass
class SemanticAction:
    """A single high-level action extracted from raw EVM opcodes."""
    action_type: ActionType
    depth: int
    from_addr: str
    to_addr: str
    params: dict[str, Any] = field(default_factory=dict)
    children: list[SemanticAction] = field(default_factory=list)
    trace_index_start: int = 0
    trace_index_end: int = 0

    @property
    def id(self) -> str:
        return f"{self.action_type.value}_{self.trace_index_start}"


@dataclass
class IRGraph:
    """The full intermediate representation of a transaction's behavior."""
    tx_hash: str
    actions: list[SemanticAction] = field(default_factory=list)
    edges: list[tuple[str, str, str]] = field(default_factory=list)  # (from_id, to_id, label)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_action(self, action: SemanticAction) -> None:
        self.actions.append(action)

    def add_edge(self, from_id: str, to_id: str, label: str = "") -> None:
        self.edges.append((from_id, to_id, label))

    def get_actions_by_type(self, action_type: ActionType) -> list[SemanticAction]:
        return [a for a in self.actions if a.action_type == action_type]

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON export."""
        return {
            "tx_hash": self.tx_hash,
            "actions": [
                {
                    "id": a.id,
                    "type": a.action_type.value,
                    "from": a.from_addr,
                    "to": a.to_addr,
                    "depth": a.depth,
                    "params": a.params,
                }
                for a in self.actions
            ],
            "edges": [
                {"from": e[0], "to": e[1], "label": e[2]} for e in self.edges
            ],
        }
