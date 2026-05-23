"""Converts IR graphs to Mermaid diagrams for report embedding."""

from __future__ import annotations

from src.ir.nodes import ActionType, IRGraph, SemanticAction


class IRVisualizer:
    """Renders an IR graph as a Mermaid flowchart or sequence diagram."""

    ACTION_COLORS = {
        ActionType.FLASH_LOAN_BORROW: "#ff6b6b",
        ActionType.FLASH_LOAN_REPAY: "#ff6b6b",
        ActionType.TOKEN_TRANSFER: "#4ecdc4",
        ActionType.DEX_SWAP: "#45b7d1",
        ActionType.STORAGE_WRITE: "#f9ca24",
        ActionType.DELEGATE_CALL: "#eb4d4b",
        ActionType.SELF_DESTRUCT: "#e74c3c",
        ActionType.LIQUIDATION: "#6c5ce7",
    }

    def to_mermaid_flowchart(self, graph: IRGraph) -> str:
        """Render as a top-down Mermaid flowchart."""
        lines = ["graph TD"]

        for action in graph.actions:
            label = self._action_label(action)
            lines.append(f'    {action.id}["{label}"]')

        for from_id, to_id, label in graph.edges:
            edge_label = f"|{label}|" if label else ""
            lines.append(f"    {from_id} -->{edge_label} {to_id}")

        return "\n".join(lines)

    def to_mermaid_sequence(self, graph: IRGraph) -> str:
        """Render as a Mermaid sequence diagram showing contract interactions."""
        lines = ["sequenceDiagram"]
        participants: set[str] = set()

        for action in graph.actions:
            for addr in (action.from_addr, action.to_addr):
                if addr and addr not in participants:
                    short = self._shorten_addr(addr)
                    lines.insert(1, f"    participant {short}")
                    participants.add(addr)

            from_short = self._shorten_addr(action.from_addr)
            to_short = self._shorten_addr(action.to_addr)
            label = action.action_type.value
            lines.append(f"    {from_short}->>+{to_short}: {label}")

        return "\n".join(lines)

    def to_sankey_data(self, graph: IRGraph) -> list[dict]:
        """Extract token flow data for Sankey diagram rendering."""
        flows = []
        for action in graph.get_actions_by_type(ActionType.TOKEN_TRANSFER):
            flows.append({
                "source": self._shorten_addr(action.from_addr),
                "target": self._shorten_addr(action.to_addr),
                "value": action.params.get("amount", 0),
                "token": action.params.get("token", "ETH"),
            })
        return flows

    def _action_label(self, action: SemanticAction) -> str:
        label = action.action_type.value.replace("_", " ").title()
        if "amount" in action.params:
            label += f"\\n{action.params['amount']}"
        return label

    def _shorten_addr(self, addr: str) -> str:
        if not addr or len(addr) < 10:
            return addr or "unknown"
        return f"{addr[:6]}..{addr[-4:]}"
