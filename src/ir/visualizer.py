"""Converts IR graphs to Mermaid diagrams for report embedding."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from src.ir.nodes import ActionType, IRGraph, SemanticAction

# Maps action type → (vulnerability description, security fix)
_VULN_FIXES: dict[ActionType, list[tuple[str, str]]] = {
    ActionType.LIQUIDATION: [
        (
            "Self-liquidation not restricted — liquidator can equal borrower",
            "Require liquidator != borrower; zero-out bonus for self-liquidations",
        ),
        (
            "Liquidation bonus can drain protocol reserves beyond actual loss",
            "Cap bonus to min(bonus_rate * debt, available_reserve_balance)",
        ),
    ],
    ActionType.DELEGATE_CALL: [
        (
            "DELEGATECALL targets an unverified or in-tx-deployed contract",
            "Validate implementation via an allowlist or EIP-1967 immutable slot",
        ),
    ],
    ActionType.FLASH_LOAN_BORROW: [
        (
            "Health / collateral factor not re-validated after flash-funded operations",
            "Re-check health factor after every balance-altering call inside the loan",
        ),
    ],
    ActionType.GOVERNANCE_ACTION: [
        (
            "Governance votes cast with flash-borrowed tokens (no lock-up)",
            "Snapshot voting power at proposal-creation block; require token time-lock",
        ),
    ],
    ActionType.DEX_SWAP: [
        (
            "Spot DEX price used directly as collateral oracle — manipulable in one tx",
            "Replace with a TWAP oracle (≥ 30-minute window) or Chainlink price feed",
        ),
    ],
    ActionType.STORAGE_WRITE: [
        (
            "State written before balance/invariant check (checks-effects violated)",
            "Apply checks-effects-interactions: validate invariants before state mutation",
        ),
    ],
    ActionType.SELF_DESTRUCT: [
        (
            "SELFDESTRUCT force-sends ETH, breaking contracts that track balance via state",
            "Never rely on address(this).balance == storedBalance; track balance in storage",
        ),
    ],
}

_ACTION_ICONS: dict[ActionType, str] = {
    ActionType.FLASH_LOAN_BORROW: "⚡",
    ActionType.FLASH_LOAN_REPAY: "↩",
    ActionType.TOKEN_TRANSFER: "💸",
    ActionType.ETH_TRANSFER: "Ξ",
    ActionType.DEX_SWAP: "🔄",
    ActionType.STORAGE_WRITE: "✍",
    ActionType.DELEGATE_CALL: "📞",
    ActionType.SELF_DESTRUCT: "💥",
    ActionType.LIQUIDATION: "⚡",
    ActionType.GOVERNANCE_ACTION: "🗳",
    ActionType.ORACLE_READ: "📊",
    ActionType.CONTRACT_DEPLOYMENT: "🚀",
    ActionType.UNKNOWN: "?",
}

# Action types that are inherently suspicious in certain combinations
_HIGH_RISK_TYPES = {
    ActionType.FLASH_LOAN_BORROW,
    ActionType.LIQUIDATION,
    ActionType.DELEGATE_CALL,
    ActionType.SELF_DESTRUCT,
    ActionType.GOVERNANCE_ACTION,
}


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

    def to_forensic_flowchart(
        self,
        graph: IRGraph,
        scenario_config: dict[str, Any] | None = None,
    ) -> str:
        """Network-style forensic graph: address nodes with full addresses, aggregated edges."""
        cfg = scenario_config or {}

        attacker = cfg.get("attacker_address", "").lower()
        attack_contract = graph.metadata.get("tx_to", "").lower()
        target_map = {
            t["address"].lower(): t.get("name", "Protocol")
            for t in cfg.get("target_contracts", [])
        }
        token_addrs = {t.lower() for t in cfg.get("tokens", [])}

        # Collect all unique non-empty addresses in a stable, meaningful order
        seen: set[str] = set()
        addr_order: list[str] = []

        def _reg(addr: str) -> None:
            a = addr.lower() if addr else ""
            if a and a not in seen:
                seen.add(a)
                addr_order.append(a)

        for a in [attacker, attack_contract, *sorted(target_map), *sorted(token_addrs)]:
            _reg(a)
        for action in graph.actions:
            _reg(action.from_addr)
            _reg(action.to_addr)

        addr_to_id: dict[str, str] = {addr: f"N{i}" for i, addr in enumerate(addr_order)}

        # Aggregate edges: (from, to) → {action_type: count}, skip self-loops
        edge_data: dict[tuple[str, str], dict[str, int]] = {}
        for action in graph.actions:
            f = action.from_addr.lower() if action.from_addr else ""
            t = action.to_addr.lower() if action.to_addr else ""
            if f and t and f != t:
                bucket = edge_data.setdefault((f, t), {})
                bucket[action.action_type.value] = bucket.get(action.action_type.value, 0) + 1

        _EDGE_LABELS: dict[str, str] = {
            "flash_loan_borrow": "flash_loan",
            "flash_loan_repay":  "flash_repay",
            "token_transfer":    "transfer",
            "eth_transfer":      "eth",
            "dex_swap":          "dex_swap",
            "delegate_call":     "delegatecall",
            "storage_write":     "storage_write",
            "self_destruct":     "selfdestruct",
            "contract_deployment": "deploy",
            "governance_action": "governance",
            "oracle_read":       "oracle_read",
            "liquidation":       "liquidation",
        }

        # Find the most-targeted contract for each action type that has vuln annotations.
        # Used to anchor vuln/fix nodes to the relevant address in the network graph.
        from collections import Counter as _Counter
        present_types = {a.action_type for a in graph.actions}
        vuln_anchor: dict[ActionType, str] = {}
        for atype in _VULN_FIXES:
            if atype not in present_types:
                continue
            to_addrs = [
                a.to_addr.lower()
                for a in graph.get_actions_by_type(atype)
                if a.to_addr
            ]
            if to_addrs:
                most_common_addr = _Counter(to_addrs).most_common(1)[0][0]
                vuln_anchor[atype] = most_common_addr

        # Build vuln/fix node list
        vuln_fix_nodes: list[tuple[str, str, str, str, str]] = []
        # (vid, fid, vuln_text, fix_text, anchor_addr)
        vf_idx = 1
        for atype, pairs in _VULN_FIXES.items():
            if atype not in present_types:
                continue
            anchor = vuln_anchor.get(atype, attack_contract or attacker)
            for vuln_desc, fix_desc in pairs:
                vuln_fix_nodes.append((f"V{vf_idx}", f"F{vf_idx}", vuln_desc, fix_desc, anchor))
                vf_idx += 1

        lines: list[str] = ["graph LR", ""]

        lines += [
            "    classDef attacker fill:#6b0f1a,stroke:#e74c3c,color:#ffd6d6,font-weight:bold",
            "    classDef atk_ctr  fill:#3d0f1a,stroke:#e74c3c,color:#ffb3b3",
            "    classDef protocol fill:#0d2137,stroke:#2980b9,color:#aed6f1",
            "    classDef token    fill:#052e16,stroke:#27ae60,color:#a9dfbf",
            "    classDef other    fill:#1a1a2e,stroke:#566573,color:#c8d6e5",
            "    classDef vuln     fill:#4a1000,stroke:#cb4335,color:#fad7a0,stroke-dasharray:6 3",
            "    classDef fix      fill:#052e16,stroke:#27ae60,color:#a9dfbf,stroke-dasharray:3 3",
            "",
        ]

        # Address nodes — full addresses as labels
        for addr in addr_order:
            nid = addr_to_id[addr]
            if addr == attacker:
                lines.append(f'    {nid}["👤 Attacker EOA<br/>{addr}"]')
            elif addr == attack_contract:
                lines.append(f'    {nid}["⚔ Attack Contract<br/>{addr}"]')
            elif addr in target_map:
                lines.append(f'    {nid}["🏛 {target_map[addr]}<br/>{addr}"]')
            elif addr in token_addrs:
                lines.append(f'    {nid}["🪙 Token<br/>{addr}"]')
            else:
                lines.append(f'    {nid}["📋 {addr}"]')

        lines.append("")

        # Vulnerability and fix nodes
        for vid, fid, vuln_text, fix_text, _ in vuln_fix_nodes:
            lines.append(f'    {vid}["🚨 {vuln_text}"]')
            lines.append(f'    {fid}["🛡 {fix_text}"]')

        lines.append("")

        # Address-to-address edges — aggregated with counts
        for (f, t), counts in sorted(edge_data.items()):
            fid_node = addr_to_id.get(f)
            tid_node = addr_to_id.get(t)
            if not fid_node or not tid_node:
                continue
            parts = []
            for atype, cnt in sorted(counts.items()):
                short = _EDGE_LABELS.get(atype, atype)
                parts.append(short if cnt == 1 else f"{short} x{cnt}")
            lines.append(f"    {fid_node} -->|{', '.join(parts)}| {tid_node}")

        lines.append("")

        # Vulnerability edges: anchor -.-> Vn -.->|fix| Fn
        for vid, fid, _, _, anchor in vuln_fix_nodes:
            anchor_nid = addr_to_id.get(anchor, addr_to_id.get(attack_contract, addr_to_id.get(attacker)))
            if anchor_nid:
                lines.append(f"    {anchor_nid} -.->|exposes| {vid}")
            lines.append(f"    {vid} -.->|fix| {fid}")

        lines.append("")

        # Class assignments — addresses
        for addr in addr_order:
            nid = addr_to_id[addr]
            if addr == attacker:
                cls = "attacker"
            elif addr == attack_contract:
                cls = "atk_ctr"
            elif addr in target_map:
                cls = "protocol"
            elif addr in token_addrs:
                cls = "token"
            else:
                cls = "other"
            lines.append(f"    class {nid} {cls}")

        # Class assignments — vuln/fix nodes
        for vid, fid, _, _, _ in vuln_fix_nodes:
            lines.append(f"    class {vid} vuln")
            lines.append(f"    class {fid} fix")

        return "\n".join(lines)

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

    def extract_security_fixes(self, graph: IRGraph) -> list[dict[str, str]]:
        """Return a list of {vuln, fix} dicts for the actions in this graph."""
        seen: set[str] = set()
        results: list[dict[str, str]] = []
        for action in graph.actions:
            if action.action_type in _VULN_FIXES:
                for vuln, fix in _VULN_FIXES[action.action_type]:
                    if vuln not in seen:
                        seen.add(vuln)
                        results.append({"vuln": vuln, "fix": fix})
        return results

    def export_to_markdown(
        self,
        graph: IRGraph,
        output_dir: str | Path = "docs",
        scenario_config: dict[str, Any] | None = None,
        frame_count: int | None = None,
    ) -> Path:
        """Generate all diagrams and write them to a markdown file in output_dir."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        tx_short = graph.tx_hash[:10] + "..." + graph.tx_hash[-4:] if len(graph.tx_hash) > 16 else graph.tx_hash
        safe_name = graph.tx_hash[:16].replace("0x", "").lower()
        out_path = output_dir / f"diagram_{safe_name}.md"

        forensic = self.to_forensic_flowchart(graph, scenario_config)
        sequence = self.to_mermaid_sequence(graph)
        fixes = self.extract_security_fixes(graph)

        action_counts = Counter(a.action_type.value for a in graph.actions)

        lines = [
            f"# Forensic Diagram — `{tx_short}`\n",
            f"- **Transaction:** `{graph.tx_hash}`",
        ]
        if scenario_config:
            if scenario_config.get("attacker_address"):
                lines.append(f"- **Attacker:** `{scenario_config['attacker_address']}`")
            for t in scenario_config.get("target_contracts", []):
                lines.append(f"- **Target:** {t.get('name', '')} `{t.get('address', '')}`")
        if frame_count is not None:
            lines.append(f"- **EVM Frames:** {frame_count:,}")
        lines.append(f"- **Semantic Actions:** {len(graph.actions)}")
        lines.append(f"- **Edges:** {len(graph.edges)}\n")

        lines.append("### Action Breakdown\n")
        lines.append("| Type | Count |")
        lines.append("|------|-------|")
        for atype, count in action_counts.most_common():
            lines.append(f"| {atype} | {count} |")
        lines.append("")

        lines.append("## Forensic Flowchart\n")
        lines.append("```mermaid")
        lines.append(forensic)
        lines.append("```\n")

        lines.append("## Sequence Diagram")
        lines.append("```mermaid")
        lines.append(sequence)
        lines.append("```\n")

        if fixes:
            lines.append("## Security Findings\n")
            lines.append("| Vulnerability | Recommended Fix |")
            lines.append("|--------------|-----------------|")
            for f in fixes:
                lines.append(f"| {f['vuln']} | {f['fix']} |")
            lines.append("")

        out_path.write_text("\n".join(lines))
        return out_path

    def _action_label(self, action: SemanticAction) -> str:
        icon = _ACTION_ICONS.get(action.action_type, "")
        label = f"{icon} {action.action_type.value.replace('_', ' ').title()}"
        if "amount" in action.params:
            label += f"\\n{action.params['amount']}"
        return label

    def _shorten_addr(self, addr: str) -> str:
        if not addr or len(addr) < 10:
            return addr or "unknown"
        return f"{addr[:6]}..{addr[-4:]}"
