"""Converts IR graphs to Mermaid diagrams for report embedding."""

from __future__ import annotations

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
        """Rich forensic Mermaid flowchart: attack path + vulnerability + fix annotations."""
        cfg = scenario_config or {}
        lines: list[str] = ["graph TD"]
        lines.append("")

        # ── Style classes ──────────────────────────────────────────────
        lines += [
            "    classDef attacker fill:#6b0f1a,stroke:#e74c3c,color:#ffd6d6,font-weight:bold",
            "    classDef protocol fill:#0d2137,stroke:#2980b9,color:#aed6f1",
            "    classDef flash   fill:#2c0f40,stroke:#8e44ad,color:#dab8f3",
            "    classDef step    fill:#0f1f2e,stroke:#566573,color:#c8d6e5",
            "    classDef vuln    fill:#4a1000,stroke:#cb4335,color:#fad7a0,stroke-dasharray:6 3",
            "    classDef fix     fill:#052e16,stroke:#27ae60,color:#a9dfbf,stroke-dasharray:3 3",
            "    classDef profit  fill:#3d2c00,stroke:#d4ac0d,color:#fef9e7,font-weight:bold",
            "    classDef xfer    fill:#0a2618,stroke:#27ae60,color:#abebc6",
            "",
        ]

        # ── Actors ─────────────────────────────────────────────────────
        attacker = cfg.get("attacker_address", "")
        atk_short = self._shorten_addr(attacker) if attacker else "Attacker"
        lines.append(f'    ATTKR["🔴 Attacker<br/>{atk_short}"]')

        targets = cfg.get("target_contracts", [])
        proto_ids: list[str] = []
        for i, t in enumerate(targets):
            pid = f"PROTO{i}"
            proto_ids.append(pid)
            name = t.get("name", f"Protocol {i}")
            addr = self._shorten_addr(t.get("address", ""))
            lines.append(f'    {pid}["🏛 {name}<br/>{addr}"]')
        lines.append("")

        # ── Derive attack phases from IR actions ───────────────────────
        present = {a.action_type for a in graph.actions}
        has_fl_borrow = ActionType.FLASH_LOAN_BORROW in present
        has_fl_repay = ActionType.FLASH_LOAN_REPAY in present
        has_liq = ActionType.LIQUIDATION in present
        has_delegate = ActionType.DELEGATE_CALL in present
        has_swap = ActionType.DEX_SWAP in present
        has_governance = ActionType.GOVERNANCE_ACTION in present
        has_selfdestruct = ActionType.SELF_DESTRUCT in present
        has_transfers = ActionType.TOKEN_TRANSFER in present or ActionType.ETH_TRANSFER in present

        steps: list[tuple[str, str, str]] = []  # (node_id, label, class)
        step_num = 1

        if has_fl_borrow:
            fl_actions = graph.get_actions_by_type(ActionType.FLASH_LOAN_BORROW)
            amount_hint = ""
            if fl_actions and "value" in fl_actions[0].params:
                amount_hint = f"<br/>{fl_actions[0].params['value']:,} wei"
            steps.append((
                f"S{step_num}",
                f"⚡ {step_num}. Flash Loan Borrow{amount_hint}",
                "flash",
            ))
            step_num += 1

        if has_swap:
            swap_actions = graph.get_actions_by_type(ActionType.DEX_SWAP)
            steps.append((
                f"S{step_num}",
                f"🔄 {step_num}. DEX Swap × {len(swap_actions)}<br/>⚠ spot-price oracle risk",
                "vuln",
            ))
            step_num += 1

        if has_delegate:
            dc_actions = graph.get_actions_by_type(ActionType.DELEGATE_CALL)
            targets_str = ", ".join(
                self._shorten_addr(a.to_addr) for a in dc_actions[:2] if a.to_addr
            )
            steps.append((
                f"S{step_num}",
                f"📞 {step_num}. DELEGATECALL<br/>⚠ into: {targets_str}",
                "vuln",
            ))
            step_num += 1

        if has_governance:
            steps.append((
                f"S{step_num}",
                f"🗳 {step_num}. Governance Action<br/>⚠ flash-borrowed voting power",
                "vuln",
            ))
            step_num += 1

        if has_liq:
            liq_actions = graph.get_actions_by_type(ActionType.LIQUIDATION)
            steps.append((
                f"S{step_num}",
                f"⚡ {step_num}. Liquidation × {len(liq_actions)}<br/>⚠ self-liquidation / bonus drain",
                "vuln",
            ))
            step_num += 1

        if has_selfdestruct:
            steps.append((
                f"S{step_num}",
                f"💥 {step_num}. SELFDESTRUCT<br/>⚠ force-ETH injection",
                "vuln",
            ))
            step_num += 1

        # Generic transfers if nothing more specific
        if has_transfers and not steps:
            xfer_count = len(graph.get_actions_by_type(ActionType.TOKEN_TRANSFER))
            xfer_count += len(graph.get_actions_by_type(ActionType.ETH_TRANSFER))
            steps.append((f"S{step_num}", f"💸 {step_num}. Token/ETH Transfer × {xfer_count}", "xfer"))
            step_num += 1

        if has_fl_repay:
            steps.append((f"S{step_num}", f"↩ {step_num}. Flash Loan Repay", "flash"))
            step_num += 1

        steps.append(("PROFIT", "💰 Profit Extracted", "profit"))

        # Emit step nodes
        for node_id, label, cls in steps:
            lines.append(f'    {node_id}["{label}"]')
        lines.append("")

        # ── Vulnerability & Fix nodes ──────────────────────────────────
        vuln_fix_pairs: list[tuple[str, str, str, str]] = []  # (vid, fid, vuln_text, fix_text)
        vf_index = 1
        for action_type in present:
            if action_type in _VULN_FIXES:
                for vuln_desc, fix_desc in _VULN_FIXES[action_type]:
                    vid = f"V{vf_index}"
                    fid = f"F{vf_index}"
                    vuln_fix_pairs.append((vid, fid, vuln_desc, fix_desc))
                    vf_index += 1

        for vid, fid, vuln_text, fix_text in vuln_fix_pairs:
            lines.append(f'    {vid}["🚨 {vuln_text}"]')
            lines.append(f'    {fid}["🛡 {fix_text}"]')
        lines.append("")

        # ── Edges ─────────────────────────────────────────────────────
        lines.append("    %% Attack flow")
        lines.append(f"    ATTKR -->|initiates| {steps[0][0]}")

        for i in range(len(steps) - 1):
            cur_id = steps[i][0]
            nxt_id = steps[i + 1][0]
            lines.append(f"    {cur_id} --> {nxt_id}")

        # Connect to protocol targets
        for pid in proto_ids:
            # Attach the first step to the protocol target
            if steps:
                lines.append(f"    {steps[0][0]} -->|targets| {pid}")

        lines.append("")
        lines.append("    %% Vulnerability links")
        for vid, fid, _, _ in vuln_fix_pairs:
            lines.append(f"    {vid} -.->|fix| {fid}")

        # Link vuln nodes back to relevant steps (heuristic: pair by order)
        vuln_steps = [s for s in steps if s[2] == "vuln"]
        for i, (vid, fid, _, _) in enumerate(vuln_fix_pairs):
            if i < len(vuln_steps):
                step_id = vuln_steps[i][0]
                lines.append(f"    {step_id} -.->|exposes| {vid}")

        lines.append("")
        lines.append("    %% Class assignments")
        lines.append("    class ATTKR attacker")
        lines.append("    class PROFIT profit")
        for pid in proto_ids:
            lines.append(f"    class {pid} protocol")
        for node_id, _, cls in steps:
            if cls != "profit":
                lines.append(f"    class {node_id} {cls}")
        for vid, fid, _, _ in vuln_fix_pairs:
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
