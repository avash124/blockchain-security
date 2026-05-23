"""Unit tests for IRVisualizer — Mermaid flowchart, sequence diagram, Sankey."""

from src.ir.nodes import ActionType, IRGraph, SemanticAction
from src.ir.visualizer import IRVisualizer


def _graph_with_actions(*specs: tuple[ActionType, str, str]) -> IRGraph:
    """Build an IRGraph from (action_type, from_addr, to_addr) tuples."""
    g = IRGraph(tx_hash="0xtest")
    for i, (atype, from_a, to_a) in enumerate(specs):
        g.add_action(SemanticAction(
            action_type=atype, depth=1, from_addr=from_a, to_addr=to_a,
            trace_index_start=i,
        ))
    return g


# ------------------------------------------------------------------
# to_mermaid_flowchart
# ------------------------------------------------------------------

class TestMermaidFlowchart:
    def test_empty_graph(self):
        viz = IRVisualizer()
        g = IRGraph(tx_hash="0xtest")
        mermaid = viz.to_mermaid_flowchart(g)
        assert mermaid.startswith("graph TD")
        assert mermaid.strip().count("\n") == 0

    def test_single_action(self):
        viz = IRVisualizer()
        g = _graph_with_actions((ActionType.ETH_TRANSFER, "0xa", "0xb"))
        mermaid = viz.to_mermaid_flowchart(g)
        assert "graph TD" in mermaid
        assert "eth_transfer_0" in mermaid
        assert "Eth Transfer" in mermaid

    def test_multiple_actions_with_edges(self):
        viz = IRVisualizer()
        g = _graph_with_actions(
            (ActionType.FLASH_LOAN_BORROW, "0xa", "0xpool"),
            (ActionType.DEX_SWAP, "0xa", "0xdex"),
            (ActionType.FLASH_LOAN_REPAY, "0xa", "0xpool"),
        )
        g.add_edge("flash_loan_borrow_0", "dex_swap_1", "sequence")
        g.add_edge("dex_swap_1", "flash_loan_repay_2", "sequence")
        mermaid = viz.to_mermaid_flowchart(g)
        assert "flash_loan_borrow_0" in mermaid
        assert "dex_swap_1" in mermaid
        assert "flash_loan_repay_2" in mermaid
        assert "-->|sequence|" in mermaid

    def test_edge_without_label(self):
        viz = IRVisualizer()
        g = _graph_with_actions(
            (ActionType.ETH_TRANSFER, "0xa", "0xb"),
            (ActionType.STORAGE_WRITE, "0xa", "0xb"),
        )
        g.add_edge("eth_transfer_0", "storage_write_1", "")
        mermaid = viz.to_mermaid_flowchart(g)
        assert "-->" in mermaid
        assert "||" not in mermaid

    def test_action_label_includes_amount(self):
        viz = IRVisualizer()
        g = IRGraph(tx_hash="0xtest")
        g.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER, depth=1,
            from_addr="0xa", to_addr="0xb",
            params={"amount": "1000 DAI"}, trace_index_start=0,
        ))
        mermaid = viz.to_mermaid_flowchart(g)
        assert "1000 DAI" in mermaid


# ------------------------------------------------------------------
# to_mermaid_sequence
# ------------------------------------------------------------------

class TestMermaidSequence:
    def test_empty_graph(self):
        viz = IRVisualizer()
        g = IRGraph(tx_hash="0xtest")
        seq = viz.to_mermaid_sequence(g)
        assert seq.startswith("sequenceDiagram")

    def test_participants_registered(self):
        viz = IRVisualizer()
        g = _graph_with_actions(
            (ActionType.ETH_TRANSFER, "0xaaaaaa1111111111111111111111111111111111", "0xbbbbbb2222222222222222222222222222222222"),
        )
        seq = viz.to_mermaid_sequence(g)
        assert "participant" in seq
        assert "0xaaaa" in seq
        assert "0xbbbb" in seq

    def test_action_type_in_message(self):
        viz = IRVisualizer()
        g = _graph_with_actions((ActionType.DEX_SWAP, "0xa" * 20, "0xb" * 20))
        seq = viz.to_mermaid_sequence(g)
        assert "dex_swap" in seq

    def test_multiple_actions_produce_multiple_messages(self):
        viz = IRVisualizer()
        g = _graph_with_actions(
            (ActionType.ETH_TRANSFER, "0xa" * 20, "0xb" * 20),
            (ActionType.TOKEN_TRANSFER, "0xb" * 20, "0xc" * 20),
        )
        seq = viz.to_mermaid_sequence(g)
        assert "eth_transfer" in seq
        assert "token_transfer" in seq


# ------------------------------------------------------------------
# to_sankey_data
# ------------------------------------------------------------------

class TestSankeyData:
    def test_empty_graph(self):
        viz = IRVisualizer()
        g = IRGraph(tx_hash="0xtest")
        assert viz.to_sankey_data(g) == []

    def test_token_transfers_only(self):
        viz = IRVisualizer()
        g = IRGraph(tx_hash="0xtest")
        g.add_action(SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER, depth=1,
            from_addr="0xaaaaaa1111111111111111111111111111111111",
            to_addr="0xbbbbbb2222222222222222222222222222222222",
            params={"amount": 1000, "token": "DAI"},
        ))
        g.add_action(SemanticAction(
            action_type=ActionType.ETH_TRANSFER, depth=1,
            from_addr="0xa", to_addr="0xb",
            params={"value": 500},
        ))
        flows = viz.to_sankey_data(g)
        assert len(flows) == 1  # only TOKEN_TRANSFER, not ETH_TRANSFER
        assert flows[0]["value"] == 1000
        assert flows[0]["token"] == "DAI"

    def test_multiple_flows(self):
        viz = IRVisualizer()
        g = IRGraph(tx_hash="0xtest")
        for i in range(3):
            g.add_action(SemanticAction(
                action_type=ActionType.TOKEN_TRANSFER, depth=1,
                from_addr=f"0x{i}aaa", to_addr=f"0x{i}bbb",
                params={"amount": 100 * (i + 1), "token": "USDC"},
            ))
        flows = viz.to_sankey_data(g)
        assert len(flows) == 3
        assert flows[0]["value"] == 100
        assert flows[2]["value"] == 300


# ------------------------------------------------------------------
# _shorten_addr
# ------------------------------------------------------------------

class TestShortenAddr:
    def test_normal_address(self):
        viz = IRVisualizer()
        assert viz._shorten_addr("0xaabbccddee1122334455") == "0xaabb..4455"

    def test_short_address(self):
        viz = IRVisualizer()
        assert viz._shorten_addr("0xab") == "0xab"

    def test_empty_address(self):
        viz = IRVisualizer()
        assert viz._shorten_addr("") == "unknown"

    def test_none_address(self):
        viz = IRVisualizer()
        assert viz._shorten_addr(None) == "unknown"
