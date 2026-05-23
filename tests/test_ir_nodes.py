"""Unit tests for IR graph dataclasses — SemanticAction, IRGraph."""

from src.ir.nodes import ActionType, IRGraph, SemanticAction


# ------------------------------------------------------------------
# SemanticAction
# ------------------------------------------------------------------

class TestSemanticAction:
    def test_id_format(self):
        a = SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER, depth=1,
            from_addr="0xa", to_addr="0xb", trace_index_start=42,
        )
        assert a.id == "token_transfer_42"

    def test_id_changes_with_index(self):
        a = SemanticAction(
            action_type=ActionType.DEX_SWAP, depth=1,
            from_addr="0xa", to_addr="0xb", trace_index_start=0,
        )
        b = SemanticAction(
            action_type=ActionType.DEX_SWAP, depth=1,
            from_addr="0xa", to_addr="0xb", trace_index_start=99,
        )
        assert a.id != b.id

    def test_default_params_empty(self):
        a = SemanticAction(action_type=ActionType.UNKNOWN, depth=0, from_addr="", to_addr="")
        assert a.params == {}
        assert a.children == []
        assert a.trace_index_start == 0
        assert a.trace_index_end == 0

    def test_children_are_independent(self):
        a = SemanticAction(action_type=ActionType.UNKNOWN, depth=0, from_addr="", to_addr="")
        b = SemanticAction(action_type=ActionType.UNKNOWN, depth=0, from_addr="", to_addr="")
        a.children.append(b)
        assert len(a.children) == 1
        assert len(b.children) == 0


# ------------------------------------------------------------------
# IRGraph
# ------------------------------------------------------------------

class TestIRGraph:
    def test_add_action(self):
        g = IRGraph(tx_hash="0xabc")
        a = SemanticAction(action_type=ActionType.ETH_TRANSFER, depth=1, from_addr="0xa", to_addr="0xb")
        g.add_action(a)
        assert len(g.actions) == 1
        assert g.actions[0] is a

    def test_add_edge(self):
        g = IRGraph(tx_hash="0xabc")
        g.add_edge("a", "b", "sequence")
        assert len(g.edges) == 1
        assert g.edges[0] == ("a", "b", "sequence")

    def test_add_edge_default_label(self):
        g = IRGraph(tx_hash="0xabc")
        g.add_edge("x", "y")
        assert g.edges[0] == ("x", "y", "")

    def test_get_actions_by_type_filters_correctly(self):
        g = IRGraph(tx_hash="0xabc")
        g.add_action(SemanticAction(action_type=ActionType.ETH_TRANSFER, depth=1, from_addr="0xa", to_addr="0xb"))
        g.add_action(SemanticAction(action_type=ActionType.DEX_SWAP, depth=1, from_addr="0xa", to_addr="0xb"))
        g.add_action(SemanticAction(action_type=ActionType.ETH_TRANSFER, depth=2, from_addr="0xa", to_addr="0xc"))
        assert len(g.get_actions_by_type(ActionType.ETH_TRANSFER)) == 2
        assert len(g.get_actions_by_type(ActionType.DEX_SWAP)) == 1
        assert len(g.get_actions_by_type(ActionType.SELF_DESTRUCT)) == 0

    def test_to_dict_structure(self):
        g = IRGraph(tx_hash="0xdeadbeef")
        a = SemanticAction(
            action_type=ActionType.TOKEN_TRANSFER, depth=1,
            from_addr="0xsender", to_addr="0xrecv",
            params={"value": 100}, trace_index_start=5,
        )
        g.add_action(a)
        g.add_edge(a.id, "other_0", "sequence")

        d = g.to_dict()
        assert d["tx_hash"] == "0xdeadbeef"
        assert len(d["actions"]) == 1
        assert d["actions"][0]["id"] == "token_transfer_5"
        assert d["actions"][0]["type"] == "token_transfer"
        assert d["actions"][0]["from"] == "0xsender"
        assert d["actions"][0]["to"] == "0xrecv"
        assert d["actions"][0]["params"]["value"] == 100
        assert len(d["edges"]) == 1
        assert d["edges"][0]["label"] == "sequence"

    def test_to_dict_empty_graph(self):
        g = IRGraph(tx_hash="0x0")
        d = g.to_dict()
        assert d["tx_hash"] == "0x0"
        assert d["actions"] == []
        assert d["edges"] == []

    def test_metadata_preserved(self):
        g = IRGraph(tx_hash="0xabc", metadata={"block": 12345, "chain": "mainnet"})
        assert g.metadata["block"] == 12345
        assert g.metadata["chain"] == "mainnet"
