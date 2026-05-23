"""Unit tests for opcode-to-IR translation — lifter and edge building."""

import pytest

from src.acquisition.trace_fetcher import TraceFrame, TransactionTrace
from src.ir.lifter import IRLifter
from src.ir.nodes import ActionType


def _frame(
    op: str,
    depth: int = 1,
    stack: list[str] | None = None,
    memory: list[str] | None = None,
) -> TraceFrame:
    return TraceFrame(pc=0, op=op, gas=1_000_000, gas_cost=3, depth=depth, stack=stack or [], memory=memory)


def _call_stack(target: str = "0xdeadbeef", value: int = 0, args_length: int = 0) -> list[str]:
    return ["0x0", "0x0", hex(args_length), "0x0", hex(value), target, "0xfffff"]


def _trace(frames: list[TraceFrame]) -> TransactionTrace:
    return TransactionTrace(
        tx_hash="0xtest", from_addr="0xattacker", to_addr="0xtarget",
        value=0, gas_used=100_000, status=True, frames=frames,
    )


# ------------------------------------------------------------------
# Basic opcode lifting
# ------------------------------------------------------------------

class TestBasicLifting:
    def test_empty_trace(self):
        ir = IRLifter().lift(_trace([]))
        assert ir.tx_hash == "0xtest"
        assert len(ir.actions) == 0
        assert len(ir.edges) == 0

    def test_selfdestruct_detected(self):
        ir = IRLifter().lift(_trace([
            _frame("PUSH1"),
            _frame("SELFDESTRUCT", stack=["0xbeneficiary"]),
        ]))
        selfdestructs = ir.get_actions_by_type(ActionType.SELF_DESTRUCT)
        assert len(selfdestructs) == 1

    def test_sstore_detected(self):
        ir = IRLifter().lift(_trace([_frame("SSTORE", stack=["0x0", "0x1"])]))
        writes = ir.get_actions_by_type(ActionType.STORAGE_WRITE)
        assert len(writes) == 1

    def test_delegatecall_detected(self):
        ir = IRLifter().lift(_trace([_frame("DELEGATECALL", stack=["0x0", "0xtarget"])]))
        delegatecalls = ir.get_actions_by_type(ActionType.DELEGATE_CALL)
        assert len(delegatecalls) == 1

    def test_create2_detected(self):
        ir = IRLifter().lift(_trace([_frame("CREATE2")]))
        deploys = ir.get_actions_by_type(ActionType.CONTRACT_DEPLOYMENT)
        assert len(deploys) == 1

    def test_unmatched_opcodes_skipped(self):
        ir = IRLifter().lift(_trace([
            _frame("PUSH1"),
            _frame("ADD"),
            _frame("MSTORE"),
            _frame("JUMP"),
        ]))
        assert len(ir.actions) == 0

    def test_call_eth_transfer(self):
        stack = _call_stack(target="0xrecv", value=10**18, args_length=0)
        ir = IRLifter().lift(_trace([_frame("CALL", stack=stack)]))
        transfers = ir.get_actions_by_type(ActionType.ETH_TRANSFER)
        assert len(transfers) == 1
        assert transfers[0].params["value"] == 10**18

    def test_call_known_selector(self):
        # transfer(address,uint256) = 0xa9059cbb
        memory = ["a9059cbb" + "0" * 56]
        stack = _call_stack(target="0xtoken", value=0, args_length=36)
        ir = IRLifter().lift(_trace([_frame("CALL", stack=stack, memory=memory)]))
        token_transfers = ir.get_actions_by_type(ActionType.TOKEN_TRANSFER)
        assert len(token_transfers) == 1


# ------------------------------------------------------------------
# Trace index tracking
# ------------------------------------------------------------------

class TestTraceIndices:
    def test_trace_indices_set_correctly(self):
        ir = IRLifter().lift(_trace([
            _frame("PUSH1"),
            _frame("SSTORE", stack=["0x0", "0x1"]),
            _frame("ADD"),
            _frame("SELFDESTRUCT", stack=["0xbeneficiary"]),
        ]))
        assert len(ir.actions) == 2
        assert ir.actions[0].trace_index_start == 1  # SSTORE at index 1
        assert ir.actions[1].trace_index_start == 3  # SELFDESTRUCT at index 3

    def test_consumed_frames_advance_index(self):
        ir = IRLifter().lift(_trace([
            _frame("SSTORE", stack=["0x0", "0x1"]),
            _frame("SSTORE", stack=["0x0", "0x2"]),
        ]))
        assert len(ir.actions) == 2
        assert ir.actions[0].trace_index_start == 0
        assert ir.actions[1].trace_index_start == 1


# ------------------------------------------------------------------
# Edge building — sequential spine
# ------------------------------------------------------------------

class TestSequentialEdges:
    def test_sequential_edges_created(self):
        ir = IRLifter().lift(_trace([
            _frame("SSTORE", stack=["0x0", "0x1"]),
            _frame("SELFDESTRUCT", stack=["0xbeneficiary"]),
        ]))
        assert len(ir.edges) == 1
        assert ir.edges[0][2] == "sequence"

    def test_three_actions_two_sequence_edges(self):
        ir = IRLifter().lift(_trace([
            _frame("SSTORE", stack=["0x0", "0x1"]),
            _frame("SSTORE", stack=["0x0", "0x2"]),
            _frame("SELFDESTRUCT", stack=["0xbeneficiary"]),
        ]))
        seq_edges = [e for e in ir.edges if e[2] == "sequence"]
        assert len(seq_edges) == 2

    def test_single_action_no_edges(self):
        ir = IRLifter().lift(_trace([_frame("SSTORE", stack=["0x0", "0x1"])]))
        assert len(ir.edges) == 0


# ------------------------------------------------------------------
# Edge building — flash loan scope
# ------------------------------------------------------------------

class TestFlashLoanScopeEdges:
    def _flash_loan_trace(self) -> TransactionTrace:
        """Trace with borrow at pool, then repay to same pool."""
        borrow_mem = ["5cffe9de" + "0" * 56]  # flashLoan selector
        repay_mem = ["a9059cbb" + "0" * 56]   # transfer selector used as repay proxy
        return _trace([
            _frame("CALL", stack=_call_stack("0xpool", value=0, args_length=4), memory=["5cffe9de" + "0" * 56]),
            _frame("SSTORE", stack=["0x0", "0x1"]),
            _frame("CALL", stack=_call_stack("0xpool", value=0, args_length=4), memory=["5cffe9de" + "0" * 56]),
        ])

    def test_flash_loan_scope_edge_from_ir(self):
        """Build a graph manually to verify _detect_flash_loan_scope logic."""
        from src.ir.nodes import IRGraph, SemanticAction
        lifter = IRLifter()

        graph = IRGraph(tx_hash="0xtest")
        borrow = SemanticAction(
            action_type=ActionType.FLASH_LOAN_BORROW, depth=1,
            from_addr="0xattacker", to_addr="0xpool",
            trace_index_start=0, trace_index_end=1,
        )
        swap = SemanticAction(
            action_type=ActionType.DEX_SWAP, depth=2,
            from_addr="0xattacker", to_addr="0xdex",
            trace_index_start=1, trace_index_end=2,
        )
        repay = SemanticAction(
            action_type=ActionType.FLASH_LOAN_REPAY, depth=1,
            from_addr="0xattacker", to_addr="0xpool",
            trace_index_start=2, trace_index_end=3,
        )
        graph.add_action(borrow)
        graph.add_action(swap)
        graph.add_action(repay)

        lifter._build_edges(graph)

        fl_edges = [e for e in graph.edges if e[2] == "flash_loan_scope"]
        assert len(fl_edges) == 1
        assert fl_edges[0] == (borrow.id, repay.id, "flash_loan_scope")

    def test_no_flash_loan_scope_without_repay(self):
        from src.ir.nodes import IRGraph, SemanticAction
        lifter = IRLifter()

        graph = IRGraph(tx_hash="0xtest")
        graph.add_action(SemanticAction(
            action_type=ActionType.FLASH_LOAN_BORROW, depth=1,
            from_addr="0xattacker", to_addr="0xpool",
        ))
        lifter._build_edges(graph)

        fl_edges = [e for e in graph.edges if e[2] == "flash_loan_scope"]
        assert len(fl_edges) == 0


# ------------------------------------------------------------------
# Edge building — amount match
# ------------------------------------------------------------------

class TestAmountMatchEdges:
    def test_same_value_transfers_linked(self):
        from src.ir.nodes import IRGraph, SemanticAction
        lifter = IRLifter()

        graph = IRGraph(tx_hash="0xtest")
        t1 = SemanticAction(
            action_type=ActionType.ETH_TRANSFER, depth=1,
            from_addr="0xa", to_addr="0xb",
            params={"value": 1000}, trace_index_start=0,
        )
        t2 = SemanticAction(
            action_type=ActionType.ETH_TRANSFER, depth=1,
            from_addr="0xb", to_addr="0xc",
            params={"value": 1000}, trace_index_start=1,
        )
        graph.add_action(t1)
        graph.add_action(t2)
        lifter._build_edges(graph)

        amount_edges = [e for e in graph.edges if e[2] == "amount_match"]
        assert len(amount_edges) == 1

    def test_different_values_not_linked(self):
        from src.ir.nodes import IRGraph, SemanticAction
        lifter = IRLifter()

        graph = IRGraph(tx_hash="0xtest")
        graph.add_action(SemanticAction(
            action_type=ActionType.ETH_TRANSFER, depth=1,
            from_addr="0xa", to_addr="0xb",
            params={"value": 1000}, trace_index_start=0,
        ))
        graph.add_action(SemanticAction(
            action_type=ActionType.ETH_TRANSFER, depth=1,
            from_addr="0xb", to_addr="0xc",
            params={"value": 2000}, trace_index_start=1,
        ))
        lifter._build_edges(graph)

        amount_edges = [e for e in graph.edges if e[2] == "amount_match"]
        assert len(amount_edges) == 0

    def test_zero_value_not_linked(self):
        from src.ir.nodes import IRGraph, SemanticAction
        lifter = IRLifter()

        graph = IRGraph(tx_hash="0xtest")
        graph.add_action(SemanticAction(
            action_type=ActionType.ETH_TRANSFER, depth=1,
            from_addr="0xa", to_addr="0xb",
            params={"value": 0}, trace_index_start=0,
        ))
        graph.add_action(SemanticAction(
            action_type=ActionType.ETH_TRANSFER, depth=1,
            from_addr="0xb", to_addr="0xc",
            params={"value": 0}, trace_index_start=1,
        ))
        lifter._build_edges(graph)

        amount_edges = [e for e in graph.edges if e[2] == "amount_match"]
        assert len(amount_edges) == 0


# ------------------------------------------------------------------
# Edge building — storage dependency
# ------------------------------------------------------------------

class TestStorageDepEdges:
    def test_sstore_then_sload_same_slot(self):
        from src.ir.nodes import IRGraph, SemanticAction
        lifter = IRLifter()

        graph = IRGraph(tx_hash="0xtest")
        write = SemanticAction(
            action_type=ActionType.STORAGE_WRITE, depth=1,
            from_addr="", to_addr="", params={"slot": "0x5"},
            trace_index_start=0,
        )
        read = SemanticAction(
            action_type=ActionType.STORAGE_READ, depth=1,
            from_addr="", to_addr="", params={"slot": "0x5"},
            trace_index_start=1,
        )
        graph.add_action(write)
        graph.add_action(read)
        lifter._build_edges(graph)

        dep_edges = [e for e in graph.edges if e[2] == "storage_dep"]
        assert len(dep_edges) == 1
        assert dep_edges[0] == (write.id, read.id, "storage_dep")

    def test_different_slots_not_linked(self):
        from src.ir.nodes import IRGraph, SemanticAction
        lifter = IRLifter()

        graph = IRGraph(tx_hash="0xtest")
        graph.add_action(SemanticAction(
            action_type=ActionType.STORAGE_WRITE, depth=1,
            from_addr="", to_addr="", params={"slot": "0x5"},
            trace_index_start=0,
        ))
        graph.add_action(SemanticAction(
            action_type=ActionType.STORAGE_READ, depth=1,
            from_addr="", to_addr="", params={"slot": "0x6"},
            trace_index_start=1,
        ))
        lifter._build_edges(graph)

        dep_edges = [e for e in graph.edges if e[2] == "storage_dep"]
        assert len(dep_edges) == 0


# ------------------------------------------------------------------
# Mixed trace — full pipeline
# ------------------------------------------------------------------

class TestFullPipeline:
    def test_mixed_opcodes_produces_correct_action_counts(self):
        frames = [
            _frame("PUSH1"),
            _frame("SSTORE", stack=["0x1", "0x2"]),
            _frame("ADD"),
            _frame("CALL", stack=_call_stack("0xrecv", value=10**18, args_length=0)),
            _frame("MSTORE"),
            _frame("SELFDESTRUCT", stack=["0xben"]),
        ]
        ir = IRLifter().lift(_trace(frames))
        assert len(ir.get_actions_by_type(ActionType.STORAGE_WRITE)) == 1
        assert len(ir.get_actions_by_type(ActionType.ETH_TRANSFER)) == 1
        assert len(ir.get_actions_by_type(ActionType.SELF_DESTRUCT)) == 1
        assert len(ir.actions) == 3
        seq_edges = [e for e in ir.edges if e[2] == "sequence"]
        assert len(seq_edges) == 2
