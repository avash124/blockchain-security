"""Unit tests for opcode-to-IR translation."""

import pytest

from src.acquisition.trace_fetcher import TraceFrame, TransactionTrace
from src.ir.lifter import IRLifter
from src.ir.nodes import ActionType


def _make_frame(op: str, depth: int = 1, stack: list[str] | None = None) -> TraceFrame:
    return TraceFrame(
        pc=0,
        op=op,
        gas=1000000,
        gas_cost=3,
        depth=depth,
        stack=stack or [],
    )


def _make_trace(frames: list[TraceFrame]) -> TransactionTrace:
    return TransactionTrace(
        tx_hash="0xtest",
        from_addr="0xattacker",
        to_addr="0xtarget",
        value=0,
        gas_used=100000,
        status=True,
        frames=frames,
    )


class TestIRLifter:
    def test_empty_trace(self):
        lifter = IRLifter()
        trace = _make_trace([])
        ir = lifter.lift(trace)
        assert ir.tx_hash == "0xtest"
        assert len(ir.actions) == 0

    def test_selfdestruct_detected(self):
        lifter = IRLifter()
        frames = [
            _make_frame("PUSH1"),
            _make_frame("SELFDESTRUCT", stack=["0xbeneficiary"]),
        ]
        trace = _make_trace(frames)
        ir = lifter.lift(trace)

        selfdestructs = ir.get_actions_by_type(ActionType.SELF_DESTRUCT)
        assert len(selfdestructs) == 1

    def test_sstore_detected(self):
        lifter = IRLifter()
        frames = [
            _make_frame("SSTORE", stack=["0x0", "0x1"]),
        ]
        trace = _make_trace(frames)
        ir = lifter.lift(trace)

        writes = ir.get_actions_by_type(ActionType.STORAGE_WRITE)
        assert len(writes) == 1

    def test_delegatecall_detected(self):
        lifter = IRLifter()
        frames = [
            _make_frame("DELEGATECALL", stack=["0x0", "0xtarget"]),
        ]
        trace = _make_trace(frames)
        ir = lifter.lift(trace)

        delegatecalls = ir.get_actions_by_type(ActionType.DELEGATE_CALL)
        assert len(delegatecalls) == 1

    def test_sequential_edges_created(self):
        lifter = IRLifter()
        frames = [
            _make_frame("SSTORE", stack=["0x0", "0x1"]),
            _make_frame("SELFDESTRUCT", stack=["0xbeneficiary"]),
        ]
        trace = _make_trace(frames)
        ir = lifter.lift(trace)

        assert len(ir.edges) == 1
        assert ir.edges[0][2] == "sequence"
