"""Unit tests for PatternMatcher — opcode-to-action pattern matching."""

import pytest

from src.acquisition.trace_fetcher import TraceFrame
from src.ir.nodes import ActionType
from src.ir.patterns import PatternMatcher, _parse_stack_int, _normalize_address, KNOWN_SELECTORS


def _frame(
    op: str,
    depth: int = 1,
    stack: list[str] | None = None,
    memory: list[str] | None = None,
) -> TraceFrame:
    return TraceFrame(pc=0, op=op, gas=1_000_000, gas_cost=3, depth=depth, stack=stack or [], memory=memory)


def _call_stack(target: str = "0xdeadbeef", value: int = 0, args_length: int = 0) -> list[str]:
    """Build a 7-element CALL stack: gas, addr, value, argsOffset, argsLength, retOffset, retLength."""
    return [
        "0x0",          # retLength
        "0x0",          # retOffset
        hex(args_length),  # argsLength
        "0x0",          # argsOffset (offset 0)
        hex(value),     # value
        target,         # address
        "0xfffff",      # gas
    ]


# ------------------------------------------------------------------
# _parse_stack_int
# ------------------------------------------------------------------

class TestParseStackInt:
    def test_hex_with_prefix(self):
        assert _parse_stack_int("0xff") == 255

    def test_hex_without_prefix(self):
        assert _parse_stack_int("ff") == 255

    def test_zero(self):
        assert _parse_stack_int("0x0") == 0

    def test_empty_string(self):
        assert _parse_stack_int("") == 0

    def test_invalid_hex(self):
        assert _parse_stack_int("not_hex") == 0

    def test_large_value(self):
        assert _parse_stack_int("0xDE0B6B3A7640000") == 10**18


# ------------------------------------------------------------------
# _normalize_address
# ------------------------------------------------------------------

class TestNormalizeAddress:
    def test_full_32_byte_word(self):
        raw = "0x000000000000000000000000dEADbEEf00000000000000000000000000000001"
        assert _normalize_address(raw) == "0xdeadbeef00000000000000000000000000000001"

    def test_short_address(self):
        assert _normalize_address("0xabcd").endswith("abcd")

    def test_lowercase(self):
        assert _normalize_address("0xABCDEF") == _normalize_address("0xabcdef")


# ------------------------------------------------------------------
# PatternMatcher.match — SELFDESTRUCT
# ------------------------------------------------------------------

class TestMatchSelfdestruct:
    def test_selfdestruct_produces_action(self):
        pm = PatternMatcher()
        frame = _frame("SELFDESTRUCT", stack=["0xbeneficiary"])
        result = pm.match(frame, [frame], 0)
        assert result is not None
        action, consumed = result
        assert action.action_type == ActionType.SELF_DESTRUCT
        assert consumed == 1
        assert action.params["beneficiary"] == "0xbeneficiary"

    def test_selfdestruct_empty_stack(self):
        pm = PatternMatcher()
        frame = _frame("SELFDESTRUCT", stack=[])
        result = pm.match(frame, [frame], 0)
        assert result is not None
        action, _ = result
        assert action.params["beneficiary"] == "0x0"


# ------------------------------------------------------------------
# PatternMatcher.match — SSTORE
# ------------------------------------------------------------------

class TestMatchSstore:
    def test_sstore_produces_storage_write(self):
        pm = PatternMatcher()
        frame = _frame("SSTORE", stack=["0xvalue", "0xslot"])
        result = pm.match(frame, [frame], 0)
        assert result is not None
        action, consumed = result
        assert action.action_type == ActionType.STORAGE_WRITE
        assert consumed == 1
        assert action.params["slot"] == "0xslot"
        assert action.params["value"] == "0xvalue"

    def test_sstore_single_stack_item(self):
        pm = PatternMatcher()
        frame = _frame("SSTORE", stack=["0xslot"])
        result = pm.match(frame, [frame], 0)
        action, _ = result
        assert action.params["slot"] == "0xslot"
        assert action.params["value"] == "0x0"


# ------------------------------------------------------------------
# PatternMatcher.match — DELEGATECALL
# ------------------------------------------------------------------

class TestMatchDelegatecall:
    def test_delegatecall_produces_action(self):
        pm = PatternMatcher()
        frame = _frame("DELEGATECALL", stack=["0x0", "0xdeadbeef"])
        result = pm.match(frame, [frame], 0)
        assert result is not None
        action, consumed = result
        assert action.action_type == ActionType.DELEGATE_CALL
        assert consumed == 1

    def test_delegatecall_short_stack(self):
        pm = PatternMatcher()
        frame = _frame("DELEGATECALL", stack=[])
        result = pm.match(frame, [frame], 0)
        assert result is not None
        action, _ = result
        assert action.to_addr == "0x0"


# ------------------------------------------------------------------
# PatternMatcher.match — CREATE2
# ------------------------------------------------------------------

class TestMatchCreate2:
    def test_create2_produces_deployment(self):
        pm = PatternMatcher()
        frame = _frame("CREATE2")
        result = pm.match(frame, [frame], 0)
        assert result is not None
        action, consumed = result
        assert action.action_type == ActionType.CONTRACT_DEPLOYMENT
        assert action.params["opcode"] == "CREATE2"
        assert consumed == 1


# ------------------------------------------------------------------
# PatternMatcher.match — CALL
# ------------------------------------------------------------------

class TestMatchCall:
    def test_eth_transfer_no_calldata(self):
        pm = PatternMatcher()
        stack = _call_stack(target="0xrecipient", value=10**18, args_length=0)
        frame = _frame("CALL", stack=stack)
        result = pm.match(frame, [frame], 0)
        assert result is not None
        action, consumed = result
        assert action.action_type == ActionType.ETH_TRANSFER
        assert action.params["value"] == 10**18
        assert consumed == 1

    def test_known_selector_token_transfer(self):
        pm = PatternMatcher()
        # Memory: 0xa9059cbb (transfer) at offset 0, padded to 32 bytes
        memory_chunk = "a9059cbb" + "0" * 56  # 64 hex chars = 32 bytes
        stack = _call_stack(target="0xtoken", value=0, args_length=36)
        frame = _frame("CALL", stack=stack, memory=[memory_chunk])
        result = pm.match(frame, [frame], 0)
        assert result is not None
        action, _ = result
        assert action.action_type == ActionType.TOKEN_TRANSFER
        assert action.params["selector"] == "0xa9059cbb"
        assert action.params["function"] == "transfer"

    def test_known_selector_dex_swap(self):
        pm = PatternMatcher()
        memory_chunk = "022c0d9f" + "0" * 56
        stack = _call_stack(target="0xpool", value=0, args_length=4)
        frame = _frame("CALL", stack=stack, memory=[memory_chunk])
        result = pm.match(frame, [frame], 0)
        action, _ = result
        assert action.action_type == ActionType.DEX_SWAP

    def test_unknown_selector_with_value_is_eth_transfer(self):
        pm = PatternMatcher()
        memory_chunk = "deadbeef" + "0" * 56
        stack = _call_stack(target="0xcontract", value=1000, args_length=4)
        frame = _frame("CALL", stack=stack, memory=[memory_chunk])
        result = pm.match(frame, [frame], 0)
        action, _ = result
        assert action.action_type == ActionType.ETH_TRANSFER
        assert action.params["value"] == 1000

    def test_unknown_selector_no_value_returns_none(self):
        pm = PatternMatcher()
        memory_chunk = "deadbeef" + "0" * 56
        stack = _call_stack(target="0xcontract", value=0, args_length=4)
        frame = _frame("CALL", stack=stack, memory=[memory_chunk])
        result = pm.match(frame, [frame], 0)
        assert result is None

    def test_call_insufficient_stack_returns_none(self):
        pm = PatternMatcher()
        frame = _frame("CALL", stack=["0x1", "0x2"])
        result = pm.match(frame, [frame], 0)
        assert result is None

    def test_no_memory_short_calldata_returns_eth_transfer(self):
        pm = PatternMatcher()
        stack = _call_stack(target="0xrecv", value=0, args_length=2)
        frame = _frame("CALL", stack=stack, memory=None)
        result = pm.match(frame, [frame], 0)
        assert result is None


# ------------------------------------------------------------------
# PatternMatcher — unrecognized opcodes
# ------------------------------------------------------------------

class TestUnrecognizedOps:
    def test_add_returns_none(self):
        pm = PatternMatcher()
        assert pm.match(_frame("ADD"), [_frame("ADD")], 0) is None

    def test_push1_returns_none(self):
        pm = PatternMatcher()
        assert pm.match(_frame("PUSH1"), [_frame("PUSH1")], 0) is None

    def test_staticcall_returns_none(self):
        pm = PatternMatcher()
        assert pm.match(_frame("STATICCALL"), [_frame("STATICCALL")], 0) is None


# ------------------------------------------------------------------
# PatternMatcher — custom patterns
# ------------------------------------------------------------------

class TestCustomPatterns:
    def test_custom_selector_override(self):
        pm = PatternMatcher(custom_patterns=[{
            "selector": "0xdeadbeef",
            "name": "myCustomFn",
            "action_type": ActionType.LIQUIDATION,
        }])
        memory_chunk = "deadbeef" + "0" * 56
        stack = _call_stack(target="0xcontract", value=0, args_length=4)
        frame = _frame("CALL", stack=stack, memory=[memory_chunk])
        result = pm.match(frame, [frame], 0)
        assert result is not None
        action, _ = result
        assert action.action_type == ActionType.LIQUIDATION
        assert action.params["function"] == "myCustomFn"


# ------------------------------------------------------------------
# _extract_selector
# ------------------------------------------------------------------

class TestExtractSelector:
    def test_extracts_from_memory(self):
        pm = PatternMatcher()
        memory = ["a9059cbb" + "0" * 56]
        assert pm._extract_selector(memory, 0, 4) == "0xa9059cbb"

    def test_none_when_no_memory(self):
        pm = PatternMatcher()
        assert pm._extract_selector(None, 0, 4) is None

    def test_none_when_args_too_short(self):
        pm = PatternMatcher()
        assert pm._extract_selector(["00" * 32], 0, 3) is None

    def test_offset_into_memory(self):
        pm = PatternMatcher()
        # First 32 bytes are zeros, selector starts at byte 32
        memory = ["00" * 32, "a9059cbb" + "0" * 56]
        assert pm._extract_selector(memory, 32, 4) == "0xa9059cbb"

    def test_none_when_memory_too_short(self):
        pm = PatternMatcher()
        memory = ["abcd"]
        assert pm._extract_selector(memory, 100, 4) is None
