# Handoff: Write Unit Tests for `BlastRadiusAnalyzer` and `PrecursorAnalyzer`

You are writing pytest unit tests for two agent classes in a blockchain forensics tool.
The codebase lives at `src/`. Read the files listed below before writing anything.

---

## Files to Read First

- `src/agents/blast_radius.py` — `BlastRadiusAnalyzer`
- `src/agents/precursor.py` — `PrecursorAnalyzer`
- `src/ir/nodes.py` — `IRGraph`, `SemanticAction`, `ActionType`
- `src/verifier/state_diff.py` — `StateDiff`, `BalanceChange`, `StorageChange`
- `src/llm/client.py` — `LLMClient`, `LLMResponse`
- `tests/test_predicates.py` — reference for how this project mocks and structures tests
- `tests/test_state_diff.py` — reference for how RPC calls are patched

Write tests in `tests/test_blast_radius.py` and `tests/test_precursor.py`.

---

## Constraints and Patterns to Follow

- Use `unittest.mock.patch` and `MagicMock` — no real network calls, no real LLM calls
- Mirror the class-per-feature structure in `test_predicates.py`
- All tests must pass with `python -m pytest` and no env vars set
- Do not use `pytest-mock` — the project only uses stdlib `unittest.mock`

---

## `BlastRadiusAnalyzer` — What to Test

The class has one public method `analyze(ir_graph, state_diff, scenario_config) -> BlastRadiusReport`
and four private helpers. Test the helpers directly where possible; test `analyze()` by mocking
`LLMClient.complete`.

### `_find_shared_dependencies(ir_graph)`

- Returns unique `to_addr` values for actions whose `action_type` is in `_DEPENDENCY_ACTION_TYPES`
  (`ORACLE_READ`, `DEX_SWAP`, `FLASH_LOAN_BORROW`, `FLASH_LOAN_REPAY`, `TOKEN_TRANSFER`,
  `LIQUIDATION`, `GOVERNANCE_ACTION`)
- Also collects `to_addr` for `STORAGE_READ` / `STORAGE_WRITE` actions
- Excludes the `to_addr` of `ir_graph.actions[0]` (the root contract)
- Returns empty list when graph has no actions
- Does not return duplicates

### `_estimate_cascading_loss(state_diff)`

- Sums `abs(delta) / 1e18 * 1.0` for all `BalanceChange` where `delta < 0`
- Ignores zero and positive deltas
- Returns `0.0` for empty `StateDiff`

### `_compute_primary_loss(state_diff, scenario_config)`

- Uses `scenario_config["token_prices"]` dict (token address → USD float) when present
- Falls back to `1.0` per unit when token not in price map
- Only sums losses (`delta < 0`), ignores gains
- Returns `0.0` with no losses

### `analyze()` end-to-end (mocked LLM)

Mock `LLMClient.complete` to return a valid `LLMResponse` whose `.content` is a JSON string
matching the blast radius schema:

```json
{
  "affected_protocols": [
    {
      "name": "Aave",
      "address": "0xabc",
      "relationship": "oracle dependency",
      "risk_level": "high",
      "details": ""
    }
  ],
  "cascading_risks": ["risk1"],
  "recommendations": ["rec1"]
}
```

- Assert `BlastRadiusReport.primary_loss_usd` is correct
- Assert `affected_protocols` is populated with the right fields
- Assert `cascading_risks` prepends the estimated-cascading-loss string when there are
  negative balance deltas
- Test that malformed LLM JSON raises `ValueError`

---

## `PrecursorAnalyzer` — What to Test

The class has one public method `analyze(attacker_address, exploit_block) -> AttackerProfile`
which calls `_fetch_address_history` (Etherscan HTTP) and `_fetch_block_timestamp` (JSON-RPC).
Mock both via `patch("httpx.get")` / `patch("httpx.post")` or `patch.object`.

### `_classify_precursor(tx, attacker_address)` — test each branch directly without any network

- `to_addr == ""` and `from_addr == attacker` → `relevance = "deployment"`, description contains
  the contract address
- `from_addr == attacker` and `isError == "1"` → `relevance = "test_run"`
- Incoming ETH from a known Tornado Cash address → `relevance = "funding"`, description contains
  `"tornado_cash"`
- Incoming ETH from a known CEX address → `relevance = "funding"`, description contains `"cex"`
- Incoming ETH from a known bridge address → `relevance = "funding"`, description contains
  `"bridge"`
- Outgoing zero-value call with calldata (`input != "0x"`) → `relevance = "reconnaissance"`
- Outgoing zero-value call with no calldata → returns `None`
- Incoming ETH from unknown address → returns `None`

### `_identify_funding_source(txs)`

- Returns `"tornado_cash"` when first incoming ETH is from a known Tornado Cash address
- Returns `"cex:<addr>"` for a CEX hot wallet
- Returns `"bridge:<addr>"` for a bridge
- Returns `None` when no incoming ETH transactions exist
- Skips zero-value transactions

### `analyze()` end-to-end (mocked HTTP)

- Mock `_fetch_address_history` to return a list of two raw Etherscan tx dicts: one deployment,
  one test run, both before `exploit_block`
- Mock `_fetch_block_timestamp` to return a fixed Unix timestamp
- Assert `profile.precursor_txs` has 2 entries with correct `relevance` values
- Assert `profile.deployed_contracts` contains the contract address from the deployment tx
- Assert `profile.estimated_preparation_time_hours` is computed correctly
- Test that an empty tx history returns an `AttackerProfile` with no precursor txs and
  `funding_source = None`

---

## Key Data Structures to Build in Fixtures

```python
# Minimal IRGraph with one flash loan borrow + one token transfer
from src.ir.nodes import IRGraph, SemanticAction, ActionType

def make_graph():
    graph = IRGraph(tx_hash="0xtest")
    graph.add_action(SemanticAction(
        action_type=ActionType.FLASH_LOAN_BORROW,
        depth=1, from_addr="0xattacker", to_addr="0xlender",
    ))
    graph.add_action(SemanticAction(
        action_type=ActionType.TOKEN_TRANSFER,
        depth=1, from_addr="0xlender", to_addr="0xpool",
    ))
    return graph


# Minimal StateDiff with one loss and one gain
from src.verifier.state_diff import StateDiff, BalanceChange

def make_diff():
    return StateDiff(balance_changes=[
        BalanceChange(address="0xattacker", token="ETH", before=0, after=int(1e18)),
        BalanceChange(address="0xvictim",   token="ETH", before=int(2e18), after=0),
    ])


# Minimal Etherscan tx dict
def make_etherscan_tx(
    from_addr, to_addr, value="0", is_error="0",
    input_data="0x", contract_address=""
):
    return {
        "hash": "0xabc",
        "blockNumber": "100",
        "timeStamp": "1700000000",
        "from": from_addr,
        "to": to_addr,
        "value": value,
        "isError": is_error,
        "input": input_data,
        "contractAddress": contract_address,
    }


# Mocked LLMResponse for blast radius
from unittest.mock import MagicMock
from src.llm.client import LLMResponse

def make_llm_response(content: str) -> LLMResponse:
    return LLMResponse(
        content=content,
        model="gpt-4o",
        input_tokens=100,
        output_tokens=50,
        stop_reason="stop",
    )
```

---

## Run Tests With

```
python -m pytest tests/test_blast_radius.py tests/test_precursor.py -v
```
