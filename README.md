# WireBlock — Blockchain Forensics & Security Analysis Pipeline

WireBlock is a production-grade forensic analysis pipeline for detecting, classifying, and verifying cryptocurrency exploit transactions on Ethereum. Given a transaction hash and a fork block, it orchestrates a full end-to-end investigation: tracing EVM execution, lifting opcodes to semantic actions, classifying the attack technique via agentic reasoning, verifying findings through deterministic predicates and counterfactual ablation, and rendering an interactive HTML forensic report.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Architecture Overview](#architecture-overview)
- [Pipeline Flow](#pipeline-flow)
- [Project Structure](#project-structure)
- [Supported Exploit Techniques](#supported-exploit-techniques)
- [Included Scenarios](#included-scenarios)
- [Key Data Structures](#key-data-structures)
- [Setup & Installation](#setup--installation)
- [Running the Pipeline](#running-the-pipeline)
- [Running Tests](#running-tests)
- [Configuration Reference](#configuration-reference)
- [Technologies Used](#technologies-used)

---

## What It Does

When a DeFi exploit occurs, analysts need to answer a set of hard questions quickly:
- What attack technique was used?
- Which contracts and tokens were affected?
- How much was stolen, and how?
- What causal factors made it possible?
- Could adjacent protocols be at risk?

BigChain automates this investigation. Feed it a transaction hash and it produces a fully-reasoned forensic report with:
- A classified attack hypothesis (with AI reasoning and confidence score)
- A state diff showing exact pre/post balance and storage changes
- Deterministic predicate checks (flash loan detected? reentrancy signature present? balance increased?)
- Ablation results proving or disproving causality through counterfactual testing
- A final verdict: `VERIFIED`, `REFUTED`, or `INCONCLUSIVE`
- An HTML report with attack flow diagrams and remediation recommendations

---

## Architecture Overview

```
+---------------------------------------------------------------------+
|                         ForensicPipeline                            |
|                       (src/orchestrator.py)                         |
+----------+------------+------------+--------------+----------------+
           |            |            |              |
    +------+------+ +---+------+ +--+----------+ +-+--------------+
    | Acquisition | |    IR    | |   Agents    | |   Verifier    |
    |   Layer     | |  Layer   | |   Layer     | |   Layer       |
    +------+------+ +---+------+ +--+----------+ +-+--------------+
           |            |            |              |
    +------+------+ +---+------+ +--+----------+ +-+--------------+
    |trace_fetcher| | lifter   | | classifier  | | predicates    |
    |etherscan    | | patterns | | blast_radius| | state_diff    |
    |fork_manager | | nodes    | | precursor   | | causal        |
    |rpc_client   | |visualizer| |             | | verdict       |
    +-------------+ +----------+ +-------------+ +-------+--------+
                                                          |
                                                  +-------+--------+
                                                  | Report Layer   |
                                                  |  render.py     |
                                                  |  template.j2   |
                                                  +----------------+
```

### Layer Responsibilities

| Layer | Path | Purpose |
|---|---|---|
| **Acquisition** | `src/acquisition/` | Fetches EVM traces, contract source code, and manages Anvil forks |
| **IR** | `src/ir/` | Lifts raw opcode traces to semantic actions (flash loans, swaps, transfers) |
| **Agents** | `src/agents/` | Agent-powered exploit classification, blast radius, and precursor analysis |
| **Verifier** | `src/verifier/` | Deterministic predicate checks, state diffs, ablation testing, verdict generation |
| **Report** | `src/report/` | Jinja2 HTML report rendering with Mermaid diagrams |

---

## Pipeline Flow

```
Input: tx_hash + fork_block_number + scenario config
         |
         v
1. TRACE ACQUISITION
   +-- debug_traceTransaction RPC call -> raw opcode trace
   +-- Etherscan API -> contract source code & ABI

         |
         v
2. IR LIFTING
   +-- Pattern match function selectors -> SemanticAction types
   |   (0xa9059cbb -> TOKEN_TRANSFER, 0xab9c4b5d -> FLASH_LOAN_BORROW, etc.)
   +-- Build IRGraph with edges representing control/data flow
   +-- Assign trace index ranges to each action

         |
         v
3. CLASSIFICATION  
   +-- Classify exploit technique (flash_loan_attack, reentrancy, etc.)
   +-- Return primary hypothesis + alternatives with confidence scores
   +-- Identify affected contracts and suggested causal factors

         |
         v
4. STATE DIFF COMPUTATION
   +-- Query RPC for pre-exploit balances and storage slots
   +-- Query RPC for post-exploit balances and storage slots
   +-- Produce BalanceChange and StorageChange records

         |
         v
5. PREDICATE EVALUATION
   +-- balance_increased: attacker net positive?
   +-- flash_loan_detected: flash loan borrow in IR?
   +-- reentrancy_detected: recursive call pattern in trace?
   +-- governance_token_borrowed: governance token flash-borrowed?
   +-- ... (10+ deterministic checks, each PASS / FAIL / SKIP)

         |
         v
6. ABLATION TESTING  (Counterfactual)
   +-- Fork Ethereum state at pre-exploit block via Anvil
   +-- Remove causal factor (e.g., patch flash loan callback)
   +-- Replay transaction -> did exploit still succeed? -> AblationResult

         |
         v
7. VERDICT GENERATION
   +-- Combine predicate results + ablation outcomes + LLM classification
   +-- Compute confidence score
   +-- Return VERIFIED / REFUTED / INCONCLUSIVE

         |
         v
8. HTML REPORT RENDERING
   +-- Mermaid attack flow diagram
   +-- State diff tables
   +-- Predicate result grid
   +-- Ablation results
   +-- Security fix recommendations

Output: output/<scenario>_report.html
```

---

## Project Structure

```
bigchain/
|
+-- demo.py                         # CLI entry point -- run a named scenario
+-- generate_euler_report.py        # Standalone report generation (no RPC needed)
+-- docker-compose.yml              # Anvil fork + PostgreSQL services
+-- foundry.toml                    # Foundry/Anvil configuration
|
+-- src/
|   +-- orchestrator.py             # ForensicPipeline orchestrator + PipelineConfig
|   |
|   +-- acquisition/
|   |   +-- trace_fetcher.py        # debug_traceTransaction RPC fetcher
|   |   +-- etherscan_client.py     # Contract source code + tx info from Etherscan
|   |   +-- fork_manager.py         # Anvil fork lifecycle management
|   |   +-- rpc_client.py           # Generic JSON-RPC client with retries
|   |
|   +-- ir/
|   |   +-- nodes.py                # IRGraph, SemanticAction, ActionType (14 types)
|   |   +-- lifter.py               # Opcode trace -> IRGraph conversion
|   |   +-- patterns.py             # Function selector -> ActionType pattern matching
|   |   +-- visualizer.py           # Mermaid diagram generator + fix suggestions
|   |
|   +-- agents/
|   |   +-- classifier.py           # OpenAI-powered exploit technique classifier
|   |   +-- blast_radius.py         # Impact scope and cascading loss analyzer
|   |   +-- precursor.py            # Attacker preparation and funding source analysis
|   |
|   +-- llm/
|   |   +-- client.py               # Connects with OpenAI with retry logic
|   |   +-- prompts.py              # System prompts
|   |
|   +-- verifier/
|   |   +-- predicates.py           # Deterministic predicate engine (10+ checks)
|   |   +-- state_diff.py           # Pre/post-exploit state comparison
|   |   +-- causal.py               # Ablation testing via counterfactual state patching
|   |   +-- verdict.py              # Verdict aggregation + confidence scoring
|   |
|   +-- report/
|       +-- render.py               # Jinja2 HTML report renderer
|       +-- template.html.j2        # HTML/CSS report template
|       +-- assets/                 # Static CSS/JS for report styling
|
+-- scenarios/
|   +-- euler/
|   |   +-- config.yaml             # tx_hash, fork_block, attacker, targets, tokens
|   |   +-- expected.json           # Expected output for regression testing
|   +-- nomad/
|   |   +-- config.yaml
|   +-- beanstalk/
|       +-- config.yaml
|
+-- config/
|   +-- techniques.yaml             # Exploit technique definitions + indicators
|   +-- predicates.yaml             # Predicate definitions + parameters
|   +-- ir_patterns.yaml            # Opcode-to-action pattern definitions
|
+-- tests/
|   +-- test_attack_scenarios.py
|   +-- test_blast_radius.py
|   +-- test_precursor.py
|   +-- test_ir_lifter.py
|   +-- test_ir_nodes.py
|   +-- test_patterns.py
|   +-- test_predicates.py
|   +-- test_state_diff.py
|   +-- test_state_diff_integration.py
|   +-- test_causal.py
|   +-- test_verdict.py
|   +-- test_visualizer.py
|   +-- test_scenarios.py
|
+-- foundry/
|   +-- src/                        # Solidity contracts for fork testing
|   +-- test/                       # Solidity test harness
|
+-- output/                         # Generated reports and state diffs
+-- docs/
    +-- handoff_test_agents.md      # Agent test specifications
```

---

## Supported Exploit Techniques

| Technique | Description |
|---|---|
| **Flash Loan Attack** | Uncollateralized loan used to amplify capital within a single transaction, exploiting arithmetic or logic bugs at scale |
| **Price Oracle Manipulation** | Moving spot prices on AMMs to corrupt on-chain oracle readings, enabling profitable trades or liquidations |
| **Reentrancy** | Recursive callback into the victim contract before state updates are written, draining funds iteratively |
| **Governance Manipulation** | Flash-borrowing governance tokens to pass malicious proposals (e.g., Beanstalk) |
| **Delegate Call Exploit** | Using `DELEGATECALL` to an attacker-controlled implementation to overwrite victim storage |
| **Access Control Bypass** | Exploiting missing or improperly configured authorization checks on privileged functions |
| **Liquidity Pool Drain** | Arithmetic precision errors, donation attacks, or rounding exploits against AMM invariants |
| **Sandwich Attack** | MEV-based front-run + back-run around a victim transaction to extract value |
| **Self-Destruct Exploit** | Force-sending ETH via `SELFDESTRUCT` to contracts unprepared for direct ETH receipt |
| **Logic Bug** | Arithmetic overflow/underflow, incorrect state machine transitions, or semantic errors in business logic |

---

## Included Scenarios

Three real-world exploits are pre-configured and ready to analyze:

### Euler Finance (March 2023, ~$197M)
- **Technique**: Donation attack exploiting a missing health check in the `donateToReserves` function
- **Impact**: ~$197M drained across DAI, WBTC, stETH, USDC
- **Config**: `scenarios/euler/config.yaml`

### Nomad Bridge (August 2022, ~$190M)
- **Technique**: Improper initialization — a Merkle root was set to `0x00`, allowing arbitrary message validation
- **Impact**: ~$190M drained by hundreds of copycat attackers
- **Config**: `scenarios/nomad/config.yaml`

### Beanstalk Governance (April 2022, ~$182M)
- **Technique**: Flash-borrowed governance tokens used to pass and immediately execute a malicious proposal
- **Impact**: ~$182M protocol treasury drained in a single transaction
- **Config**: `scenarios/beanstalk/config.yaml`

---

## Key Data Structures

### `IRGraph` — Semantic transaction representation
```python
@dataclass
class IRGraph:
    tx_hash: str
    actions: list[SemanticAction]     # Semantic actions in execution order
    edges: list[tuple[str, str, str]] # (from_id, to_id, edge_label) control/data flow
    metadata: dict                    # tx_from, tx_to, block_number
```

### `SemanticAction` — A single high-level operation
```python
@dataclass
class SemanticAction:
    action_type: ActionType   # FLASH_LOAN_BORROW | TOKEN_TRANSFER | DEX_SWAP | ...
    depth: int                # Call stack depth in EVM trace
    from_addr: str
    to_addr: str
    params: dict              # Decoded calldata (amount, token, recipient, etc.)
    trace_index_start: int
    trace_index_end: int
```

`ActionType` supports 14 types: `TOKEN_TRANSFER`, `FLASH_LOAN_BORROW`, `FLASH_LOAN_REPAY`, `DEX_SWAP`, `STORAGE_READ`, `STORAGE_WRITE`, `CALL`, `DELEGATECALL`, `STATICCALL`, `CREATE`, `SELFDESTRUCT`, `LOG`, `LIQUIDATION`, `GOVERNANCE_VOTE`.

### `StateDiff` — Pre/post-exploit state changes
```python
@dataclass
class StateDiff:
    tx_hash: str
    balance_changes: list[BalanceChange]   # Token/ETH balance deltas per address
    storage_changes: list[StorageChange]   # Storage slot value changes per contract
```

### `VerdictReport` — Final forensic result
```python
@dataclass
class VerdictReport:
    verdict: Verdict                          # VERIFIED | REFUTED | INCONCLUSIVE
    confidence: float                         # 0.0 - 1.0
    technique: str                            # e.g., "flash_loan_attack"
    reasoning: str                            # Human-readable explanation
    predicate_results: list[PredicateCheck]   # Deterministic check outcomes
    ablation_results: list[AblationResult]    # Counterfactual test outcomes
    classification: ClassificationResult      # LLM classification with alternatives
```

---

## Setup & Installation

### Prerequisites

- Python 3.10+
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (for Anvil fork)
- Docker (for `docker-compose` services)
- An Ethereum archive node RPC URL (e.g., Alchemy, Infura — archive access required)
- An Etherscan API key
- An OpenAI API key

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment

Copy the example env file and fill in your keys:

```bash
cp .env.example .env
```

```env
MAINNET_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
ETHER_SCAN_KEY=YOUR_ETHERSCAN_KEY
ANTHROPIC_API_KEY=YOUR_ANTHROPIC_KEY
OPENAI_API_KEY=YOUR_OPENAI_KEY

POSTGRES_USER=WireBlock
POSTGRES_PASSWORD=WireBlock
POSTGRES_DB=traces
ANVIL_PORT=8545
```

### Start Infrastructure Services

```bash
docker-compose up -d
```

This starts:
- **Anvil**: Ethereum mainnet fork on `localhost:8545`
- **PostgreSQL**: Trace storage on `localhost:5432`

---

## Running the Pipeline

### Analyze a Pre-Built Scenario

```bash
python demo.py euler       # Euler Finance exploit
python demo.py nomad       # Nomad Bridge exploit
python demo.py beanstalk   # Beanstalk governance exploit
```

The report is written to `output/<scenario>_report.html`.

### Generate a Static Report (No RPC Required)

```bash
python generate_euler_report.py
```

This generates a fully-rendered HTML report from cached data — useful for demos or when you don't have archive RPC access.

### Analyze a Custom Transaction

You can instantiate `ForensicPipeline` directly:

```python
from src.orchestrator import ForensicPipeline, PipelineConfig

config = PipelineConfig(
    rpc_url="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY",
    etherscan_api_key="YOUR_KEY",
    anthropic_api_key="YOUR_KEY",
    output_dir="output/",
)

pipeline = ForensicPipeline(config)
report = pipeline.run(
    tx_hash="0xabc123...",
    fork_block=17_000_000,
    attacker_address="0xdeadbeef...",
    target_contracts=["0xcontract1...", "0xcontract2..."],
)
print(report.verdict, report.confidence)
```

---

## Running Tests

```bash
# Full test suite
python -m pytest tests/ -v

# Specific module
python -m pytest tests/test_predicates.py -v
python -m pytest tests/test_state_diff_integration.py -v

# Fast unit tests only (no RPC)
python -m pytest tests/ -v -m "not integration"
```

The test suite covers all layers: IR lifting, pattern matching, predicate evaluation, state diff computation, causal ablation, verdict generation, and HTML report rendering.

---

## Configuration Reference

### `config/techniques.yaml`
Defines exploit technique metadata: name, description, indicators, and subtypes. The classifier uses this to constrain output.

### `config/predicates.yaml`
Defines each deterministic predicate check: what to look for in the IRGraph or StateDiff, parameters, and pass/fail conditions.

### `config/ir_patterns.yaml`
Maps EVM function selectors to `ActionType` values. Covers Aave (flash loans), Uniswap (swaps), ERC-20 (transfers), and governance tokens.

### `scenarios/<name>/config.yaml`
Per-scenario configuration:

```yaml
tx_hash: "0x..."
fork_block: 16_817_996
attacker_address: "0x..."
target_contracts:
  - "0x..."
tokens:
  - symbol: DAI
    address: "0x..."
```

---

## Technologies Used

| Technology | Role |
|---|---|
| **OpenAI Agents** | Exploit technique classification, blast radius analysis, precursor analysis |
| **Anvil (Foundry)** | Ethereum mainnet fork for counterfactual ablation testing |
| **Etherscan API** | Contract source code and transaction metadata retrieval |
| **Jinja2** | HTML forensic report templating |
| **Mermaid** | Attack flow diagram rendering in HTML reports |
| **PostgreSQL** | Persistent trace and state diff storage |
| **pytest** | Unit and integration test suite |
| **Python dataclasses** | Typed data structures throughout (IRGraph, StateDiff, VerdictReport) |
| **JSON-RPC** | EVM trace fetching via `debug_traceTransaction` |

---

## Contributing

When adding a new scenario:
1. Create `scenarios/<name>/config.yaml` with the transaction hash, fork block, attacker address, and target contracts.
2. Add an `expected.json` with the expected verdict and technique for regression testing.
3. Run `python demo.py <name>` to verify the pipeline produces a valid report.

When adding a new exploit technique:
1. Add an entry to `config/techniques.yaml` with indicators.
2. Add corresponding predicate entries to `config/predicates.yaml`.
3. Add any new function selectors to `config/ir_patterns.yaml`.
4. Update the classifier system prompt in `src/llm/prompts.py`.
