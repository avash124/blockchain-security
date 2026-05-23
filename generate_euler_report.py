"""
Standalone demo: builds a realistic Euler Finance attack IR graph and renders
the forensic HTML report — no live RPC or API keys required.

Run:
    python generate_euler_report.py
Then open output/euler_report.html in a browser.
"""

from __future__ import annotations

import sys
import webbrowser
from pathlib import Path

# ── Euler Finance exploit context ─────────────────────────────────────────────
# Attack: 13 March 2023 | Loss: ~$197M | Technique: donation + self-liquidation
# The attacker donated eDAI to the Euler reserve (reducing their collateral)
# then self-liquidated, pocketing the liquidation bonus from protocol reserves.

SCENARIO_CONFIG = {
    "scenario": "euler",
    "name": "Euler Finance Exploit",
    "date": "2023-03-13",
    "chain": "mainnet",
    "tx_hash": "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d",
    "fork_block": 16817995,
    "attacker_address": "0xeBC29199C817Dc47BA12E3F86102564D640539d4",
    "target_contracts": [
        {"name": "Euler Protocol", "address": "0x27182842E098f60e3D576794A5bFFb0777E025d3"},
        {"name": "eDAI Token",     "address": "0xe025E3ca2bE02316033184551D4d3Aa22c860fDA"},
    ],
    "exploit_technique": "donation_attack",
    "estimated_loss_usd": 197_000_000,
    "tags": ["flash_loan", "donation", "liquidation"],
}


def build_euler_ir_graph():
    """Construct a realistic IR graph for the Euler Finance exploit transaction."""
    from src.ir.nodes import ActionType, IRGraph, SemanticAction

    graph = IRGraph(
        tx_hash=SCENARIO_CONFIG["tx_hash"],
        metadata={"block": SCENARIO_CONFIG["fork_block"] + 1, "chain": "mainnet"},
    )

    ATTACKER  = SCENARIO_CONFIG["attacker_address"]
    EULER     = SCENARIO_CONFIG["target_contracts"][0]["address"]
    EDAI      = SCENARIO_CONFIG["target_contracts"][1]["address"]
    AAVE      = "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9"
    DAI       = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
    LOAN_CTR  = "0xA56Ec6F53cF0e964c5c06F1AA7FFF15B5C49dAae"  # attacker's loan contract

    def make(idx, atype, frm, to, **params):
        a = SemanticAction(
            action_type=atype, depth=1 + (idx % 3),
            from_addr=frm, to_addr=to, params=params,
        )
        a.trace_index_start = idx
        a.trace_index_end   = idx + 1
        return a

    actions = [
        # 1. Flash loan 30M DAI from Aave
        make(0,  ActionType.FLASH_LOAN_BORROW,  ATTACKER, AAVE,
             value=30_000_000 * 10**18, token=DAI, protocol="aave_v2"),

        # 2. Deposit 30M DAI → Euler, receive 200M eDAI + 200M dDAI (debt)
        make(1,  ActionType.TOKEN_TRANSFER,      ATTACKER, EULER,
             amount=30_000_000 * 10**18, token=DAI, action="deposit"),

        make(2,  ActionType.STORAGE_WRITE,       EULER, EULER,
             slot="0x01", value="200000000000000000000000000", note="mint eDAI"),

        make(3,  ActionType.STORAGE_WRITE,       EULER, EULER,
             slot="0x02", value="200000000000000000000000000", note="mint dDAI"),

        # 3. Borrow an additional 200M DAI (leverage)
        make(4,  ActionType.TOKEN_TRANSFER,      EULER, ATTACKER,
             amount=200_000_000 * 10**18, token=DAI, action="borrow"),

        # 4. donateToReserves — THE VULNERABLE CALL
        #    Donates 100M eDAI, collapsing the health factor below 1.0
        #    Euler had no health-check guard after this path.
        make(5,  ActionType.STORAGE_WRITE,       ATTACKER, EULER,
             slot="0x03", value="0", note="donateToReserves: 100M eDAI burned from attacker"),

        # 5. Self-liquidation: attacker's second contract liquidates the first
        make(6,  ActionType.LIQUIDATION,         LOAN_CTR, EULER,
             liquidator=LOAN_CTR, borrower=ATTACKER,
             bonus_pct=20, note="self-liquidation; bonus extracted from protocol"),

        make(7,  ActionType.TOKEN_TRANSFER,      EULER, LOAN_CTR,
             amount=120_000_000 * 10**18, token=EDAI, action="liquidation_bonus"),

        # 6. Second iteration with the second loan contract (amplifies profit)
        make(8,  ActionType.FLASH_LOAN_BORROW,   LOAN_CTR, AAVE,
             value=30_000_000 * 10**18, token=DAI, protocol="aave_v2"),

        make(9,  ActionType.LIQUIDATION,         LOAN_CTR, EULER,
             liquidator=LOAN_CTR, borrower=LOAN_CTR,
             bonus_pct=20, note="second self-liquidation round"),

        # 7. Redeem eDAI → DAI
        make(10, ActionType.TOKEN_TRANSFER,      EULER, ATTACKER,
             amount=197_000_000 * 10**18, token=DAI, action="redeem"),

        # 8. Repay both flash loans
        make(11, ActionType.FLASH_LOAN_REPAY,    ATTACKER, AAVE,
             value=30_000_000 * 10**18, token=DAI),

        make(12, ActionType.FLASH_LOAN_REPAY,    LOAN_CTR, AAVE,
             value=30_000_000 * 10**18, token=DAI),

        # 9. Profit transferred out
        make(13, ActionType.TOKEN_TRANSFER,      ATTACKER, "0x0000dead",
             amount=197_000_000 * 10**18, token=DAI, action="profit_out"),
    ]

    for action in actions:
        graph.add_action(action)

    # Sequential edges
    for i in range(len(graph.actions) - 1):
        graph.add_edge(graph.actions[i].id, graph.actions[i + 1].id, "sequence")

    return graph


def build_mock_verdict(ir_graph):
    """Build a realistic mock verdict for the Euler exploit."""
    from src.agents.classifier import ClassificationResult, Hypothesis
    from src.verifier.predicates import PredicateCheck, PredicateResult
    from src.verifier.verdict import Verdict, VerdictReport

    classification = ClassificationResult(
        primary_hypothesis=Hypothesis(
            technique="donation_attack",
            confidence=0.94,
            reasoning=(
                "The trace shows a flash loan borrow followed by a deposit that mints "
                "both eDAI and dDAI, then a donateToReserves call that removes collateral "
                "without reducing debt, and finally a self-liquidation that extracts the "
                "liquidation bonus from protocol reserves. This matches the Euler donation "
                "attack pattern with high confidence."
            ),
            supporting_actions=[
                "flash_loan_borrow_0",
                "storage_write_5",
                "liquidation_6",
                "flash_loan_repay_11",
            ],
        ),
        alternative_hypotheses=[
            Hypothesis(
                technique="flash_loan_attack",
                confidence=0.45,
                reasoning="Flash loan present, but the root cause is the donation logic bug.",
            ),
        ],
    )

    predicates = [
        PredicateCheck(
            name="flash_loan_detected",
            result=PredicateResult.PASS,
            details="Found 2 borrow(s) and 2 repay(s) from Aave v2",
        ),
        PredicateCheck(
            name="balance_increased",
            result=PredicateResult.PASS,
            details="Attacker gained on 1 asset(s): DAI — net +197,000,000 DAI",
        ),
        PredicateCheck(
            name="balance_decreased",
            result=PredicateResult.PASS,
            details="Euler reserves lost ~197M DAI across 7 change(s)",
        ),
        PredicateCheck(
            name="reentrancy_detected",
            result=PredicateResult.FAIL,
            details="No nested re-entry detected; liquidation is synchronous",
        ),
        PredicateCheck(
            name="price_manipulation",
            result=PredicateResult.FAIL,
            details="No oracle read sandwiched between DEX swaps",
        ),
    ]

    return VerdictReport(
        verdict=Verdict.VERIFIED,
        confidence=0.91,
        technique="donation_attack",
        reasoning=(
            "5 predicates evaluated: 3 PASS, 2 FAIL. The flash loan borrow+repay pair is "
            "confirmed, attacker balance increased by ~$197M DAI, and Euler reserves were "
            "drained. The self-liquidation (liquidation_6) combined with the donateToReserves "
            "storage write (storage_write_5) is the causal chain. No reentrancy or oracle "
            "manipulation observed — the root cause is a missing health-factor guard in the "
            "donate pathway and unrestricted self-liquidation."
        ),
        predicate_results=predicates,
        ablation_results=[],
        classification=classification,
    )


def main():
    sys.path.insert(0, str(Path(__file__).parent))

    # Install jinja2 if needed
    try:
        import jinja2  # noqa: F401
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "jinja2", "-q"])

    from src.ir.visualizer import IRVisualizer
    from src.report.render import ReportRenderer

    ir_graph  = build_euler_ir_graph()
    verdict   = build_mock_verdict(ir_graph)

    visualizer = IRVisualizer()
    mermaid    = visualizer.to_forensic_flowchart(ir_graph, SCENARIO_CONFIG)
    fixes      = visualizer.extract_security_fixes(ir_graph)

    output_path = Path("output") / "euler_report.html"
    ReportRenderer().render(
        verdict=verdict,
        ir_graph=ir_graph,
        mermaid_diagram=mermaid,
        scenario_config=SCENARIO_CONFIG,
        output_path=output_path,
        security_fixes=fixes,
    )

    print(f"Report written → {output_path.resolve()}")

    # Try to open in the default browser
    try:
        webbrowser.open(output_path.resolve().as_uri())
    except Exception:
        pass


if __name__ == "__main__":
    main()
