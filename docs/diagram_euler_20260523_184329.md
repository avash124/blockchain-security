# Forensic Diagram — `0xc310a0af...111d`

- **Transaction:** `0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d`
- **Attacker:** `0xeBC29199C817Dc47BA12E3F86102564D640539d4`
- **Target:** Euler Protocol `0x27182842E098f60e3D576794A5bFFb0777E025d3`
- **Target:** eDAI `0xe025E3ca2bE02316033184551D4d3Aa22c860fDA`
- **EVM Frames:** 89,623
- **Semantic Actions:** 139
- **Edges:** 138

### Action Breakdown

| Type | Count |
|------|-------|
| storage_write | 95 |
| delegate_call | 36 |
| token_transfer | 7 |
| flash_loan_borrow | 1 |

## Forensic Flowchart

```mermaid
graph LR

    classDef attacker fill:#6b0f1a,stroke:#e74c3c,color:#ffd6d6,font-weight:bold
    classDef atk_ctr  fill:#3d0f1a,stroke:#e74c3c,color:#ffb3b3
    classDef protocol fill:#0d2137,stroke:#2980b9,color:#aed6f1
    classDef token    fill:#052e16,stroke:#27ae60,color:#a9dfbf
    classDef other    fill:#1a1a2e,stroke:#566573,color:#c8d6e5
    classDef vuln     fill:#4a1000,stroke:#cb4335,color:#fad7a0,stroke-dasharray:6 3
    classDef fix      fill:#052e16,stroke:#27ae60,color:#a9dfbf,stroke-dasharray:3 3

    N0["👤 Attacker EOA<br/>0xebc29199c817dc47ba12e3f86102564d640539d4"]
    N1["⚔ Attack Contract<br/>0xebc29199c817dc47ba12e3f86102564d640cbf99"]
    N2["🏛 Euler Protocol<br/>0x27182842e098f60e3d576794a5bffb0777e025d3"]
    N3["🏛 eDAI<br/>0xe025e3ca2be02316033184551d4d3aa22c860fda"]
    N4["🪙 Token<br/>0x6b175474e89094c44da98b954eedeac495271d0f"]
    N5["📋 0x5f259d0b76665c337c6104145894f4d1d2758b8c"]
    N6["📋 0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9"]
    N7["📋 0xc6845a5c768bf8d7681249f8927877efda425baf"]
    N8["📋 0x028171bca77440897b824ca71d1c56cac55b68a3"]
    N9["📋 0x7b2a3cf972c3193f26cdec6217d27379b6417bd0"]
    N10["📋 0x0000000000000000000000000000000000000120"]
    N11["📋 0xbb0d4bb654a21054af95456a3b29c63e8d1f4c0a"]
    N12["📋 0x42ec0eb1d2746a9f2739d7501c5d5608bde9ee89"]
    N13["📋 0x3297c8db9360f87a7f7826f52a4fa143988931a6"]
    N14["📋 0x29daddfda3442693c21a50351a2b4820ddbbff79"]
    N15["📋 0xd737ee2bb39f49c62a436002a77f2710cc45ed98"]
    N16["📋 0xe025e3ca2be02316033184551d4d3aa22024d9dc"]
    N17["📋 0xa0b3ee897f233f385e5d61086c32685257d4f12b"]
    N18["📋 0x6c3c78838c761c6ac7be9f59fe808ea2a6e4379d"]
    N19["📋 0x3f87b818f94f3cc21e47fd3bf015e8d8183a3e08"]
    N20["📋 0x778a13d3eeb110a4f7bb6529f99c000119a08e92"]
    N21["📋 0xd23a44eb2db8ad0817c994d3533528c030279f7c"]
    N22["📋 0x583c21631c48d442b5c0e605d624f54a0b366c72"]
    N23["📋 0xd784927ff2f95ba542bfc824c8a8a98f3495f6b5"]
    N24["📋 0xd9ed413bcf58c266f95fe6ba63b13cf79299ce31"]

    V1["🚨 DELEGATECALL targets an unverified or in-tx-deployed contract"]
    F1["🛡 Validate implementation via an allowlist or EIP-1967 immutable slot"]
    V2["🚨 Health / collateral factor not re-validated after flash-funded operations"]
    F2["🛡 Re-check health factor after every balance-altering call inside the loan"]
    V3["🚨 State written before balance/invariant check (checks-effects violated)"]
    F3["🛡 Apply checks-effects-interactions: validate invariants before state mutation"]

    N8 -->|delegatecall x3| N9
    N2 -->|delegatecall| N14
    N2 -->|delegatecall x5| N11
    N2 -->|delegatecall x2| N15
    N5 -->|flash_loan| N6
    N18 -->|delegatecall x2| N19
    N20 -->|delegatecall x2| N21
    N6 -->|delegatecall x2| N7
    N17 -->|transfer| N4
    N23 -->|delegatecall| N24
    N16 -->|delegatecall x8| N13
    N16 -->|delegatecall x2| N12
    N16 -->|transfer| N4
    N1 -->|transfer| N4

    N13 -.->|exposes| V1
    V1 -.->|fix| F1
    N6 -.->|exposes| V2
    V2 -.->|fix| F2
    N16 -.->|exposes| V3
    V3 -.->|fix| F3

    class N0 attacker
    class N1 atk_ctr
    class N2 protocol
    class N3 protocol
    class N4 token
    class N5 other
    class N6 other
    class N7 other
    class N8 other
    class N9 other
    class N10 other
    class N11 other
    class N12 other
    class N13 other
    class N14 other
    class N15 other
    class N16 other
    class N17 other
    class N18 other
    class N19 other
    class N20 other
    class N21 other
    class N22 other
    class N23 other
    class N24 other
    class V1 vuln
    class F1 fix
    class V2 vuln
    class F2 fix
    class V3 vuln
    class F3 fix
```

## Sequence Diagram
```mermaid
sequenceDiagram
    participant 0xd9ed..ce31
    participant 0xd784..f6b5
    participant 0x583c..6c72
    participant 0xd23a..9f7c
    participant 0x778a..8e92
    participant 0x3f87..3e08
    participant 0x6c3c..379d
    participant 0xa0b3..f12b
    participant 0xe025..d9dc
    participant 0xd737..ed98
    participant 0x29da..ff79
    participant 0x3297..31a6
    participant 0x42ec..ee89
    participant 0xbb0d..4c0a
    participant 0x2718..25d3
    participant 0xebc2..bf99
    participant 0x0000..0120
    participant 0x6b17..1d0f
    participant 0x7b2a..7bd0
    participant 0x0281..68a3
    participant 0xc684..5baf
    participant 0x7d27..c7a9
    participant 0x5f25..8b8c
    0x5f25..8b8c->>+0x7d27..c7a9: flash_loan_borrow
    0x7d27..c7a9->>+0xc684..5baf: delegate_call
    0x0281..68a3->>+0x7b2a..7bd0: delegate_call
    unknown->>+0x6b17..1d0f: token_transfer
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0x0000..0120->>+0x0000..0120: storage_write
    0xebc2..bf99->>+0x6b17..1d0f: token_transfer
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0x2718..25d3->>+0xbb0d..4c0a: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+0x6b17..1d0f: token_transfer
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+0x42ec..ee89: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    0x2718..25d3->>+0xbb0d..4c0a: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+0x42ec..ee89: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+0x42ec..ee89: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+0x3297..31a6: delegate_call
    unknown->>+unknown: storage_write
    0x2718..25d3->>+0x29da..ff79: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+0x6b17..1d0f: token_transfer
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+0x42ec..ee89: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    0x2718..25d3->>+0xbb0d..4c0a: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+0x42ec..ee89: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+0x42ec..ee89: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+0x3297..31a6: delegate_call
    unknown->>+unknown: storage_write
    0x2718..25d3->>+0xbb0d..4c0a: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    0x2718..25d3->>+0xd737..ed98: delegate_call
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0x3297..31a6: delegate_call
    0xe025..d9dc->>+0x3297..31a6: delegate_call
    0xe025..d9dc->>+0x3297..31a6: delegate_call
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0x2718..25d3->>+0xd737..ed98: delegate_call
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0x3297..31a6: delegate_call
    0xe025..d9dc->>+0x3297..31a6: delegate_call
    0xe025..d9dc->>+0x3297..31a6: delegate_call
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0x42ec..ee89: delegate_call
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0x3297..31a6: delegate_call
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0x2718..25d3->>+0xbb0d..4c0a: delegate_call
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0x6b17..1d0f: token_transfer
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0x42ec..ee89: delegate_call
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xe025..d9dc->>+0x3297..31a6: delegate_call
    0xe025..d9dc->>+0xe025..d9dc: storage_write
    0xa0b3..f12b->>+0x6b17..1d0f: token_transfer
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0xebc2..bf99->>+0xebc2..bf99: storage_write
    0x6c3c..379d->>+0x3f87..3e08: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    0x778a..8e92->>+0xd23a..9f7c: delegate_call
    0x0281..68a3->>+0x7b2a..7bd0: delegate_call
    0x583c..6c72->>+0x583c..6c72: storage_write
    0x583c..6c72->>+0x583c..6c72: storage_write
    0xd784..f6b5->>+0xd9ed..ce31: delegate_call
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0x0281..68a3->>+0x7b2a..7bd0: delegate_call
    0x7d27..c7a9->>+0xc684..5baf: delegate_call
    unknown->>+unknown: storage_write
    0x778a..8e92->>+0xd23a..9f7c: delegate_call
    0x6c3c..379d->>+0x3f87..3e08: delegate_call
    unknown->>+unknown: storage_write
    unknown->>+unknown: storage_write
    unknown->>+0x6b17..1d0f: token_transfer
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
    0x6b17..1d0f->>+0x6b17..1d0f: storage_write
```

## Security Findings

| Vulnerability | Recommended Fix |
|--------------|-----------------|
| Health / collateral factor not re-validated after flash-funded operations | Re-check health factor after every balance-altering call inside the loan |
| DELEGATECALL targets an unverified or in-tx-deployed contract | Validate implementation via an allowlist or EIP-1967 immutable slot |
| State written before balance/invariant check (checks-effects violated) | Apply checks-effects-interactions: validate invariants before state mutation |
