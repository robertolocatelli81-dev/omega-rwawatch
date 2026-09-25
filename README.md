# OMEGA-RWAWatch

> Independent project, not affiliated with, reviewed or endorsed by BlackRock or Securitize. It reads public on-chain
> data only. It is **not** an official NAV, price or assets-under-management feed: a total supply is not a fund's
> assets. BlackRock and BUIDL are named only to identify the contracts read.

Records, on a hash-chained memory, what the contracts of the tokenized fund BUIDL (issued by BlackRock, tokenized by
Securitize) report on six EVM chains — total supply, owner, contract structure, and whether signed-authorization entry
points (EIP-712 / EIP-2612 / EIP-3009) exist — each reading at a recorded block, from public RPC nodes.

## Where the addresses come from

Six of the seven watched EVM addresses are listed on BlackRock's own page
[blackrock.com/…/blackrock-token-addresses](https://www.blackrock.com/corporate/compliance/scams-and-fraud/blackrock-token-addresses)
(checked 25/09/2026; the page also lists Solana and Aptos). The BNB Chain address is **not** on that page: it comes from
BscScan, and its `owner()` is the same externally owned account as the six listed contracts. Each run re-reads
`owner()` and flags a change.

## Each cycle

1. **Node identity, per chain:** the URL must answer `eth_chainId` with the expected chain, and its latest block must
   be at most 15 minutes old; otherwise the chain is **not assessed**.
2. **Positive control, per chain:** a token known to expose EIP-712 (USDC; a PancakeSwap LP on BNB) must be seen
   exposing it on that node; otherwise the chain is **not assessed** — never reported as clean. The control proves the
   reader works; the absence of EIP-712 on BUIDL rests on two readings: no EIP-712 family selector in the
   implementation's code, and `DOMAIN_SEPARATOR()` reverting when called through the proxy.
3. **Readings at one block per chain.** A node error other than a revert, an unreadable symbol or supply, or a small
   proxy whose implementation cannot be located makes the chain **not assessed**.
4. **Unregistered tokens:** an explorer search (Blockscout on Ethereum, Arbitrum, Optimism, Polygon; BscScan on BNB;
   none on Avalanche — reported as "not searched") returns tokens matching `BUIDL` or `BlackRock USD Institutional`,
   first result page per term. Only two things are asserted about them: whether a token is owned by the issuer key (a
   likely new issuer deployment, to be checked by hand) and whether it carries BlackRock's name while **not** being
   owned by that key (not an issuer deployment: imitation, wrapper or third-party product — not told apart). Tokens
   sharing only the common word "BUIDL" are counted, not classified.
5. **Council** (deterministic): coverage, address/symbol/decimals/implementation changes per (chain, token), EIP-712
   entry points appearing, owner changes, new unregistered tokens, supply moves → `QUIET` / `ELEVATED` / `ALERT`.
6. **Evidence:** with the optional `omega-evidence` package, the cycle is written as a pack signed with Ed25519
   **and co-signed with ML-DSA-65** (FIPS 204) when the backend is available, anchored in a hash-chained ledger. The
   pack names, per token, the address, chain id, owner, implementation and the SHA-256 of its code.

```bash
python -m omega_evidence evidence/<pack>.json --ledger evidence/rwawatch_evidence.ledger.jsonl \
    --trust-store evidence/trust.jsonl --require-pq
```

| Aspect | Detail |
|--------|--------|
| Chains | Ethereum (BUIDL, BUIDL-I), Arbitrum, Optimism, Polygon, Avalanche, BNB Chain |
| Sources | public JSON-RPC nodes (publicnode.com); explorer search APIs for unregistered tokens |
| Memory | `rwawatch_memory.jsonl` — SHA-256 hash-chain |
| Deps | Python stdlib; `omega-evidence` optional (signed pack; ML-DSA-65 needs `cryptography` ≥ 48) |
| Cadence | systemd timer provided in `deploy/`, **not enabled** |

## Run

```bash
python3 rwawatch.py                 # one snapshot, printed, not saved
python3 rwawatch_orchestrator.py    # one cycle, appended to the memory (+ signed pack if omega-evidence is installed)
python3 tests/test_rwawatch.py      # 25 tests, no network, no wall clock; every write sandboxed
```

## Measured (25/09/2026)

Six chains assessed, chain ids as expected, node lag ≤ 15 s, positive control passed on each. No BUIDL contract exposes
EIP-712 / EIP-2612 / EIP-3009 entry points; `owner()` is the same account on all seven. BUIDL supply on the six EVM
chains ≈ 883.7 M (Ethereum ≈ 208.3 M, Avalanche ≈ 486.2 M, BNB ≈ 146.5 M, Optimism ≈ 26.5 M, Arbitrum ≈ 8.6 M, Polygon
≈ 7.5 M), identical to the value read from a second RPC provider on every chain; BUIDL-I on Ethereum ≈ 239.7 M, kept
apart. Solana (≈ 987.8 M) and Aptos (≈ 161.7 M) were read by hand the same day and are not covered by this version;
with them the total is ≈ 2.27 B, consistent with the ≈ 2.3 B reported publicly in May 2026 — a consistency check, not a
proof that no chain double-counts a bridged supply. Explorer search found, on the first result page, tokens carrying
BlackRock's name that are not owned by the issuer key: Ethereum 7, Polygon 12, Optimism 2, Arbitrum 1.

> **Honest scope.** It VERIFIES and RECORDS public on-chain facts at a block and tracks them over time. It does **not**
> predict, value, or rate the fund; it does not tell an imitation from a wrapper. The hash-chain is vendored; this
> project never imports from or writes into `~/omega/`.
