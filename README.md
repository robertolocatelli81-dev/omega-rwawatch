# OMEGA-RWAWatch

Records, on a hash-chained memory, what the contracts of BlackRock's tokenized fund BUIDL (tokenized by Securitize)
report on the EVM chains where it is deployed — total supply, contract structure, and whether signed-authorization
entry points (EIP-712 / EIP-2612 / EIP-3009) exist — each reading at a recorded block, from public RPC nodes.

An independent, **audit-first** OMEGA-method watcher, not affiliated with BlackRock or Securitize. Each cycle:
1. per chain, a **positive control** first: a token known to expose EIP-712 (USDC; a PancakeSwap LP on BNB) must be
   seen exposing it on that node — if not, the chain is **not assessed**, never reported as clean;
2. the watched addresses are read at one block per chain;
3. a deterministic **council** compares the cycle with the previous one (coverage, implementation-code changes,
   signed-authorization entry points appearing, supply moves) and gives `QUIET` / `ELEVATED` / `ALERT`;
4. a detection threshold on run-to-run supply moves self-tunes with a **rollback guarantee**;
5. with the optional `omega-evidence` package installed, the cycle is written as an **Ed25519-signed, ledger-anchored
   evidence pack** (`evidence/`), verifiable with
   `python -m omega_evidence evidence/<pack>.json --ledger evidence/rwawatch_evidence.ledger.jsonl --trust-store evidence/trust.jsonl`
   (the anchor lives in one shared ledger: without `--ledger` the anchor layer reports SKIP). Measured 25/09/2026: PASS,
   authenticated, anchor PASS, with both the Python and the Node verifier of omega-evidence.

| Aspect | Detail |
|--------|--------|
| Chains | Ethereum (BUIDL, BUIDL-I), Arbitrum, Optimism, Polygon, Avalanche, BNB Chain |
| Sources | public JSON-RPC nodes (publicnode.com); watched addresses from block explorers, provenance per address in `REGISTRY` |
| Memory | `rwawatch_memory.jsonl` — SHA-256 hash-chain |
| Deps | Python stdlib; `omega-evidence` optional, only for the signed pack |
| Cadence | systemd timer provided in `deploy/`, **not enabled** |

## Run

```bash
python3 rwawatch.py                 # one snapshot, printed, not saved
python3 rwawatch_orchestrator.py    # one cycle, appended to the memory (+ signed pack if omega-evidence is installed)
python3 tests/test_rwawatch.py      # 14 tests, no network; every write sandboxed
```

## First measured cycle (25/09/2026)

Every chain assessed, positive control passed on each; no watched contract exposes EIP-712 / EIP-2612 / EIP-3009
entry points. BUIDL total supply over the six EVM chains ≈ 883.7 M (Ethereum ≈ 208.3 M, Avalanche ≈ 486.2 M, BNB ≈
146.5 M, Optimism ≈ 26.5 M, Arbitrum ≈ 8.6 M, Polygon ≈ 7.5 M); BUIDL-I on Ethereum ≈ 239.7 M, kept apart. Solana and
Aptos also carry BUIDL and are not covered by this version.

> **Honest scope.** It VERIFIES and RECORDS public on-chain facts at a block and tracks them over time. It does **not**
> predict, it does not value the fund, and a total supply is not assets under management. The watched addresses come
> from block explorers, not from an issuer publication: a reading shows what the contract at that address reports,
> not that it is the issuer's. The hash-chain is **vendored**; this project never imports from or writes into `~/omega/`.
