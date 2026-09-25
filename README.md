# OMEGA-RWAWatch

> Independent project, not affiliated with, reviewed or endorsed by BlackRock, Securitize, J.P. Morgan, Franklin
> Templeton or Circle. It reads public on-chain data only. It is **not** an official NAV, price or
> assets-under-management feed: a total supply is not a fund's assets. Issuers and funds are named only to identify
> the contracts read.

Records, on a hash-chained memory, what the contracts of five tokenized money-market / treasury funds report on ten
chains — total supply, controlling key, contract structure, and whether signed-authorization entry points
(EIP-712 / EIP-2612 / EIP-3009) or, on Aptos, signature primitives exist — each reading at a recorded block, slot,
ledger version or Stellar ledger, from public nodes.

| Fund token | Issuer | Chains watched |
|------------|--------|----------------|
| BUIDL (+ BUIDL-I) | BlackRock, tokenized by Securitize | Ethereum, Arbitrum, Optimism, Polygon, Avalanche, BNB, Solana, Aptos |
| JLTXX, MONY | J.P. Morgan Asset Management | Ethereum (EIP-2535 Diamonds) |
| BENJI | Franklin Templeton (FOBXX) | Ethereum, Polygon, Arbitrum, Avalanche, Base, Solana, Aptos, Stellar |
| USYC | Circle | Ethereum, BNB, Solana |

## Where the addresses come from

Every address comes from the issuer's own page, checked 25/09/2026 (sha256 of the raw HTML recorded in `REGISTRY`),
with one exception:

- **BUIDL** — [blackrock.com/…/blackrock-token-addresses](https://www.blackrock.com/corporate/compliance/scams-and-fraud/blackrock-token-addresses):
  six of the seven EVM addresses, Solana and Aptos. The BNB Chain address is **not** on that page: it comes from
  BscScan, and its `owner()` is the same externally owned account as the six listed contracts.
- **JLTXX** — J.P. Morgan Asset Management press release of 13/05/2026 (the only address in it).
- **MONY** — found by this watcher: the search under JLTXX's terms returned a token owned by the key recorded for
  JLTXX; J.P. Morgan's press release of 15/12/2025 lists that address, and only that one.
- **BENJI** — [Benji DevHub, contracts](https://digitalassets.franklintempleton.com/benji/benji-contracts/). The page
  lists BENJI on eight chains, and separately **iBENJI** (Ethereum, BNB Chain), a different Franklin fund token, not watched.
- **USYC** — [Circle docs, USYC smart contracts](https://developers.circle.com/tokenized/usyc/smart-contracts)
  (Ethereum, BNB, Solana; the Arc chain is not read).

Each run re-reads the controlling key and flags a change. Where a contract exposes none, nothing is claimed: the BENJI
EVM contracts have no `owner()` and an empty EIP-1967 admin slot (control sits in Franklin's own modules, not
watched), so their key is **not checked**.

## Each cycle

Solana and Aptos follow the same gates with their own means: the network is identified by the genesis hash
(Solana mainnet-beta) or `chain_id` 1 (Aptos); the finalized slot / ledger must be at most 15 minutes old; the positive
control is a Token-2022 mint known to carry `permanentDelegate` and `transferHook` (PYUSD) on Solana, and on Aptos a
readable fungible asset (USDC) plus a framework module known to use ed25519 (`0x1::account`), which the bytecode scan
must see. On Solana the reading records the mint authority, freeze authority, extensions, permanent delegate and
transfer-hook program; on Aptos the object owner, the issuer's Move modules (hashed: a change is an upgrade) and any
signature primitive in them. Stellar (Horizon) is identified by its network passphrase; the control is USDC, which
must read with a non-zero amount; the supply is the exact sum, in stroops, of every place the asset can sit (accounts,
claimable balances, liquidity pools, contracts), and the "controlling key" is a SHA-256 fingerprint of the issuer
account's signers and thresholds. Horizon serves current state only: the ledger is recorded before and after.
The controlling key of every token is compared with the one recorded on 25/09/2026.

An EIP-2535 Diamond (JLTXX) has no single implementation to scan: it is read through its own loupe
(`facetAddresses`, `facetFunctionSelectors`), whose control is that `name()` must map to a facet; if it does not,
the chain is not assessed.

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
   sharing only the common word "BUIDL" are counted, not classified; a match that could not be read is listed apart and
   raises `ELEVATED` (it is neither). Each fund is searched by its own terms (BUIDL: `BUIDL`, `BlackRock USD
   Institutional`; JLTXX: `JLTXX`, `JPMorgan OnChain`; BENJI: `Franklin OnChain` — the bare `BENJI` returns a page of
   unrelated memecoins; USYC: `USYC`) and matched against its issuer's name and the keys recorded for it on any chain.
   Where a fund's contracts expose no owner (BENJI on EVM), a same-named token's owner is **not comparable**: said,
   never read as "different".
5. **Council** (deterministic): coverage, address/symbol/decimals/implementation changes per (chain, token), EIP-712
   entry points appearing or disappearing, owner changes, new unregistered tokens, supply moves per token (the
   threshold is tuned on BUIDL's series and applied to every token) → `QUIET` / `ELEVATED` / `ALERT`.
6. **Evidence:** with the optional `omega-evidence` package, the cycle is written as a pack signed with Ed25519
   **and co-signed with ML-DSA-65** (FIPS 204) when the backend is available, anchored in a hash-chained ledger. The
   pack names, per token, the address, chain id, owner, implementation and the SHA-256 of its code.

```bash
python -m omega_evidence evidence/<pack>.json --ledger evidence/rwawatch_evidence.ledger.jsonl \
    --trust-store evidence/trust.jsonl --require-pq
```

| Aspect | Detail |
|--------|--------|
| Chains | Ethereum, Arbitrum, Optimism, Polygon, Avalanche, BNB Chain, Base, Solana, Aptos, Stellar |
| Sources | public nodes (publicnode.com; api.mainnet-beta.solana.com; api.mainnet.aptoslabs.com; horizon.stellar.org); explorer search APIs |
| Memory | `rwawatch_memory.jsonl` — SHA-256 hash-chain |
| Deps | Python stdlib; `omega-evidence` optional (signed pack; ML-DSA-65 needs `cryptography` ≥ 48) |
| Cadence | systemd timer provided in `deploy/`, **not enabled** |

## Run

```bash
python3 rwawatch.py                 # one snapshot, printed, not saved
python3 rwawatch_orchestrator.py    # one cycle, appended to the memory (+ signed pack if omega-evidence is installed)
python3 tests/test_rwawatch.py      # 33 tests, no network, no wall clock; every write sandboxed
```

## Measured (25/09/2026, cycle 14:42 UTC)

Ten chains assessed, network identities as expected, positive control passed on each; every controlling key that
exists equal to the one recorded. Total supply per token over the assessed chains:

| Token | Total | Per chain | EIP-712 family |
|-------|------:|-----------|----------------|
| BUIDL | ≈ 2,033.3 M | Solana 987.9 · Avalanche 486.3 · Ethereum 208.3 · Aptos 161.7 · BNB 146.5 · Optimism 26.5 · Arbitrum 8.6 · Polygon 7.5 | none |
| BUIDL-I | ≈ 239.7 M | Ethereum | none |
| JLTXX | ≈ 849.2 M | Ethereum (Diamond: 16 facets, 68 selectors) | none |
| BENJI | ≈ 668.0 M | Stellar 430.7 · Base 59.7 · Ethereum 48.2 · Arbitrum 48.0 · Avalanche 34.3 · Polygon 32.2 · Aptos 14.7 · Solana 0.2 | none |
| USYC | ≈ 2,111.3 M | BNB 2,073.9 · Ethereum 37.3 · Solana 0.0001 | `DOMAIN_SEPARATOR`, `permit` on Ethereum and BNB |

USYC is the only watched fund token that accepts EIP-2612 `permit` signatures; the others expose no EIP-712 entry
point. On Aptos no signature primitive appears in the BUIDL issuer's modules. The BENJI Aptos object is owned by the
address the official page lists as its "Authorization Module". The BUIDL EVM values were identical to those read from
a second RPC provider in an earlier cycle the same day; with BUIDL-I the BUIDL total is ≈ 2.27 B, consistent with the
≈ 2.3 B reported publicly in May 2026 — a consistency check, not a proof that no chain double-counts a bridged supply.

Explorer search found, on the first result page, tokens carrying BlackRock's name that are not owned by the issuer
key: Ethereum 7, Polygon 12, Optimism 2, Arbitrum 1. In the 14:42 cycle six Polygon reads failed and the six tokens
fell silently into the "not classified" count under a QUIET vote; a re-run found all 12. Fixed the same day: an
unreadable match is now listed apart and flagged.

Search for the other funds (25/09/2026, first result page, five chains with a search source), tokens carrying a
watched issuer's name that are not registered: **owned by a key recorded for the fund**: one — `0x6a7c6aa2…` on
Ethereum, owned by the JLTXX key, which the issuer's own release confirms as its fund MONY (now registered). **Owner
not comparable** (BENJI): Ethereum 2 — iBENJI (on the official page, as a different Franklin token) and a token named
exactly like the fund, 2,100 M supply, not on the official page; Polygon 3 named exactly like the fund, not on the official page. **Not owned
by a recorded key**: JLTXX-named on Ethereum 1; USYC-named on Ethereum 3 (wrappers and an Aave market, by their
names), Arbitrum 1 ("Hashnote USYC", supply 0), Polygon 3 named "Circle USYC" on a chain absent from Circle's list.

The cycle's pack verified `PASS`, `pq_protected`, with the Python verifier and with the Node one (`oeverify.mjs`); the
same pack with one digit of the body changed fails `pack-sha3`. A cycle with discovery takes about 8 minutes.

> **Honest scope.** It VERIFIES and RECORDS public on-chain facts at a block and tracks them over time. It does **not**
> predict, value, or rate any fund; it does not tell an imitation from a wrapper. The hash-chain is vendored; this
> project never imports from or writes into `~/omega/`.
