# OMEGA-RWAWatch

> Independent project, not affiliated with, reviewed or endorsed by BlackRock, Securitize, J.P. Morgan, Franklin
> Templeton, Circle, Backed Assets, Ondo or State Street. It reads public on-chain data only. It is **not** an official
> NAV, price or assets-under-management feed: a total supply is not a fund's assets, nor an ETF's NAV. Issuers,
> funds and ETFs are named only to identify the contracts read.

Records, on a hash-chained memory, what the contracts of five tokenized money-market / treasury funds report on ten
chains, and — since 2026-09-28 — what the contracts of four tokenized ETF trackers (bCSPX, bIB01, SPYx, IBITon) report
on Ethereum, Base, BNB Chain and Solana — total supply, controlling key, contract structure, and whether signed-authorization entry points
(EIP-712 / EIP-2612 / EIP-3009), ERC-3643 / ERC-7943 permissioned entry points or, on Solana, Token-2022 control
extensions exist — each reading at a recorded block, slot, ledger version or Stellar ledger, from public nodes.
A total supply is a token count: not a fund's assets, not an ETF's NAV.

| Fund token | Issuer | Chains watched |
|------------|--------|----------------|
| BUIDL (+ BUIDL-I) | BlackRock, tokenized by Securitize | Ethereum, Arbitrum, Optimism, Polygon, Avalanche, BNB, Solana, Aptos |
| JLTXX, MONY | J.P. Morgan Asset Management | Ethereum (EIP-2535 Diamonds) |
| BENJI | Franklin Templeton (FOBXX) | Ethereum, Polygon, Arbitrum, Avalanche, Base, Solana, Aptos, Stellar |
| USYC | Circle | Ethereum, BNB, Solana |

## Tokenized ETFs (added 2026-09-28)

A distinct asset class from the funds above: each token tracks one listed ETF, as its issuer describes it. The method is the same — the
address is read on-chain at a block or slot, the controlling key (`owner()` on EVM, mint and freeze authority on
Solana) is compared with the one recorded for the issuer, and the control surface of the code is fingerprinted.
**Total supply is a token count. It is not AUM and it is not the underlying ETF's NAV.** The lifecycle column is
what the issuer declares, with the date it was read; it is not measured on-chain. Blocks/slots below are readings of
2026-09-28 made at three moments (12:25, 14:11 and 14:24 UTC), each at the block/slot shown; a cycle records one block
per chain. On Solana, a Token-2022 mint with `scaledUiAmountConfig` shows
holders `raw × multiplier` (splits, reinvested dividends): the record keeps the raw amount (`total_supply`) and, apart,
the effective multiplier and `ui_amount`. SPYx's multiplier is 1.0057146 (so the two differ by 0.57%); IBITon's is 1.

| Token | Underlying ETF | Chain (read at) | Total supply, 2026-09-28 | Control tie | Lifecycle (declared) |
|-------|----------------|-----------------|--------------------------|-------------|----------------------|
| bCSPX | iShares Core S&P 500 UCITS (CSPX) | Ethereum (block 26075939) | 3,343.43 | `owner()` = 0x22f2dfe…1603 ✓ | redemption only (issuer page: no new issuance) |
| bCSPX | iShares Core S&P 500 UCITS (CSPX) | Base (block 51904493) | 10,000.00 | `owner()` = 0xd1966bd…1d80 ✓ (a different key from Ethereum) | redemption only (issuer page: no new issuance) |
| bIB01 | iShares $ Treasury Bond 0-1yr UCITS | Ethereum (block 26075939) | 45,326.80 | `owner()` = 0x22f2dfe…1603 ✓ | redemption only (issuer page: no new issuance) |
| SPYx | SPDR S&P 500 ETF Trust (SPY) | Solana, Token-2022 (slot 451345109) | 95,231.04 raw — 95,775.24 as displayed (multiplier 1.0057146) | mint authority 7pt9tkct… ✓, freeze authority JDq14BWv… ✓ | listed (xStocks catalog, read 2026-09-28) |
| IBITon | iShares Bitcoin Trust ETF (IBIT) | Ethereum (block 26076466) | 594,883.78 | `owner()` reverts; AccessControl `DEFAULT_ADMIN_ROLE` sole member 0x3715b21…34f1 ✓ | listed (Ondo asset page, read 2026-09-28) |
| IBITon | iShares Bitcoin Trust ETF (IBIT) | BNB Chain (block 124538507) | 4,777.18 | `DEFAULT_ADMIN_ROLE` sole member 0x8860bbf…3b26 ✓ (a different key from Ethereum) | listed (Ondo asset page, read 2026-09-28) |
| IBITon | iShares Bitcoin Trust ETF (IBIT) | Solana, Token-2022 (slot 451342150) | 24.81 | mint authority 9foMHsSD… ✓, freeze authority 51QVCuHf… ✓ | listed (Ondo asset page, read 2026-09-28) |

Issuer: Backed Assets (JE) Limited for the bTokens and SPYx (xStocks brand), Ondo Global Markets (BVI) Limited for
IBITon. Every ETF address comes from the issuer's own page, read as raw HTML on 2026-09-28: IBITon from
`app.ondo.finance/assets/ibiton` (its embedded `supportedNetworks` list; the page is dynamic, so no stable page hash),
bCSPX and bIB01 from `assets.backed.fi/products/bcspx` and `/bib01` (explorer links under "Smart Contracts"), SPYx from
the catalog at `xstocks.com/products` (embedded JSON; its underlying per `assets.backed.fi/products/sp500-xstock`). On-chain ties: the two Ethereum bTokens share one `owner()`;
bCSPX on Base rests on the issuer page alone (its `owner()` is another key); SPYx shares its mint and freeze authority
with xStocks NVDAx; IBITon's admin keys are recorded to detect a change, not as an independent tie. All were read
on-chain on 2026-09-28. The three bTokens expose EIP-2612 `permit`; SPYx carries all five Token-2022
control extensions watched (`permanentDelegate`, `defaultAccountState`, `pausableConfig`, `transferHook`,
`confidentialTransferMint`); IBITon on Solana carries four of them (no `permanentDelegate`); on both mints the
`transferHook` has no hook program set.

**Beacon proxies (added 2026-09-28).** The IBITon EVM contracts are EIP-1967 *beacon* proxies: the proxy stores a
beacon address, and the executing code is what the beacon's `implementation()` returns. The resolver
(`locate_implementation`, shared by the structure read and the permissioned scan) tries the direct slots first and
the beacon only afterwards, so every contract already registered keeps its fingerprint unchanged (measured before/
after, 2026-09-28: 23/23 identical against the previous commit — 16 fund contracts and 7 positive controls,
`tools/negctl_structure.py HEAD~1` — and the 3 bTokens identical against a baseline taken before the change, not kept in the repo). A beacon whose `implementation()`
reverts, or points to an address without code, leaves the implementation *not located* and the reading NOT
ASSESSED. IBITon's code carries `compliance()`, which answers with a contract address (1,403 bytes; its `owner()` is a
key other than IBITon's admin, so its relation to the issuer is not established on-chain; its bytecode contains
no PUSH4 of ICompliance `canTransfer`, `bindToken` or `isTokenBound`). Called directly,
`identityRegistry()`, `isFrozen()` and `canTransfer()` revert (measured 2026-09-28). The byte scan's absence of the
other selectors is still not asserted: IBITon exposes no `permit`, so the scan's positive control cannot pass on it.

**Permissioned-token scan (ERC-3643 / ERC-7943).** The ten 4-byte selectors of the T-REX and uRWA entry points (uRWA as in its
Final text of 2026-05-05; `canTransfer(address,address,uint256)` has the same selector in both — on the token in uRWA,
on the Compliance module in T-REX — and `forcedTransfer` is on the token in both) are hardcoded (keccak-256 computed
offline, recomputable; the runtime stays stdlib-only) and searched in the executing
bytecode. On the three Backed contracts today the result is *absent*: control sits in `owner()` and `permit`, not in
an on-chain identity registry. That absence is reported only because the scan first passes a positive control — it
must see `permit` (`d505accf`) on the same bytecode where it is known to exist — and it did on all three.
**Limit:** the scan is validated on its mechanism, not against a deployed ERC-3643 contract in the registry. Until one
is added, "absent" means "the selectors are not in this bytecode", nothing more.

**A same-named token, checked by hand (2026-09-28).** A token listed on OpenSea as "QQQX" (mint `AAmDPyYbvXkqCX8CBRR7w1m2XiGMcTuV9BRdL7miMJyM`) sits on the legacy Token program, has
no mint or freeze authority and no extensions, with a supply of 299.9 M. The xStocks mints are Token-2022 with mint
authority `7pt9tkct…`. The two do not match, so it is not registered. This layer runs no explorer search of its own (the search exists
for the funds only), so this check was manual and the cycle does not repeat it. Of the seven contracts registered,
three are redemption-only per their issuer; the same-named QQQX is not tied to the xStocks keys (imitation or unrelated
token: not told apart here).

OMEGA-RWAWatch verifies what tokenized funds and ETFs report on-chain — supply, controlling key, control surface —
at a recorded block, and keeps the record. It does not value, price, rate or predict any of them.

## Where the addresses come from

For the five funds, every address comes from the issuer's own page, checked 25/09/2026 (sha256 of the raw HTML recorded
in `REGISTRY`), with one exception (the tokenized ETFs have their own provenance, stated in the section above):

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
   Institutional`; JLTXX: `JLTXX`, `JPMorgan OnChain`; BENJI: `Franklin Templeton BENJI`, `Franklin OnChain` — the bare
   `BENJI` returns a page of unrelated memecoins; USYC: `USYC`) and matched against its issuer's name and the EVM control keys recorded for it (a same-named token found by an EVM explorer can only be owned by an EVM key).
   Where a fund's contracts expose no owner (BENJI on EVM), a same-named token's owner is **not comparable**: said,
   never read as "different". **The search has its own positive control:** for each fund registered on a chain, the
   registered token must be among the results; if it is not, the status says the search is blind for that fund there
   and no finding for it means anything (measured 25/09/2026: BscScan returns nothing for every USYC term, so USYC on
   BNB Chain is not searchable). A fund the search saw last cycle and no longer sees raises `ELEVATED`.
5. **Council** (deterministic; each chain is compared with the last cycle in which THAT chain was assessed, so a chain that misses a cycle is not dropped from the comparison): coverage, address/symbol/decimals/implementation changes per (chain, token), EIP-712
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
| Deps | Python stdlib (3.9, 3.11, 3.13 in CI); `omega-evidence` optional (signed pack; ML-DSA-65 needs `cryptography` ≥ 48) |
| Cadence | systemd timer provided in `deploy/`, **not enabled** |
| License | BSL 1.1 (`LICENSE`); security reports: `SECURITY.md` |

## Run

```bash
python3 rwawatch.py                 # one snapshot, printed, not saved
python3 rwawatch_orchestrator.py    # one cycle, appended to the memory (+ signed pack if omega-evidence is installed)
python3 tests/test_rwawatch.py      # 59 tests, no network, no wall clock; every write sandboxed
mkdir -p /tmp/abl/home && python3 tools/ablate_guards.py /tmp/abl   # 33 scripted mutations of the guards: each must turn the suite red
```

The watcher needs nothing beyond the standard library: Ed25519 and ML-DSA-65 are not in it, so the signed evidence
pack is optional and comes from `omega-evidence` (not on PyPI; pinned in `pyproject.toml` to the commit of its tag
v0.9.1) plus `cryptography`:

```bash
pip install ".[evidence]" "cryptography>=48"   # omega-evidence @ commit of v0.9.1 (GitHub) + the ML-DSA-65 backend
```

CI (`.github/workflows/ci.yml`) runs the suite stdlib-only on three Python versions, the guard ablation (every
mutation must fail the suite), the suite again with the signing path live, and gitleaks over the whole history. The
production memory, the latest record, the evidence packs and the signing keys are never committed (gitignored; the
keys live in `~/.config/omega-rwawatch/`, mode 0600).

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

Search for the other funds (25/09/2026, first result page, five chains with a search source; USYC is not
searchable on BNB Chain — search control failed), tokens carrying a
watched issuer's name that are not registered: **owned by a key recorded for the fund**: one — `0x6a7c6aa2…` on
Ethereum, owned by the JLTXX key, which the issuer's own release confirms as its fund MONY (now registered). **Owner
not comparable** (BENJI): Ethereum 2 — iBENJI (on the official page, as a different Franklin token) and a token named
exactly like the fund, 2,100 M supply, not on the official page; Polygon 6 — named like the fund's legal name or like the official contracts ("Franklin Templeton BENJI"), five with
100,000 M supply and one with 0, none on the official page (recounted 15:15 UTC with the search control's term). **Not owned
by a recorded key**: JLTXX-named on Ethereum 1; USYC-named on Ethereum 3 (wrappers and an Aave market, by their
names), Arbitrum 1 ("Hashnote USYC", supply 0), Polygon 3 named "Circle USYC" on a chain absent from Circle's list.

Every reading of the 14:42 cycle's kind was repeated at about 15:05 UTC on a second provider (drpc, arbitrum.io,
avax.network, binance dataseed, base.org, optimism.io; a second Solana RPC; the Aptos fullnode at the same ledger
version; the LOBSTR Horizon): 16/16 EVM readings identical at the same block (total supply and owner), Solana 3/3,
Aptos 2/2, Stellar supply and signer set identical. The test suite is checked by 28 scripted mutations of its guards
(`tools/ablate_guards.py`); none survived (on 28/09/2026, after the ETF layer, the tool has 33 mutations: 0 of 33).

The cycle's pack verified `PASS`, `pq_protected`, with the Python verifier and with the Node one (`oeverify.mjs`); the
same pack with one digit of the body changed fails `pack-sha3`. A cycle with discovery takes about 8 minutes.

> **Honest scope.** It VERIFIES and RECORDS public on-chain facts at a block and tracks them over time. It does **not**
> predict, value, or rate any fund; it does not tell an imitation from a wrapper. The hash-chain is vendored; this
> project never imports from or writes into `~/omega/`.
