# Changelog

## 0.3.0 — unreleased — the control record: who can act on each token, under which guard, and every change of it

- **Control record** (`spec/control-record.md`, `rwawatch-control/1`, written before the code). Every token of an
  assessed chain, in the fund layer and in the ETF layer, records six powers — owner, upgrade, mint, freeze, seize,
  pause — each `present` (with its holder and where it was read), `absent` (with what was read) or `not_evaluated`
  (with the reason; never `absent` because it could not be read). Each holder is classified at the same block: one key
  (no code), multisig (Safe `getOwners` + `getThreshold`, Gnosis MultiSigWallet `required`; Squads v4 on Solana),
  timelock (`getMinDelay`), or a contract with its `owner()` followed one level. The record is closed: an unknown key,
  value or spec version, or an address not written as the token's chain writes it, is refused by the council.
- **Council.** `_agent_control` raises the posture when a power changes hands, or when a holder's members, threshold,
  delay or owner change — also while the token's `owner()` stays the same; it compares too the fields that carried
  control before this version (Solana freeze authority, permanent delegate, transfer-hook program; Stellar flags; the
  ETF layer's keys), so a baseline written by 0.2.0 is not blind. `_agent_etf` reads the ETF layer, which no analyst
  read before: a key that is not the issuer's, a chain not assessed or a token not readable raise the posture. The
  per-chain baseline carries the ETF layer.
- **Measured on 0.2.0 (commit `cfa5f39`) and on this version**, same inputs: a change of freeze authority, of permanent
  delegate, and an ETF mint / freeze authority that is no longer the issuer's were `QUIET`, now `ELEVATED`; the StablR
  and SILV incident vectors were `QUIET`, now `ELEVATED` (see the README).
- **Incident vectors** (`tests/vectors/`): StablR USDR, Zoth, HINC recorded from two public archive nodes with identical
  answers (`tools/record_vectors.py`); SILV rebuilt from the Squads multisig's public transactions, end state equal to
  the account (`tools/reconstruct_squads.py`).
- **Explorer search.** A chain not searched is `null` in `search_control`, named apart from a blind search (`false`).
  On 13/11/2026 the council said «search blind (control failed)» for eight fund/chain pairs: three had no explorer
  configured (Avalanche, Base), four were refused by the explorer (Arbitrum and Polygon Blockscout answered HTTP 403 to
  every term), one was a blind search (USYC on BNB Chain). Optimism's explorer is called at the address its 301 points to.
- `tools/spec_orphans.py` (0 orphans between specification, code and tests); `tools/ablate_guards.py` 80 mutations
  (33 before), 0 surviving; `USER_AGENT` `omega-rwawatch/0.3`; `LICENSE` and `pyproject.toml` both 0.3.0 (the
  `LICENSE` said 0.1.0 while the package said 0.2.0).
- BUIDL on BNB Chain: BlackRock's page lists the address (raw HTML read 13/11/2026); the registry and the README said
  it did not (true on 25/09/2026).

What changes for a user of 0.2.0: each token record gains a `control` key; `discovery.search_control` can hold `null`;
the council has two more analysts, so a posture can be `ELEVATED` where 0.2.0 said `QUIET`. The first cycle after the
update says «first control reading» for every token and raises nothing for it.

## 0.2.0 — 2026-10-04 — the memory survives an interrupted or concurrent write; a repeated key is refused

- `save_memory` writes a temporary file, fsyncs it and replaces the memory atomically: an interruption mid-write leaves
  the previous memory intact, never truncated. The temporary is per process, so two cycles at once no longer share it
  (bench of two processes, 25 rounds with a barrier: 25 of 50 writers raised `FileNotFoundError` before, 0 of 50 now,
  each of the 25 memories whole and verifying).
- `load_memory` refuses a record carrying the same key twice (`ValueError`, the cycle stops): `json.loads` kept the last
  value, so the chain verified one value while the bytes also carried another.
- `verify_chain` answers `(False, "malformed record at #i")` on a record that is not an object or lacks `self_hash` /
  `prev_hash`, wherever it sits in the chain, instead of raising.
- The files the orchestrator, two tools and the test helper opened are closed.

Measured: `tests/test_rwawatch.py` 63 tests on Python 3.9 (standard library only), 3.11 and 3.13; `tools/ablate_guards.py`
0 of 33 mutations surviving.

What changes for a user of 0.1.0: a memory file with a repeated key in a record no longer loads (it loaded with the last
value); the temporary file is `<memory>.<pid>.tmp`.

## 0.1.0 — 25–28 September 2026 — the first public code (untagged)

Everything up to commit `fcfea03`, including the tokenized-ETF layer (bCSPX, bIB01, SPYx, IBITon), EIP-1967 beacon proxies
and the AccessControl control key.
