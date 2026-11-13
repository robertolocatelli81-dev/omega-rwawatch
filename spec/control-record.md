# The control record — specification `rwawatch-control/1`

Status: draft for 0.3.0 (unreleased), written 2026-11-13 before the code that implements it.

A **control record** says, for one watched token at one recorded block (EVM), slot (Solana), ledger version (Aptos) or
ledger (Stellar), **who can act on the token and under which guard**: who owns it, who can upgrade its code, mint,
freeze, seize, pause; and, for each holder of such a power, whether it is a single key, a multisig (members and
threshold) or a timelock (minimum delay). The council compares each control record with the previous one for the same
token and raises the posture when anything in it changed.

The record is **closed**: every key below is listed with its clause, every value comes from a closed vocabulary, and a
record with an unknown key, an unknown value or an unknown spec version is refused by the council (posture ELEVATED,
with the reason), never read past.

Each clause has an identifier in square brackets. `tools/spec_orphans.py` checks that every clause is cited by at least
one test, that every field of the record named in this file is produced by the code, and that the vocabularies in the
code equal the ones written here. Its count of orphans must be 0.

## 1. Where the record sits

- **[CR-1]** Every token read in an assessed chain of the fund layer (`signal.chains[].tokens[]`) and of the ETF layer
  (`etf_signal.chains[].tokens[]`, when `readable` is true) carries one key `control`. A token of a chain that was not
  assessed carries none (the chain says why it was not assessed).
- **[CR-2]** `control.spec` is the string `rwawatch-control/1`. The council knows this version only; any other value is
  refused (§5, P6).
- **[CR-3]** A control record has exactly the keys `spec`, `powers`, `holders`. Any other key is refused (P6).

## 2. Powers

- **[CR-4]** `control.powers` has exactly six keys: `owner`, `upgrade`, `mint`, `freeze`, `seize`, `pause`.
- **[CR-5]** Each power has exactly the keys `status`, `holder`, `source`, `reason`.
  - `status` ∈ {`present`, `absent`, `not_evaluated`} (closed vocabulary).
  - `present`: `holder` is the address (EVM: lower-case `0x…`; Solana, Aptos, Stellar: as the chain writes it) that
    holds the power, and `source` says where it was read (for example `owner()`, `eip1967.admin`, `mintAuthority`).
  - `absent`: `holder` is null; `source` says what was read to establish the absence.
  - `not_evaluated`: `holder` is null; `reason` says why (no standard interface on that chain, the interface did not
    answer, a gate kept in code that is not read). A power is never `absent` because it could not be read.
  - `reason` is null for `present` and `absent`, a non-empty string for `not_evaluated`.

What each chain reads (version 1):

| Power | EVM | Solana (SPL Token / Token-2022) | Aptos | Stellar |
|---|---|---|---|---|
| `owner` **[CR-6]** | `owner()` (EIP-173); ETF layer: the sole `DEFAULT_ADMIN_ROLE` member when `owner()` reverts, as before. `owner()` reverting with no enumerable admin → `absent` with source `owner() reverted` | `mintAuthority` (the controlling key, as before) | object owner | signers fingerprint of the issuer account |
| `upgrade` **[CR-7]** | EIP-1967 admin slot when non-zero (`eip1967.admin`); beacon proxy → the beacon's `owner()` (`beacon.owner()`); EIP-1967 implementation with an empty admin slot → `not_evaluated` (the gate is in the implementation's code: UUPS or custom); EIP-2535 Diamond, ZeppelinOS or slot-1 proxy → `not_evaluated` (gate in code); no proxy mechanism found → `absent` with source `no EIP-1967, ZeppelinOS, slot-1, beacon or EIP-2535 proxy` | `not_evaluated` (the token program is shared, the mint has no own code) | `not_evaluated` | `not_evaluated` |
| `mint` **[CR-8]** | `not_evaluated` (no standard interface enumerates the minter) | `mintAuthority`, `absent` when null | `not_evaluated` | `not_evaluated` |
| `freeze` **[CR-9]** | `not_evaluated` | `freezeAuthority`, `absent` when null | `not_evaluated` | issuer account when the asset flag `auth_revocable` is true; `absent` when false |
| `seize` **[CR-10]** | `not_evaluated` | Token-2022 `permanentDelegate`, `absent` when the extension is missing or its delegate is null | `not_evaluated` | issuer account when `auth_clawback_enabled` is true; `absent` when false |
| `pause` **[CR-11]** | `not_evaluated` | Token-2022 `pausableConfig.authority`, `absent` when the extension is missing or its authority is null | `not_evaluated` | `not_evaluated` |

## 3. Holders

- **[CR-12]** `control.holders` maps every distinct non-null `holder` of `powers` to one holder entry, and holds no other
  key. Keys are written as in `powers` (EVM lower-case).
- **[CR-13]** A holder entry has exactly the keys `kind`, `members`, `threshold`, `min_delay_s`, `owner`, `source`,
  `reason`. `kind` ∈ {`eoa`, `multisig`, `timelock`, `contract`, `account`, `not_evaluated`} (closed vocabulary).
- **[CR-14]** EVM, at the same block: no code at the address → `eoa` (one key). Code present →
  - `getOwners()` answers a list and `getThreshold()` (Safe) or `required()` (Gnosis MultiSigWallet) answers a number
    → `multisig`, `members` = the owners lower-case and sorted, `threshold` = the number, `source` names the
    interface (`safe` or `multisigwallet`);
  - else `getMinDelay()` (OpenZeppelin TimelockController) answers → `timelock`, `min_delay_s` = the delay;
  - else `owner()` answers → `contract` with `owner` = that address, and the owner gets its own holder entry (one
    level only: the owner's own `owner` is not followed, so the map stays finite);
  - else `contract` with `reason` `no multisig, timelock or owner() interface answered`.
  Unused keys are null.
- **[CR-15]** Solana: the holder account is read at the same commitment. An account owned by the Squads v4 program whose
  data decodes as a Squads `Multisig` → `multisig` (`members` sorted, `threshold`, `min_delay_s` = the multisig's
  `time_lock`, `source` `squads-v4`). A Squads vault address is a program-derived address with no data: it is read as
  `multisig` only when the registry declares its multisig and vault index **and** deriving the vault address from them
  gives the holder (checked at every cycle; `source` `squads-v4 vault <index> of <multisig>`); otherwise `account` with
  `reason` `a key or a program-derived address: who signs for it is not read`.
- **[CR-16]** Aptos and Stellar holders: `account` (the Stellar signers are already fingerprinted in the `owner` power).
- **[CR-17]** A holder that could not be read (the call failed for a reason other than a revert) is `not_evaluated` with
  the reason; the chain stays assessed only if its other gates passed.

## 4. Fields the council compares

- **[CR-18]** A power is compared by the pair (`status`, `holder`); `source` and `reason` are not compared (they are
  explanations).
- **[CR-19]** A holder is compared by (`kind`, `members`, `threshold`, `min_delay_s`, `owner`).

## 5. Posture

- **[P1]** For the same (layer, chain, token) in the current snapshot and in the baseline, a power whose (`status`,
  `holder`) differs → ELEVATED, naming the token, the power, the value before and after.
- **[P2]** A holder present in both whose compared fields differ → ELEVATED (for example a multisig whose members or
  threshold changed while the token's `owner()` stayed the same).
- **[P3]** Fields that existed before this specification and carry control are compared too, so a baseline written
  before `rwawatch-control/1` is not blind: Solana `freeze_authority`, `permanent_delegate`, `transfer_hook_program`;
  Stellar `flags`; ETF layer `mint_authority`, `freeze_authority`, `control_key`. A difference → ELEVATED.
- **[P4]** ETF layer: `same_owner`, `same_mint_authority` or `same_freeze_authority` false (the key read is not the one
  recorded for the issuer) → ELEVATED. Null means not comparable and is said in the rationale.
- **[P5]** ETF layer: a chain not assessed, or a token not readable → ELEVATED (coverage lost, never quiet).
- **[P6]** A control record that breaks §1–§3 (unknown spec, unknown or missing key, value outside its vocabulary) →
  ELEVATED with the reason. Nothing in it is compared.
- **[P7]** A baseline token without `control` (written before this specification) → the control comparison is not
  made for it and the rationale says `first control reading`; P3 still applies.
- **[P8]** A power or holder that is identical in both → no vote. A power that is `present` with an `eoa` holder, or a
  missing timelock, is recorded, not raised: the posture follows changes and mismatches with the recorded keys, it does
  not grade designs.

## 6. Search for same-named tokens (the explorer search, revised with this version)

- **[S1]** Per fund registered on a chain, `discovery.search_control[fund]` is `true` (the registered token is among the
  results), `false` (the explorer answered and the registered token is not among the results: the search is blind for
  that fund) or `null` (the chain was not searched: no explorer configured, or the explorer refused or failed every
  term). Before this version a chain with no explorer configured was written `false`, read as «control failed».
- **[S2]** The council names the three cases apart: `search blind (control failed)` only for `false`; `not searched`
  with the explorer's answer for `null`.
- **[S3]** Coverage lost (a fund `true` in the baseline and not `true` now) stays ELEVATED, as before.

## 7. What this record does not say

It says who holds a power at a block, not whether that holder acts in good faith, not who the people behind a key are,
and not whether a multisig's members are distinct persons. `eoa` means one key on chain, not one person. A power
`not_evaluated` is a gap in reading, not a clean bill.
