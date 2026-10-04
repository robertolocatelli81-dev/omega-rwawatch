# CLAUDE.md — OMEGA-RWAWatch

## What this is
A separate project applying the OMEGA *method* (positive control + hash-chain audit) to **public on-chain readings of
five tokenized funds** — BlackRock BUIDL, J.P. Morgan JLTXX and MONY, Franklin Templeton BENJI, Circle USYC — on ten
chains (7 EVM + Solana, Aptos, Stellar), plus, since 28/09/2026, **four tokenized-ETF trackers** (bCSPX, bIB01, SPYx,
IBITon) on Ethereum, Base, BNB Chain and Solana. It **VERIFIES** and records; it does **NOT** forecast, value, or rate any fund. Not
affiliated with any issuer; not an official NAV/AUM feed. Registry source: each issuer's own address page (BUIDL BNB
is the only exception, tied by shared owner()). GitHub: create/push ONLY after Fable 5 review
(Roberto's order, 25/09/2026; review done 28/09/2026 — see the publication report in the OMEGA workbench).

## Hard constraint
Lives entirely under `~/progetti/omega-rwawatch/`, own git repo, never writes into `~/omega/`. The hash-chain primitive
is vendored in `rwawatch.py`. `omega-evidence` is an OPTIONAL dependency (signed pack); without it the watcher works
and says the pack is not written.

## Layout
- `rwawatch.py` — JSON-RPC, Solana, Aptos and Stellar readers (EIP-2535 Diamond via its loupe), positive control per chain, `REGISTRY` of watched addresses (with provenance),
  vendored SHA-256 hash-chain.
- `rwawatch_agents.py` — council: coverage, structure (implementation code), signed-authorization entry points, supply move.
- `rwawatch_orchestrator.py` — one cycle: snapshot → council vs previous → self-tune (rollback-guaranteed) → chain →
  optional signed pack. Signing seed: `~/.config/omega-rwawatch/signing.seed` (0600), or `$RWAWATCH_SIGNING_SEED`.
- `tests/test_rwawatch.py` — 62 tests, no network (fake node); every write sandboxed in a temp dir.
- `tools/ablate_guards.py` — 33 scripted mutations of the guards; each must make the suite fail (CI job `ablation`).
- `deploy/` — systemd `.service` + `.timer`, NOT enabled (paths via the `%h` specifier).
- `LICENSE` (BSL 1.1), `SECURITY.md`, `.github/workflows/ci.yml` (stdlib-only suite on 3.9/3.11/3.13, ablation,
  evidence path with omega-evidence from its GitHub tag, gitleaks on the whole history).

## Conventions
- English code and docstrings; honest-scope wording (verify ≠ predict).
- A chain whose node or positive control fails is NOT ASSESSED — never reported as quiet or clean.
- Never edit `*_memory.jsonl` / ledgers in place; append through the code path.

## Next steps
1. (done 25/09) Solana, Aptos, Stellar readers; JLTXX, BENJI, USYC.
2. Explorer search beyond the first result page; an Avalanche search source.
3. Changes to on-chain compliance parameters (Aptos `compliance_service`).
4. Bridge mechanism per chain (burn-and-mint vs lock-and-mint) to rule double counting in or out.
5. (done 25/09) Explorer search for the other funds; it found MONY by owner key.
