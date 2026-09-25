# CLAUDE.md — OMEGA-RWAWatch

## What this is
A separate project applying the OMEGA *method* (positive control + hash-chain audit) to **public on-chain readings of
BlackRock's BUIDL** on six EVM chains. It **VERIFIES** and records; it does **NOT** forecast, value, or rate the fund.

## Hard constraint
Lives entirely under `~/progetti/omega-rwawatch/`, own git repo, never writes into `~/omega/`. The hash-chain primitive
is vendored in `rwawatch.py`. `omega-evidence` is an OPTIONAL dependency (signed pack); without it the watcher works
and says the pack is not written.

## Layout
- `rwawatch.py` — JSON-RPC readers, positive control per chain, `REGISTRY` of watched addresses (with provenance),
  vendored SHA-256 hash-chain.
- `rwawatch_agents.py` — council: coverage, structure (implementation code), signed-authorization entry points, supply move.
- `rwawatch_orchestrator.py` — one cycle: snapshot → council vs previous → self-tune (rollback-guaranteed) → chain →
  optional signed pack. Signing seed: `~/.config/omega-rwawatch/signing.seed` (0600), or `$RWAWATCH_SIGNING_SEED`.
- `tests/test_rwawatch.py` — no network (fake node); every write sandboxed in a temp dir.
- `deploy/` — systemd `.service` + `.timer`, NOT enabled.

## Conventions
- English code and docstrings; honest-scope wording (verify ≠ predict).
- A chain whose node or positive control fails is NOT ASSESSED — never reported as quiet or clean.
- Never edit `*_memory.jsonl` / ledgers in place; append through the code path.

## Next steps
1. Solana (Token-2022 mint) and Aptos (Move fungible asset) readers.
2. Imitation-token discovery (explorer search) with the structural test used on 25/09 (Polygon had 4 same-named tokens).
3. Changes to on-chain compliance parameters (Aptos `compliance_service`).
