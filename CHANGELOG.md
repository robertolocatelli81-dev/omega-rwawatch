# Changelog

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
