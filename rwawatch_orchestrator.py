#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OMEGA-RWAWatch · orchestrator — one cycle with hash-chained long-term memory, a multi-agent council, continuous
improvement of a detection threshold (rollback-guaranteed), and an optional signed evidence pack.

Each run: take a fresh on-chain snapshot, let the council compare it with the previous one, self-tune the supply-move
threshold from the history of run-to-run moves (a new threshold is committed ONLY if it strictly improves
separation; otherwise the incumbent is held), append the cycle to the hash-chained memory, and — if the optional
`omega-evidence` package is installed — write an Ed25519-signed, ledger-anchored evidence pack of the cycle.

Honest: the threshold is a DETECTION threshold on observed moves; nothing here forecasts supply or values the fund.

Run:  python3 rwawatch_orchestrator.py
"""
import json
import os
import statistics
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import rwawatch as core           # noqa: E402
import rwawatch_agents as agents  # noqa: E402

MEMORY = os.path.join(HERE, "rwawatch_memory.jsonl")
LATEST = os.path.join(HERE, "rwawatch_latest.json")
EVIDENCE_DIR = os.path.join(HERE, "evidence")
KEY_PATH = os.path.expanduser(os.environ.get("RWAWATCH_SIGNING_SEED", "~/.config/omega-rwawatch/signing.seed"))
PQ_KEY_PATH = os.path.expanduser(os.environ.get("RWAWATCH_PQ_KEY", "~/.config/omega-rwawatch/mldsa65.key"))
THR_MIN, THR_MAX, THR_STEP, THR_INIT = 0.25, 20.0, 0.25, 2.0      # % move of total supply between runs


def load_memory(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    return []


def save_memory(records, path):
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _series(memory):
    """Run-to-run % moves of the total supply, over the chains assessed in both runs."""
    snaps = [r.get("snapshot") for r in memory if r.get("snapshot")]
    out = []
    for prev, cur in zip(snaps, snaps[1:]):
        common = set(prev["signal"].get("chains_assessed", [])) & set(cur["signal"].get("chains_assessed", []))

        def total(s):
            return sum(t["total_supply"] for c in s["signal"].get("chains", []) if c["chain"] in common
                       for t in c.get("tokens", []) if t["token"] == "BUIDL" and t.get("total_supply") is not None)
        a = total(prev)
        if a > 0:
            out.append(abs(total(cur) - a) / a * 100)
    return out


def _quality(values, thr):
    A = [v for v in values if v >= thr]
    B = [v for v in values if v < thr]
    if len(values) < 4 or len(A) < 2 or len(B) < 2:
        return None
    frac = len(A) / len(values)
    if not (0.05 <= frac <= 0.45):
        return None
    return (statistics.mean(A) - statistics.mean(B)) / (statistics.pstdev(A) + statistics.pstdev(B) + 1e-9)


def _last_threshold(memory):
    for r in reversed(memory):
        if r.get("threshold") is not None:
            return r["threshold"]
    return None


def improve_threshold(memory):
    """Self-tune with a non-regression guarantee: the new threshold only if it strictly beats the incumbent."""
    values = _series(memory)
    if len(values) < 4:
        return THR_INIT, "warmup: not enough history"
    incumbent = _last_threshold(memory) or THR_INIT
    base_q = _quality(values, incumbent)
    best_thr, best_q = incumbent, (base_q if base_q is not None else -1e9)
    t = THR_MIN
    while t <= THR_MAX + 1e-9:
        q = _quality(values, t)
        if q is not None and q > best_q:
            best_thr, best_q = t, q
        t += THR_STEP
    if best_q > -1e9 and (base_q is None or best_q > base_q):
        return round(best_thr, 4), f"tuned -> {round(best_thr, 4)} (q={best_q:.3f})"
    return incumbent, f"hold {incumbent} (no strict improvement)"


def write_evidence(record):
    """Optional: a signed, anchored omega-evidence pack of this cycle. Absent package or key → said, never faked."""
    try:
        from omega_evidence import pack as P, signing, trust
    except ImportError:
        return {"written": False, "why": "omega-evidence not installed (pip install omega-evidence): no signed pack"}
    if not os.path.exists(KEY_PATH):
        os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(os.urandom(32).hex())
    seed = bytes.fromhex(open(KEY_PATH).read().strip())
    identity = signing.Identity("omega-rwawatch", seed)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    stamp = record["timestamp_utc"].replace(":", "").replace("-", "")[:15]
    path = os.path.join(EVIDENCE_DIR, f"rwawatch_{stamp}.json")
    sig = record["snapshot"]["signal"]
    # omega-evidence refuses floats in canonical JSON (not portable): supplies go in as exact strings — the raw
    # integer per token, and the decimal total written with a fixed number of places
    supplies = {f"{c['chain']}/{t['token']}": {"address": t.get("address"), "chain_id": (c.get("node") or {}).get("chain_id"),
                                               "raw": t.get("total_supply_raw"), "decimals": t.get("decimals"),
                                               "owner": t.get("owner"), "implementation": t.get("implementation"),
                                               "implementation_code_sha256": t.get("implementation_code_sha256")}
                for c in sig["chains"] for t in c.get("tokens", [])}
    body = {"claim": "on-chain readings of BUIDL at the recorded blocks", "memory_self_hash": record["self_hash"],
            "total_buidl_supply_assessed_chains": f"{sig['metric']:.6f}", "supplies": supplies,
            "chains_assessed": sig["chains_assessed"],
            "chains_not_assessed": sig["chains_not_assessed"],
            "blocks": {c["chain"]: c.get("block") for c in sig["chains"]}, "posture": record["verdict"]["posture"]}
    scope = ("Proves which on-chain values this watcher read, at which blocks, and that the record is signed and "
             "anchored; does NOT prove that the addresses are the issuer's, nor anything about the fund's assets.")
    P.write_pack(path, P.build_pack("rwawatch-cycle", body, scope))
    P.anchor_pack(path, os.path.join(EVIDENCE_DIR, "rwawatch_evidence.ledger.jsonl"))
    P.sign_pack(path, identity)
    # Post-quantum co-signature (ML-DSA-65, FIPS 204) over the same bytes, when the backend is available: the pack then
    # stays verifiable if Ed25519 alone stops being enough. Absent backend → said, the pack stays Ed25519-only.
    pq_pub, pq_note = None, "ML-DSA-65 backend not available: Ed25519 only"
    try:
        from omega_evidence.pqbackends import mldsa
        if mldsa.available():
            if not os.path.exists(PQ_KEY_PATH):
                os.makedirs(os.path.dirname(PQ_KEY_PATH), exist_ok=True)
                mldsa.MlDsaFileSigner.keygen(PQ_KEY_PATH)
                os.chmod(PQ_KEY_PATH, 0o600)
            signer = mldsa.MlDsaFileSigner(PQ_KEY_PATH)
            P.pq_cosign(path, signer)
            pq_pub, pq_note = signer.public_key_b64, "Ed25519 + ML-DSA-65 co-signature"
    except ImportError:
        pass
    store = os.path.join(EVIDENCE_DIR, "trust.jsonl")
    reg = trust.TrustRegistry(store)
    if not reg.status("omega-rwawatch").get("known"):
        reg.trust("omega-rwawatch", identity.public_key_b64, pq_pubkey=pq_pub)
    elif pq_pub and reg.pq_pubkey("omega-rwawatch") != pq_pub:
        reg.rotate("omega-rwawatch", identity.public_key_b64, pq_pubkey=pq_pub)   # pin the PQ key, as a recorded event
    return {"written": True, "pack": os.path.relpath(path, HERE), "public_key_b64": identity.public_key_b64,
            "pq_public_key_b64": pq_pub, "signatures": pq_note}


def run_cycle(snapshot_fn=None, evidence=True):
    memory = load_memory(MEMORY)
    snap = (snapshot_fn or core.snapshot)()
    previous = next((r["snapshot"] for r in reversed(memory) if r.get("snapshot")), None)
    threshold, thr_note = improve_threshold(memory + [{"snapshot": snap}])
    verdict = agents.judge(snap, previous, threshold)
    record = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "snapshot": snap, "verdict": verdict,
              "threshold": threshold, "threshold_note": thr_note}
    rec = core.append(memory, record)                         # hash-chain the cycle
    save_memory(memory, MEMORY)
    ok, msg = core.verify_chain(memory)
    out = dict(rec, chain_ok=ok)
    if evidence:
        try:
            out["evidence"] = write_evidence(rec)
        except Exception as ex:                   # the cycle is already chained: a pack failure is reported, not fatal
            out["evidence"] = {"written": False, "why": f"{type(ex).__name__}: {str(ex)[:160]}"}
    with open(LATEST, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[{rec['timestamp_utc']}] posture={verdict['posture']} total={snap['signal']['metric']} "
          f"assessed={snap['signal']['chains_assessed']} threshold={threshold} chain={msg} ({len(memory)} records) "
          f"evidence={'yes' if out.get('evidence', {}).get('written') else 'no'}")
    return out


if __name__ == "__main__":
    run_cycle()
