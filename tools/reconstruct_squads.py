#!/usr/bin/env python3
"""Rebuild the history of a Squads v4 multisig from its public transactions, and write the SILV incident vector.

Solana's public RPC serves an account's CURRENT data only: a multisig's members and threshold at a past slot cannot be
read. They can be rebuilt: the multisig is created by `multisig_create_v2` (members, threshold, time lock in the
instruction data) and changes only through `config_transaction_execute`, which applies the actions written by the
matching `config_transaction_create`. This tool replays them in slot order. Its positive control: the replayed end
state must equal the account as decoded today (members, threshold, time lock); the vector is not written otherwise.

    python3 tools/reconstruct_squads.py CACHE_DIR [--skip-from ISO --skip-to ISO]

Network (api.mainnet-beta.solana.com, read-only; about 5 s per transaction on 2026-11-13). Transactions already in
CACHE_DIR (one JSON per signature) are not fetched again. --skip-from/--skip-to leave out a time window (the bulk
clawback batches of 11-12/09/2026, 1,848 transactions): the end-state control then also tells whether the window held a
configuration change that was not undone.
"""
import base64
import hashlib
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import rwawatch as core  # noqa: E402

RPC = core.SOLANA_RPC
SILV_MINT = "SiLVFMgD3eD2rgK628NbTBq9MnuJF5FW2CRaVyTB35L"
MULTISIG = "BjbtdEcy324Xdmt9182D8FZYGiH2nhTLFHP7EaAEXLAi"
VAULT_INDEX = 0


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for k in range(5):
        try:
            req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json", "User-Agent": core.USER_AGENT})
            with urllib.request.urlopen(req, context=core._CTX, timeout=60) as r:
                out = json.loads(r.read())
            if "error" in out:
                raise RuntimeError(out["error"])
            return out["result"]
        except Exception:
            if k == 4:
                raise
            time.sleep(3 * (k + 1))


def disc(name):
    return hashlib.sha256(f"global:{name}".encode()).digest()[:8]


IX = {disc(n): n for n in ("multisig_create_v2", "config_transaction_create", "config_transaction_execute")}


def _members(raw, o):
    n = int.from_bytes(raw[o:o + 4], "little")
    o += 4
    return [core.b58encode(raw[o + 33 * i:o + 33 * i + 32]) for i in range(n)], o + 33 * n


def decode_create_v2(raw):
    """MultisigCreateArgsV2: config_authority Option<Pubkey>, threshold u16, members Vec<Member>, time_lock u32, …"""
    o = 8
    o += 33 if raw[o] == 1 else 1
    threshold = int.from_bytes(raw[o:o + 2], "little")
    members, o = _members(raw, o + 2)
    return {"threshold": threshold, "members": sorted(members), "time_lock_s": int.from_bytes(raw[o:o + 4], "little")}


def decode_actions(raw):
    """ConfigTransactionCreateArgs.actions: AddMember / RemoveMember / ChangeThreshold / SetTimeLock; anything else stops."""
    o, acts = 8, []
    n = int.from_bytes(raw[o:o + 4], "little")
    o += 4
    for _ in range(n):
        v = raw[o]
        o += 1
        if v == 0:
            acts.append(["AddMember", core.b58encode(raw[o:o + 32])])
            o += 33
        elif v == 1:
            acts.append(["RemoveMember", core.b58encode(raw[o:o + 32])])
            o += 32
        elif v == 2:
            acts.append(["ChangeThreshold", int.from_bytes(raw[o:o + 2], "little")])
            o += 2
        elif v == 3:
            acts.append(["SetTimeLock", int.from_bytes(raw[o:o + 4], "little")])
            o += 4
        else:
            raise SystemExit(f"config action {v} not covered: stop rather than guess")
    return acts


def signatures(address):
    out, before = [], None
    while True:
        p = {"limit": 1000}
        if before:
            p["before"] = before
        page = rpc("getSignaturesForAddress", [address, p])
        out += page
        if len(page) < 1000:
            return out
        before = page[-1]["signature"]


def replay(sigs, cache):
    state, created, events = None, {}, []
    for x in sorted(sigs, key=lambda x: x["slot"]):
        if x["err"] is not None:
            continue
        p = os.path.join(cache, f"{x['signature']}.json")
        if os.path.exists(p):
            with open(p) as f:
                t = json.load(f)
        else:
            t = rpc("getTransaction", [x["signature"], {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}])
            with open(p, "w") as f:
                json.dump(t, f)
        for ins in t["transaction"]["message"]["instructions"]:
            if ins.get("programId") != core.SQUADS_V4:
                continue
            raw = core.b58decode(ins["data"])
            name = IX.get(raw[:8])
            if name == "multisig_create_v2":
                state = decode_create_v2(raw)
            elif name == "config_transaction_create":
                created[ins["accounts"][1]] = decode_actions(raw)
            elif name == "config_transaction_execute":
                acts = next((created[a] for a in ins["accounts"] if a in created), None)
                if acts is None:
                    raise SystemExit(f"execute without its create: {x['signature']}")
                for a in acts:
                    if a[0] == "AddMember":
                        state["members"] = sorted(state["members"] + [a[1]])
                    elif a[0] == "RemoveMember":
                        state["members"].remove(a[1])
                    elif a[0] == "ChangeThreshold":
                        state["threshold"] = a[1]
                    else:
                        state["time_lock_s"] = a[1]
            else:
                continue
            events.append({"slot": x["slot"], "block_time": x["blockTime"], "signature": x["signature"],
                           "instruction": name, "actions": acts if name == "config_transaction_execute" else None,
                           "state": json.loads(json.dumps(state))})
    return events


def main():
    cache = sys.argv[1]
    os.makedirs(cache, exist_ok=True)
    skip = None
    if "--skip-from" in sys.argv:
        f = datetime.fromisoformat(sys.argv[sys.argv.index("--skip-from") + 1]).replace(tzinfo=timezone.utc).timestamp()
        t = datetime.fromisoformat(sys.argv[sys.argv.index("--skip-to") + 1]).replace(tzinfo=timezone.utc).timestamp()
        skip = (f, t)
    sigs = signatures(MULTISIG)
    kept = [x for x in sigs if not (skip and skip[0] <= x["blockTime"] <= skip[1])]
    events = replay(kept, cache)
    acc = rpc("getAccountInfo", [MULTISIG, {"encoding": "base64", "commitment": "finalized"}])
    raw = base64.b64decode(acc["value"]["data"][0])
    today = core.decode_squads_multisig(raw)
    end = events[-1]["state"]
    if (end["members"], end["threshold"], end["time_lock_s"]) != (today["members"], today["threshold"], today["time_lock_s"]):
        raise SystemExit(f"replayed end state {end} differs from the account today {today}: vector not written")
    mint = rpc("getAccountInfo", [SILV_MINT, {"encoding": "jsonParsed", "commitment": "finalized"}])
    first_change = next(e for e in events if e["instruction"] == "config_transaction_execute" and e["block_time"] > 1789000000)
    before = [e for e in events if e["slot"] < first_change["slot"]][-1]
    vector = {
        "name": "silv_squads_20260911",
        "incident": "SILV (Dominion, tokenized silver, Solana), 11/09/2026: the issuer declared its multisig compromised "
                    "at about 01:00 UTC; a vault transaction of the multisig behind the mint's freeze authority and "
                    "permanent delegate executed at 02:23:33 UTC; the multisig's members changed from 03:43:48 UTC",
        "sources": ["https://cryptoticker.io/en/tokenized-assets-solana-freeze-authority-clawback-check/ (13/09/2026: "
                    "multisig compromised around 01:00 UTC on 11/09; freeze authority and permanent delegate on the same address)",
                    "mint SiLVFMgD3eD2rgK628NbTBq9MnuJF5FW2CRaVyTB35L listed for Dominion Silver by DexScreener, Phantom, "
                    "Solana Compass, DexPaprika (not confirmed on the issuer's own site)",
                    f"multisig {MULTISIG}: the Squads v4 account named by the vault transaction 3V2U6E2f… (02:23:33 UTC)"],
        "chain": "solana", "mint": SILV_MINT, "multisig": MULTISIG, "vault_index": VAULT_INDEX,
        "vault": core.squads_vault(MULTISIG, VAULT_INDEX),
        "mint_account_today": mint, "multisig_account_today_base64": acc["value"]["data"][0],
        "multisig_account_today_slot": acc["context"]["slot"],
        "replay": {"transactions_listed": len(sigs), "transactions_replayed": len(kept),
                   "skipped_window_utc": [datetime.fromtimestamp(s, timezone.utc).isoformat() for s in skip] if skip else None,
                   "end_state_equals_account_today": True, "events": events},
        "configs": {"before": {"slot": before["slot"], **{k: before["state"][k] for k in ("members", "threshold", "time_lock_s")}},
                    "after": {"slot": first_change["slot"], **{k: first_change["state"][k] for k in ("members", "threshold", "time_lock_s")}}},
        "expect": {"posture": "ELEVATED", "agent": "_agent_control", "contains": ["members"]},
        "recorded_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    path = os.path.join(ROOT, "tests", "vectors", "silv_squads_20260911.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vector, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"{len(events)} events replayed, end state = account today; written {os.path.relpath(path, ROOT)}")


if __name__ == "__main__":
    main()
