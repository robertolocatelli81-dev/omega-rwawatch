#!/usr/bin/env python3
"""Record the EVM incident vectors of tests/vectors/ from public ARCHIVE nodes (network, read-only).

For each vector, the reader of this repository (rwawatch.read_evm_token, or read_structure + evm_control for a contract
that is not a token) runs at the block before and the block after the change, against the first archive node; every
JSON-RPC answer it needed is recorded. The same calls are then asked of a second, independent archive node, and the
vector is written only if every answer is identical. The tests replay the recorded answers (no network): a call the
reader makes that is not recorded fails the test.

    python3 tools/record_vectors.py [name ...]     # default: every EVM vector below

Blocks were found by bisection on the same nodes (2026-11-13): the last block with the old value and the first block
with the new one. Sources are the public statements and analyses that name the incident; the addresses were then read
on-chain, never copied into a verdict.
"""
import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import rwawatch as core  # noqa: E402

ARCHIVE_NODES = ("https://eth.drpc.org", "https://rpc.mevblocker.io")      # both answered eth_call at old blocks
OUT = os.path.join(ROOT, "tests", "vectors")

VECTORS = {
    "stablr_usdr_20260524": {
        "incident": "StablR USDR / EURR, 24/05/2026: the owner() of the token (a Gnosis MultiSigWallet) stayed the same "
                    "while its owner list changed — an outside key added at block 25161285, the original two owners "
                    "replaced in the following blocks; unbacked tokens minted after that",
        "sources": ["https://www.stablr.com/insights/stablr-discloses-cybersecurity-incident-affecting-usdr-and-eurr-token-operations "
                    "(issuer statement, 25/05/2026: unauthorized access, supply not fully backed 1:1)",
                    "https://www.theblock.co/post/402429 (24/05/2026: multisig exploit, 13.5 M unbacked tokens; Blockaid's attribution)",
                    "eth.blockscout.com: transactions of 0xD4677B5A8B1b97EA213Fdb876b0FcBAB3f9F6CD1 to the multisig "
                    "0xF45392bd2D6e6b8C5Dc26BA6c8a12889419B82F3 from block 25161289"],
        "chain": "ethereum", "mode": "token",
        "entry": {"token": "USDR", "address": "0x7B43E3875440B44613DC3bC08E7763e6Da63C8f8",
                  "provenance": "StablR USD (USDR), Ethereum; eth.blockscout.com search 'StablR'",
                  "expected_owner": "0xf45392bd2d6e6b8c5dc26ba6c8a12889419b82f3"},
        "blocks": {"before": 25161284, "after": 25161285},
        "expect": {"posture": "ELEVATED", "agent": "_agent_control",
                   "contains": ["holder 0xf45392bd2d6e6b8c5dc26ba6c8a12889419b82f3", "members"]},
    },
    "zoth_subvault_20250321": {
        "incident": "Zoth, 21/03/2025: the implementation behind the ERC1967Proxy USD0PPSubVault was replaced at block "
                    "22094140 by a key that was not the protocol's (about 8.4 M USD lost)",
        "sources": ["https://rekt.news/zoth-rekt", "https://www.halborn.com/blog/post/explained-the-zoth-hack-march-2025",
                    "https://quillaudits.com/blog/hack-analysis/zoth-loose-8.4m-dollar-due-to-access-control "
                    "(names the new implementation 0xc89d7894341e13d5067d003af5346b257d861f56)",
                    "eth.blockscout.com: the creator of that implementation called the proxy "
                    "0x82f3a0392F58C50fa90542519832471BaE93e43e at block 22094143"],
        "chain": "ethereum", "mode": "contract",
        "entry": {"token": "Zoth USD0PP sub-vault", "address": "0x82f3a0392F58C50fa90542519832471BaE93e43e",
                  "provenance": "ERC1967Proxy named in the analyses above; not a token (symbol() reverts)"},
        "blocks": {"before": 22094139, "after": 22094140},
        "expect": {"posture": "ELEVATED", "agent": "_agent_structure", "contains": ["implementation code changed"]},
    },
    "hinc_owner_timelock_2026": {
        "incident": "HINC (Neuberger Berman / Securitize) on Ethereum: LlamaRisk's assessment of 15/09/2026 for Aave "
                    "Horizon found the MASTER / owner() address with no on-chain timelock (a blocking condition); "
                    "owner() moved at block 26126965 to a contract answering getMinDelay() = 43200 s",
        "sources": ["https://governance.aave.com/t/arfc-onboard-hinc-neuberger-securitize-high-income-tokenized-fund-to-aave-horizon/25500 "
                    "(LlamaRisk, 15/09/2026: token 0x015C477A4E2881C4B3bB8999f59ee4A04e812344, MASTER and owner() "
                    "0x59c1eAcEc450c57Dcb9b8725d0F96635C2b676Ee, no on-chain timelock)"],
        "chain": "ethereum", "mode": "token",
        "entry": {"token": "HINC", "address": "0x015C477A4E2881C4B3bB8999f59ee4A04e812344",
                  "provenance": "LlamaRisk assessment on governance.aave.com, 15/09/2026",
                  "expected_owner": "0x59c1eacec450c57dcb9b8725d0f96635c2b676ee"},
        "blocks": {"before": 26126964, "after": 26126965},
        "expect": {"posture": "ELEVATED", "agent": "_agent_control",
                   "contains": ["owner present 0x59c1eacec450c57dcb9b8725d0f96635c2b676ee -> present 0x7ee624ffacd12f75cc299b0a2a13eaa6cfd49203"]},
    },
}


def read_vector(v, block):
    """What this repository's reader records for the vector at `block` (hex string block tag)."""
    if v["mode"] == "token":
        t = core.read_evm_token(v["chain"], v["entry"], block)
        if "unreadable" in t:
            raise SystemExit(f"unreadable at {block}: {t['unreadable']}")
        return t
    s = core.read_structure(v["chain"], v["entry"]["address"], block)
    owner = core.read_owner(v["chain"], v["entry"]["address"], block)
    s.update({"token": v["entry"]["token"], "address": v["entry"]["address"], "owner": owner,
              "control": core.evm_control(v["chain"], v["entry"]["address"], block, s, owner)})
    return s


def record(name, v):
    answers, real = {}, core.rpc

    def recording(chain, method, params, timeout=25):
        key = json.dumps([method, params], sort_keys=True)
        try:
            out = real(chain, method, params, timeout)
            answers[key] = {"result": out}
        except core.RpcError as ex:
            answers[key] = {"error": str(ex)}
            raise
        return out
    out = {"name": name, **{k: v[k] for k in ("incident", "sources", "chain", "mode", "entry", "blocks", "expect")},
           "nodes": list(ARCHIVE_NODES), "recorded_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "answers": {}, "reading": {}}
    for side, b in v["blocks"].items():
        answers.clear()
        core.RPC[v["chain"]] = ARCHIVE_NODES[0]
        core.rpc = recording
        try:
            out["reading"][side] = read_vector(v, hex(b))
        finally:
            core.rpc = real
        # the same questions to the second node: every answer must be identical
        core.RPC[v["chain"]] = ARCHIVE_NODES[1]
        for key, a in answers.items():
            method, params = json.loads(key)
            try:
                b2 = {"result": core.rpc(v["chain"], method, params)}
            except core.RpcError as ex:
                b2 = {"error": str(ex)}
            same = (b2 == a) or ("error" in a and "error" in b2 and "revert" in a["error"].lower() and "revert" in b2["error"].lower())
            if not same:
                raise SystemExit(f"{name} {side}: the two archive nodes disagree on {key}: {a} / {b2}")
        out["answers"][side] = dict(sorted(answers.items()))
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, f"{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"{name}: {sum(len(a) for a in out['answers'].values())} answers, identical on {len(ARCHIVE_NODES)} nodes -> {os.path.relpath(path, ROOT)}")


if __name__ == "__main__":
    for n in (sys.argv[1:] or VECTORS):
        record(n, VECTORS[n])
