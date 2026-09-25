#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OMEGA-RWAWatch · core — real on-chain snapshot of tokenized real-world-asset funds + vendored hash-chain.

Watches BlackRock's BUIDL tokenized fund (tokenized by Securitize) on the EVM chains where it is deployed: for each
chain it reads, from a public RPC node and at a recorded block, the token's name, symbol, decimals and total supply,
and the STRUCTURE of the contract (proxy size, implementation address and a SHA-256 of the implementation's code,
presence of EIP-712 / EIP-2612 / EIP-3009 entry points). Before trusting a chain's readings it runs a POSITIVE
CONTROL on the same node: a token known to expose EIP-712 (USDC, or a PancakeSwap LP on BNB) must be seen exposing it;
if not, that chain is reported as NOT ASSESSED, never as clean.

Honest scope: this VERIFIES and RECORDS public on-chain facts at a block and tracks them over time (the hash-chained
memory IS the record). It does NOT predict, it does not value the fund, and a total supply is not assets under
management. The addresses in REGISTRY come from block explorers (their provenance is recorded next to each), not
from an issuer publication; a reading shows what the contract at that address reports, not that the address is the
issuer's. Stdlib only; the hash-chain is VENDORED (this project never imports from or writes into ~/omega/).

Run:  python3 rwawatch.py            # one snapshot, printed, not saved
"""
import hashlib
import json
import ssl
import urllib.request
from datetime import datetime, timezone

LEDGER = "rwawatch_ledger.jsonl"
GENESIS = "0" * 64
_CTX = ssl.create_default_context()
USER_AGENT = "omega-rwawatch/0.1"

# Public RPC endpoints (one per chain; a failure is reported, never papered over).
RPC = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "arbitrum": "https://arbitrum-one-rpc.publicnode.com",
    "optimism": "https://optimism-rpc.publicnode.com",
    "polygon": "https://polygon-bor-rpc.publicnode.com",
    "avalanche": "https://avalanche-c-chain-rpc.publicnode.com",
    "bsc": "https://bsc-rpc.publicnode.com",
}

# The addresses watched, each with where it was found (25/09/2026). Structure fingerprints are READ each run, not
# asserted here, so a change of implementation shows up as a change in the record.
REGISTRY = [
    {"chain": "ethereum", "token": "BUIDL", "address": "0x7712c34205737192402172409a8f7ccef8aa2aec",
     "provenance": "Etherscan label 'BlackRock: BUIDL Token'"},
    {"chain": "ethereum", "token": "BUIDL-I", "address": "0x6a9da2d710bb9b700acde7cb81f10f1ff8c89041",
     "provenance": "Etherscan token page 'BlackRock USD Institutional Digital Liquidity Fund - I Class'"},
    {"chain": "arbitrum", "token": "BUIDL", "address": "0xA6525Ae43eDCd03dC08E775774dCAbd3bb925872",
     "provenance": "Arbitrum Blockscout (verified contract), Arbiscan token page"},
    {"chain": "optimism", "token": "BUIDL", "address": "0xa1cdab15bba75a80df4089cafba013e376957cf5",
     "provenance": "OP Mainnet Etherscan token page"},
    {"chain": "polygon", "token": "BUIDL", "address": "0x2893Ef551B6dD69F661Ac00F11D93E5Dc5Dc0e99",
     "provenance": "Polygon Blockscout (verified contract); the only same-named token with the Securitize proxy shape"},
    {"chain": "avalanche", "token": "BUIDL", "address": "0x53FC82f14F009009b440a706e31c9021E1196A2F",
     "provenance": "web search result; name and proxy shape confirmed on-chain"},
    {"chain": "bsc", "token": "BUIDL", "address": "0x2D5BdC96D9C8AabBDB38c9A27398513e7E5ef84F",
     "provenance": "BscScan search (is_checked, website securitize.io/blackrock/BUIDL)"},
]

# Positive controls: tokens that DO expose EIP-712 on each chain. If the reader cannot see it there, it cannot be
# trusted to report its absence on BUIDL.
CONTROLS = {
    "ethereum": ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
    "arbitrum": ("USDC", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
    "optimism": ("USDC", "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
    "polygon": ("USDC", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"),
    "avalanche": ("USDC", "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E"),
    "bsc": ("Cake-LP", "0x0eD7e52944161450477ee417DE9Cd3a859b14fD0"),
}

# 4-byte selectors of the EIP-712 family entry points
SELECTORS = {"DOMAIN_SEPARATOR": "3644e515", "eip712Domain": "84b0196e", "permit": "d505accf",
             "transferWithAuthorization": "e3ee160e"}
PROXY_SLOTS = {  # where proxies keep their implementation address
    "eip1967": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "zeppelinos": "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",
    "slot1": "0x1",
}


# ───────────────────────── vendored hash-chain (OMEGA-style, independent) ──
def chain_hash(record_without_hash):
    blob = json.dumps(record_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


def append(records, rec):
    rec = dict(rec)
    rec["prev_hash"] = records[-1]["self_hash"] if records else GENESIS
    rec["self_hash"] = chain_hash(rec)
    records.append(rec)
    return rec


def verify_chain(records):
    prev = GENESIS
    for i, r in enumerate(records):
        body = {k: v for k, v in r.items() if k != "self_hash"}
        if r["self_hash"] != chain_hash(body):
            return False, f"self_hash mismatch at #{i}"
        if r["prev_hash"] != prev:
            return False, f"link broken at #{i}"
        prev = r["self_hash"]
    return True, "PASS"


# ───────────────────────── JSON-RPC ──
class RpcError(Exception):
    pass


def rpc(chain, method, params, timeout=25):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC[chain], data=body,
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, context=_CTX, timeout=timeout) as r:
        out = json.loads(r.read())
    if "error" in out:
        raise RpcError(f"{method}: {out['error'].get('message', out['error'])}")
    return out.get("result")


def eth_call(chain, to, data, block):
    try:
        return rpc(chain, "eth_call", [{"to": to, "data": data}, block])
    except RpcError:
        return None                                   # a revert is an answer ("not exposed"), not a crash


def _abi_string(h):
    if not h or len(h) < 130:
        return None
    b = bytes.fromhex(h[2:])
    n = int.from_bytes(b[32:64], "big")
    return b[64:64 + n].decode("utf-8", "replace")


def _abi_uint(h):
    return int(h, 16) if h and h != "0x" else None


def read_structure(chain, address, block):
    """Proxy/implementation shape and which EIP-712 entry points the executing code exposes."""
    proxy_code = rpc(chain, "eth_getCode", [address, block]) or "0x"
    impl, impl_code, slot_name = None, proxy_code, None
    for name, slot in PROXY_SLOTS.items():
        v = rpc(chain, "eth_getStorageAt", [address, slot, block])
        if v and int(v, 16):
            cand = "0x" + v[-40:]
            c = rpc(chain, "eth_getCode", [cand, block]) or "0x"
            if len(c) > 200:
                impl, impl_code, slot_name = cand, c, name
                break
    exposed = sorted(k for k, s in SELECTORS.items() if s in impl_code)
    ds = eth_call(chain, address, "0x" + SELECTORS["DOMAIN_SEPARATOR"], block)
    return {
        "proxy_code_bytes": max(len(proxy_code) // 2 - 1, 0),
        "implementation": impl,
        "implementation_slot": slot_name,
        "implementation_code_sha256": hashlib.sha256(bytes.fromhex(impl_code[2:])).hexdigest() if len(impl_code) > 2 else None,
        "eip712_entry_points": exposed,
        "domain_separator_answers": bool(ds and len(ds) > 2),
    }


def read_token(chain, address, block):
    dec = _abi_uint(eth_call(chain, address, "0x313ce567", block))
    raw = _abi_uint(eth_call(chain, address, "0x18160ddd", block))
    return {
        "name": _abi_string(eth_call(chain, address, "0x06fdde03", block)),
        "symbol": _abi_string(eth_call(chain, address, "0x95d89b41", block)),
        "decimals": dec,
        "total_supply_raw": str(raw) if raw is not None else None,     # exact integer, as a string
        "total_supply": (raw / 10 ** dec) if raw is not None and dec is not None else None,
    }


def control_ok(chain, block):
    """The reader must SEE EIP-712 on a token that has it, on this node, at this block."""
    label, addr = CONTROLS[chain]
    s = read_structure(chain, addr, block)
    ok = "DOMAIN_SEPARATOR" in s["eip712_entry_points"] and s["domain_separator_answers"]
    return {"token": label, "address": addr, "ok": ok, "eip712_entry_points": s["eip712_entry_points"]}


def read_chain(chain, entries):
    """One chain: block, positive control, then every registered token. Any failure makes the chain NOT ASSESSED."""
    try:
        block = rpc(chain, "eth_blockNumber", [])
        ctl = control_ok(chain, block)
        if not ctl["ok"]:
            return {"chain": chain, "assessed": False, "block": int(block, 16), "control": ctl,
                    "reason": "positive control failed: the reader could not see EIP-712 where it exists"}
        tokens = []
        for e in entries:
            t = read_token(chain, e["address"], block)
            t.update(read_structure(chain, e["address"], block))
            t.update({"token": e["token"], "address": e["address"], "provenance": e["provenance"]})
            tokens.append(t)
        return {"chain": chain, "assessed": True, "block": int(block, 16), "rpc": RPC[chain], "control": ctl,
                "tokens": tokens}
    except Exception as ex:                          # network, TLS, JSON: the chain is not assessed, and says why
        return {"chain": chain, "assessed": False, "reason": f"{type(ex).__name__}: {str(ex)[:160]}"}


def fetch_signal():
    """Real on-chain readings for every registered chain. `metric` = total BUIDL supply over the ASSESSED chains."""
    by_chain = {}
    for e in REGISTRY:
        by_chain.setdefault(e["chain"], []).append(e)
    chains = [read_chain(c, es) for c, es in by_chain.items()]
    total = 0.0
    for c in chains:
        for t in c.get("tokens", []):
            if t["token"] == "BUIDL" and t.get("total_supply") is not None:
                total += t["total_supply"]
    assessed = [c["chain"] for c in chains if c.get("assessed")]
    return {
        "metric": round(total, 6),
        "metric_meaning": "sum of BUIDL total supply over the assessed EVM chains (not AUM; BUIDL-I excluded)",
        "chains_assessed": assessed,
        "chains_not_assessed": [c["chain"] for c in chains if not c.get("assessed")],
        "chains": chains,
        "source": "public JSON-RPC nodes (publicnode.com), read at the block recorded per chain",
    }


def snapshot():
    """One observation: real signal + UTC timestamp, ready to be chained."""
    return {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "domain": "rwawatch", "signal": fetch_signal()}


if __name__ == "__main__":
    recs = []
    append(recs, snapshot())
    ok, msg = verify_chain(recs)
    print(json.dumps(recs[-1], ensure_ascii=False, indent=2))
    print("chain:", msg)
