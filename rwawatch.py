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

Independent project, not affiliated with BlackRock or Securitize; not an official NAV/price/AUM feed.

Honest scope: this VERIFIES and RECORDS public on-chain facts at a block and tracks them over time (the hash-chained
memory IS the record). It does NOT predict, it does not value the fund, and a total supply is not assets under
management. Six of the seven EVM addresses in REGISTRY are listed on BlackRock's own token-address page (OFFICIAL_PAGE);
the BNB Chain one is not, and is tied to them by a shared owner(). Before any reading, each node must answer the
expected eth_chainId with a fresh block. Stdlib only; the hash-chain is VENDORED (never imports from ~/omega/).

Run:  python3 rwawatch.py            # one snapshot, printed, not saved
"""
import hashlib
import json
import ssl
import time
import urllib.parse
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

# The chain each URL must answer for (eth_chainId). A load balancer that routes to another network would otherwise
# pass the positive control — USDC exists on every chain — and record another chain's state under this name.
CHAIN_IDS = {"ethereum": 1, "arbitrum": 42161, "optimism": 10, "polygon": 137, "avalanche": 43114, "bsc": 56}
MAX_BLOCK_AGE_S = 900        # a node whose latest block is older than this is lagging: the chain is NOT ASSESSED

# Where same-named tokens are searched for (explorer search APIs; a chain without one is reported "not searched").
DISCOVERY = {
    "ethereum": ("blockscout", "https://eth.blockscout.com"),
    "arbitrum": ("blockscout", "https://arbitrum.blockscout.com"),
    "optimism": ("blockscout", "https://optimism.blockscout.com"),
    "polygon": ("blockscout", "https://polygon.blockscout.com"),
    "bsc": ("bscscan-search", "https://bscscan.com/searchHandler"),
}
DISCOVERY_TERMS = ("BUIDL", "BlackRock USD Institutional")
# The two contract shapes the registered BUIDL deployments have (measured 25/09/2026)
SECURITIZE_SHAPES = ({"proxy_code_bytes": 703, "implementation_slot": "slot1"},
                     {"proxy_code_bytes": 170, "implementation_slot": "eip1967"})

# Official source of the addresses (checked 25/09/2026, page sha256 a0c2c276…): it lists 6 of the 7 EVM addresses below,
# and the Solana and Aptos ones; not BNB Chain.
OFFICIAL_PAGE = "https://www.blackrock.com/corporate/compliance/scams-and-fraud/blackrock-token-addresses"
OFFICIAL = f"listed on {OFFICIAL_PAGE}"
# owner() of all seven registered contracts on 25/09/2026, BNB included: one externally owned account (no code), i.e.
# the same private key on every chain. A change is flagged; a same-named token with another owner is not a deployment
# of this issuer's key.
EXPECTED_OWNER = "0xe01605f6b6dc593b7d2917f4a0940db2a625b09e"

# The addresses watched, each with where it was found (25/09/2026). Structure fingerprints are READ each run, not
# asserted here, so a change of implementation shows up as a change in the record.
REGISTRY = [
    {"chain": "ethereum", "token": "BUIDL", "address": "0x7712c34205737192402172409a8f7ccef8aa2aec",
     "provenance": f"{OFFICIAL} (also Etherscan label 'BlackRock: BUIDL Token')"},
    {"chain": "ethereum", "token": "BUIDL-I", "address": "0x6a9da2d710bb9b700acde7cb81f10f1ff8c89041",
     "provenance": f"{OFFICIAL}"},
    {"chain": "arbitrum", "token": "BUIDL", "address": "0xA6525Ae43eDCd03dC08E775774dCAbd3bb925872",
     "provenance": f"{OFFICIAL}"},
    {"chain": "optimism", "token": "BUIDL", "address": "0xa1cdab15bba75a80df4089cafba013e376957cf5",
     "provenance": f"{OFFICIAL}"},
    {"chain": "polygon", "token": "BUIDL", "address": "0x2893Ef551B6dD69F661Ac00F11D93E5Dc5Dc0e99",
     "provenance": f"{OFFICIAL}"},
    {"chain": "avalanche", "token": "BUIDL", "address": "0x53FC82f14F009009b440a706e31c9021E1196A2F",
     "provenance": f"{OFFICIAL}"},
    {"chain": "bsc", "token": "BUIDL", "address": "0x2D5BdC96D9C8AabBDB38c9A27398513e7E5ef84F",
     "provenance": "NOT on the official page (25/09/2026); BscScan search (is_checked, website securitize.io/blackrock/BUIDL) "
                   "and owner() equal to the owner of the six officially listed contracts"},
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

# ───────────────────────── non-EVM chains (same method: network identity, freshness, positive control, readings) ──
SOLANA_RPC = "https://api.mainnet-beta.solana.com"
SOLANA_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"          # mainnet-beta
APTOS_API = "https://api.mainnet.aptoslabs.com/v1"
APTOS_CHAIN_ID = 1                                                        # mainnet
NONEVM_REGISTRY = [
    {"chain": "solana", "token": "BUIDL", "address": "GyWgeqpy5GueU2YbkE8xqUeVEokCMMCEeUrfbtMw6phr",
     "provenance": f"{OFFICIAL}", "expected_owner": "APm3MWbXfMMKAWgsDVnxcAGbLjvRxubPu1A8a5SA2kbJ"},
    {"chain": "aptos", "token": "BUIDL", "address": "0x50038be55be5b964cfa32cf128b5cf05f123959f286b4cc02b86cafd48945f89",
     "provenance": f"{OFFICIAL}", "expected_owner": "0x4de5876d8a8e2be7af6af9f3ca94d9e4fafb24b5f4a5848078d8eb08f08e808a"},
]
# Solana control: a Token-2022 mint KNOWN to carry the extensions watched on BUIDL (PYUSD); Aptos control: a fungible
# asset known to be readable (USDC) and a framework module known to use ed25519 (0x1::account) for the bytecode scan.
SOLANA_CONTROL = ("PYUSD", "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo", ("permanentDelegate", "transferHook"))
APTOS_CONTROL = ("USDC", "0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b")
SIG_NEEDLES = ("ed25519", "secp256k1", "multi_ed25519", "bls12381")


def _post_json(url, method, params, timeout=25):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(NETWORK_RETRIES + 1):
        try:
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, context=_CTX, timeout=timeout) as r:
                out = json.loads(r.read())
            break
        except (OSError, ssl.SSLError):
            if attempt == NETWORK_RETRIES:
                raise
            time.sleep(2)
    if "error" in out:
        raise RpcError(f"{method}: {out['error'].get('message', out['error'])}")
    return out.get("result")


def _get_json(url, timeout=25):
    for attempt in range(NETWORK_RETRIES + 1):
        try:
            return _http_json(url, timeout)
        except (OSError, ssl.SSLError):
            if attempt == NETWORK_RETRIES:
                raise
            time.sleep(2)


def _sol_mint(address):
    v = _post_json(SOLANA_RPC, "getAccountInfo", [address, {"encoding": "jsonParsed", "commitment": "finalized"}])
    val = v["value"]
    info = val["data"]["parsed"]["info"]
    ext = {e["extension"]: e.get("state") for e in info.get("extensions", [])}
    return v["context"]["slot"], val["owner"], info, ext


def read_solana(entries, now=None):
    """Solana: genesis hash must be mainnet-beta, finalized slot fresh, PYUSD must show its Token-2022 extensions."""
    try:
        genesis = _post_json(SOLANA_RPC, "getGenesisHash", [])
        slot = _post_json(SOLANA_RPC, "getSlot", [{"commitment": "finalized"}])
        bt = _post_json(SOLANA_RPC, "getBlockTime", [slot])
        node = {"chain_id": genesis, "expected_chain_id": SOLANA_GENESIS, "block": slot, "block_timestamp": bt,
                "block_age_s": int((now if now is not None else time.time()) - bt)}
        if genesis != SOLANA_GENESIS:
            return {"chain": "solana", "assessed": False, "node": node, "reason": f"genesis {genesis} is not mainnet-beta"}
        if node["block_age_s"] > MAX_BLOCK_AGE_S:
            return {"chain": "solana", "assessed": False, "node": node,
                    "reason": f"stale node: finalized slot is {node['block_age_s']} s old (> {MAX_BLOCK_AGE_S} s)"}
        label, cmint, need = SOLANA_CONTROL
        _, _, _, cext = _sol_mint(cmint)
        ctl = {"token": label, "address": cmint, "ok": all(n in cext for n in need), "extensions_seen": sorted(cext)}
        if not ctl["ok"]:
            return {"chain": "solana", "assessed": False, "node": node, "control": ctl,
                    "reason": "positive control failed: the reader could not see Token-2022 extensions where they exist"}
        tokens = []
        for e in entries:
            cslot, program, info, ext = _sol_mint(e["address"])
            dec, raw = info.get("decimals"), int(info.get("supply")) if info.get("supply") is not None else None
            md = ext.get("tokenMetadata") or {}
            tokens.append({
                "token": e["token"], "address": e["address"], "provenance": e["provenance"],
                "name": md.get("name"), "symbol": md.get("symbol"), "decimals": dec,
                "total_supply_raw": str(raw) if raw is not None else None,
                "total_supply": raw / 10 ** dec if raw is not None and dec is not None else None,
                "owner": info.get("mintAuthority"), "expected_owner": e["expected_owner"],
                "program": program, "freeze_authority": info.get("freezeAuthority"),
                "extensions": sorted(ext),
                "permanent_delegate": (ext.get("permanentDelegate") or {}).get("delegate"),
                "transfer_hook_program": (ext.get("transferHook") or {}).get("programId"),
                "implementation_code_sha256": hashlib.sha256(json.dumps(
                    {"program": program, "extensions": sorted(ext), "hook": (ext.get("transferHook") or {}).get("programId")},
                    sort_keys=True).encode()).hexdigest(),
                "eip712_entry_points": [], "read_at_slot": cslot})
            if tokens[-1]["symbol"] is None or tokens[-1]["total_supply"] is None:
                return {"chain": "solana", "assessed": False, "node": node, "control": ctl,
                        "reason": f"{e['token']} at {e['address']}: symbol or supply not readable"}
        return {"chain": "solana", "assessed": True, "block": slot, "rpc": SOLANA_RPC, "node": node, "control": ctl,
                "tokens": tokens, "discovery": {"status": "not searched (no search source for Solana)", "unregistered": []}}
    except Exception as ex:
        return {"chain": "solana", "assessed": False, "reason": f"{type(ex).__name__}: {str(ex)[:160]}"}


def _apt_resources(address, version):
    return {r["type"]: r["data"] for r in _get_json(f"{APTOS_API}/accounts/{address}/resources?ledger_version={version}&limit=200")}


def read_aptos(entries, now=None):
    """Aptos: chain_id must be mainnet, ledger fresh; everything read at ONE ledger version. The creator's Move modules
    are hashed (a change = an upgrade) and scanned for signature-verification primitives; the scan's control is
    0x1::account, which must be seen using ed25519."""
    try:
        li = _get_json(APTOS_API)
        version = li["ledger_version"]
        ts = int(li["ledger_timestamp"]) // 1_000_000
        node = {"chain_id": li["chain_id"], "expected_chain_id": APTOS_CHAIN_ID, "block": int(version),
                "block_timestamp": ts, "block_age_s": int((now if now is not None else time.time()) - ts)}
        if li["chain_id"] != APTOS_CHAIN_ID:
            return {"chain": "aptos", "assessed": False, "node": node, "reason": f"chain id {li['chain_id']} is not mainnet"}
        if node["block_age_s"] > MAX_BLOCK_AGE_S:
            return {"chain": "aptos", "assessed": False, "node": node,
                    "reason": f"stale node: ledger is {node['block_age_s']} s old (> {MAX_BLOCK_AGE_S} s)"}
        label, casset = APTOS_CONTROL
        cmeta = _apt_resources(casset, version).get("0x1::fungible_asset::Metadata") or {}
        acct = _get_json(f"{APTOS_API}/accounts/0x1/module/account?ledger_version={version}")
        ctl = {"token": label, "address": casset, "metadata_readable": bool(cmeta.get("symbol")),
               "bytecode_scan_sees_ed25519": "ed25519".encode().hex() in acct.get("bytecode", "")}
        ctl["ok"] = ctl["metadata_readable"] and ctl["bytecode_scan_sees_ed25519"]
        if not ctl["ok"]:
            return {"chain": "aptos", "assessed": False, "node": node, "control": ctl,
                    "reason": "positive control failed: asset metadata or bytecode scan not working on this node"}
        tokens = []
        for e in entries:
            res = _apt_resources(e["address"], version)
            md = res.get("0x1::fungible_asset::Metadata") or {}
            cs = res.get("0x1::fungible_asset::ConcurrentSupply") or {}
            sp = res.get("0x1::fungible_asset::Supply") or {}
            raw = (cs.get("current") or {}).get("value") if cs else sp.get("current")
            raw = int(raw) if raw is not None else None
            dec = md.get("decimals")
            owner = (res.get("0x1::object::ObjectCore") or {}).get("owner")
            mods = _get_json(f"{APTOS_API}/accounts/{owner}/modules?ledger_version={version}&limit=100") if owner else []
            code = "".join(sorted(m.get("bytecode", "") for m in mods))
            used = sorted(n for n in SIG_NEEDLES if n.encode().hex() in code)
            tokens.append({
                "token": e["token"], "address": e["address"], "provenance": e["provenance"],
                "name": md.get("name"), "symbol": md.get("symbol"), "decimals": dec,
                "total_supply_raw": str(raw) if raw is not None else None,
                "total_supply": raw / 10 ** dec if raw is not None and dec is not None else None,
                "owner": owner, "expected_owner": e["expected_owner"],
                "modules": sorted(m["abi"]["name"] for m in mods if m.get("abi")),
                "implementation_code_sha256": hashlib.sha256(code.encode()).hexdigest() if code else None,
                "signature_primitives_in_modules": used, "eip712_entry_points": [],
                "dispatchable_hooks": "0x1::fungible_asset::DispatchFunctionStore" in res})
            if tokens[-1]["symbol"] is None or tokens[-1]["total_supply"] is None:
                return {"chain": "aptos", "assessed": False, "node": node, "control": ctl,
                        "reason": f"{e['token']} at {e['address']}: symbol or supply not readable"}
        return {"chain": "aptos", "assessed": True, "block": int(version), "rpc": APTOS_API, "node": node, "control": ctl,
                "tokens": tokens, "discovery": {"status": "not searched (no search source for Aptos)", "unregistered": []}}
    except Exception as ex:
        return {"chain": "aptos", "assessed": False, "reason": f"{type(ex).__name__}: {str(ex)[:160]}"}


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


NETWORK_RETRIES = 1          # one retry on a TRANSPORT error only (25/09: a TLS handshake timeout on one node made a
                             # chain NOT ASSESSED for a transient fault); a node's JSON-RPC error is never retried


def rpc(chain, method, params, timeout=25):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(NETWORK_RETRIES + 1):
        req = urllib.request.Request(RPC[chain], data=body,
                                     headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, context=_CTX, timeout=timeout) as r:
                out = json.loads(r.read())
            break
        except (OSError, ssl.SSLError) as ex:          # URLError, timeouts and TLS errors are OSError subclasses
            if attempt == NETWORK_RETRIES:
                raise
            time.sleep(2)
    if "error" in out:
        raise RpcError(f"{method}: {out['error'].get('message', out['error'])}")
    return out.get("result")


def eth_call(chain, to, data, block):
    """None only when the call REVERTED (the function is not there): that is an answer. Any other node error
    (rate limit, internal error) is raised, so the chain becomes NOT ASSESSED instead of 'nothing found'."""
    try:
        return rpc(chain, "eth_call", [{"to": to, "data": data}, block])
    except RpcError as ex:
        if "revert" in str(ex).lower():
            return None
        raise


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


def read_owner(chain, address, block):
    o = eth_call(chain, address, "0x8da5cb5b", block)
    return ("0x" + o[-40:]).lower() if o and len(o) >= 66 else None


def read_token(chain, address, block):
    dec = _abi_uint(eth_call(chain, address, "0x313ce567", block))
    raw = _abi_uint(eth_call(chain, address, "0x18160ddd", block))
    return {
        "owner": read_owner(chain, address, block),
        "name": _abi_string(eth_call(chain, address, "0x06fdde03", block)),
        "symbol": _abi_string(eth_call(chain, address, "0x95d89b41", block)),
        "decimals": dec,
        "total_supply_raw": str(raw) if raw is not None else None,     # exact integer, as a string
        "total_supply": (raw / 10 ** dec) if raw is not None and dec is not None else None,
    }


def node_identity(chain, now=None):
    """Which chain the URL really serves, and how fresh its latest block is. `now` is injectable (tests: no wall clock)."""
    cid = int(rpc(chain, "eth_chainId", []), 16)
    head = rpc(chain, "eth_getBlockByNumber", ["latest", False])
    ts = int(head["timestamp"], 16)
    age = int((now if now is not None else time.time()) - ts)
    return {"chain_id": cid, "expected_chain_id": CHAIN_IDS[chain], "block": head["number"], "block_timestamp": ts,
            "block_age_s": age}


def _http_json(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, context=_CTX, timeout=timeout) as r:
        return json.loads(r.read())


def search_same_named(chain):
    """(status, [addresses]) of tokens an explorer lists under the watched names. Status says what was searched."""
    kind, base = DISCOVERY.get(chain, (None, None))
    if kind is None:
        return "not searched (no explorer search configured)", []
    found, errors = set(), []
    for term in DISCOVERY_TERMS:
        try:
            if kind == "blockscout":
                d = _http_json(f"{base}/api/v2/search?q={urllib.parse.quote(term)}")
                for it in d.get("items", []):
                    if it.get("type") == "token" and it.get("address_hash"):
                        found.add(it["address_hash"])
            else:
                d = _http_json(f"{base}?term={urllib.parse.quote(term)}&filterby=0")
                for it in d if isinstance(d, list) else []:
                    if str(it.get("group", "")).startswith("Tokens") and it.get("address"):
                        found.add(it["address"])
        except Exception as ex:                       # the explorer failed: say so, never read it as "none found"
            errors.append(f"{term}: {type(ex).__name__}")
    status = (f"searched {kind}, first result page per term" + (f" (errors: {'; '.join(errors)})" if errors else ""))
    return status, sorted(found, key=str.lower)


def classify_unregistered(chain, address, block):
    """What a same-named, unregistered token looks like on-chain. Never a verdict of fraud: a shape and a reading."""
    t = read_token(chain, address, block)
    s = read_structure(chain, address, block)
    shape = {"proxy_code_bytes": s["proxy_code_bytes"], "implementation_slot": s["implementation_slot"]}
    t.update({"address": address, "proxy_code_bytes": s["proxy_code_bytes"],
              "implementation_slot": s["implementation_slot"],
              "securitize_shape": shape in SECURITIZE_SHAPES, "same_owner": t.get("owner") == EXPECTED_OWNER})
    # "BUIDL" is a common crypto word used by projects older than the fund: a symbol alone proves nothing. What can be
    # said is only this: whether the token is owned by the issuer key, and whether it carries BlackRock's name.
    t["carries_blackrock_name"] = "blackrock" in (t.get("name") or "").lower()
    if t["same_owner"]:
        t["class"] = "owned by the issuer key but not in the registry: likely a new issuer deployment — check and add by hand"
    elif t["carries_blackrock_name"]:
        t["class"] = ("carries BlackRock's name, not owned by the issuer key: NOT an issuer deployment "
                      "(imitation, wrapper or third-party product — not told apart here)")
    else:
        t["class"] = "shares a search term only (e.g. the common word BUIDL): not classified"
    return t


def discover(chain, block, registered):
    status, addrs = search_same_named(chain)
    known = {a.lower() for a in registered}
    out = []
    for a in addrs:
        if a.lower() in known:
            continue
        try:
            out.append(classify_unregistered(chain, a, block))
        except Exception as ex:
            out.append({"address": a, "class": f"unreadable: {type(ex).__name__}"})
    # kept: owned by the issuer key, or carrying BlackRock's name; tokens sharing only a search term are counted
    kept = [u for u in out if u.get("same_owner") or u.get("carries_blackrock_name")]
    return {"status": status, "unregistered": kept, "other_matches_not_classified": len(out) - len(kept)}


def control_ok(chain, block):
    """The reader must SEE EIP-712 on a token that has it, on this node, at this block."""
    label, addr = CONTROLS[chain]
    s = read_structure(chain, addr, block)
    ok = "DOMAIN_SEPARATOR" in s["eip712_entry_points"] and s["domain_separator_answers"]
    return {"token": label, "address": addr, "ok": ok, "eip712_entry_points": s["eip712_entry_points"]}


def read_chain(chain, entries, now=None, discovery=True):
    """One chain: node identity (chain id, block age), positive control, then every registered token and, if
    enabled, same-named unregistered tokens. Any failure of the node checks makes the chain NOT ASSESSED."""
    try:
        node = node_identity(chain, now)
        if node["chain_id"] != node["expected_chain_id"]:
            return {"chain": chain, "assessed": False, "node": node,
                    "reason": f"the URL serves chain id {node['chain_id']}, not {node['expected_chain_id']}"}
        if node["block_age_s"] > MAX_BLOCK_AGE_S:
            return {"chain": chain, "assessed": False, "node": node,
                    "reason": f"stale node: latest block is {node['block_age_s']} s old (> {MAX_BLOCK_AGE_S} s)"}
        block = node["block"]
        ctl = control_ok(chain, block)
        if not ctl["ok"]:
            return {"chain": chain, "assessed": False, "block": int(block, 16), "control": ctl,
                    "reason": "positive control failed: the reader could not see EIP-712 where it exists"}
        tokens = []
        for e in entries:
            t = read_token(chain, e["address"], block)
            if t["symbol"] is None or t["total_supply"] is None:
                return {"chain": chain, "assessed": False, "node": node, "control": ctl,
                        "reason": f"{e['token']} at {e['address']}: symbol or supply not readable"}
            t.update(read_structure(chain, e["address"], block))
            if t["implementation"] is None and t["proxy_code_bytes"] < 1024:
                # a small proxy whose implementation this reader cannot locate: the EIP-712 scan would read the proxy
                # itself and report "absent" (NEMESIS 25/09) — not assessed instead of a false clean
                return {"chain": chain, "assessed": False, "node": node, "control": ctl,
                        "reason": f"{e['token']} at {e['address']}: proxy of {t['proxy_code_bytes']} bytes, implementation not located"}
            t.update({"token": e["token"], "address": e["address"], "provenance": e["provenance"],
                      "expected_owner": EXPECTED_OWNER})
            tokens.append(t)
        found = discover(chain, block, [e["address"] for e in entries]) if discovery else {"status": "disabled", "unregistered": []}
        return {"chain": chain, "assessed": True, "block": int(block, 16), "rpc": RPC[chain], "node": node,
                "control": ctl, "tokens": tokens, "discovery": found}
    except Exception as ex:                          # network, TLS, JSON: the chain is not assessed, and says why
        return {"chain": chain, "assessed": False, "reason": f"{type(ex).__name__}: {str(ex)[:160]}"}


def fetch_signal(now=None, discovery=True):
    """Real on-chain readings for every registered chain. `metric` = total BUIDL supply over the ASSESSED chains."""
    by_chain = {}
    for e in REGISTRY:
        by_chain.setdefault(e["chain"], []).append(e)
    chains = [read_chain(c, es, now, discovery) for c, es in by_chain.items()]
    chains.append(read_solana([e for e in NONEVM_REGISTRY if e["chain"] == "solana"], now))
    chains.append(read_aptos([e for e in NONEVM_REGISTRY if e["chain"] == "aptos"], now))
    total = 0.0
    for c in chains:
        for t in c.get("tokens", []):
            if t["token"] == "BUIDL" and t.get("total_supply") is not None:
                total += t["total_supply"]
    assessed = [c["chain"] for c in chains if c.get("assessed")]
    return {
        "metric": round(total, 6),
        "metric_meaning": "sum of BUIDL total supply over the assessed chains, EVM + Solana + Aptos (not AUM; BUIDL-I excluded)",
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
