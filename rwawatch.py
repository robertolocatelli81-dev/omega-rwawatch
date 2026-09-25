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
    "base": "https://base-rpc.publicnode.com",
}

# The chain each URL must answer for (eth_chainId). A load balancer that routes to another network would otherwise
# pass the positive control — USDC exists on every chain — and record another chain's state under this name.
CHAIN_IDS = {"ethereum": 1, "arbitrum": 42161, "optimism": 10, "polygon": 137, "avalanche": 43114, "bsc": 56,
             "base": 8453}
MAX_BLOCK_AGE_S = 900        # a node whose latest block is older than this is lagging: the chain is NOT ASSESSED

# Where same-named tokens are searched for (explorer search APIs; a chain without one is reported "not searched").
DISCOVERY = {
    "ethereum": ("blockscout", "https://eth.blockscout.com"),
    "arbitrum": ("blockscout", "https://arbitrum.blockscout.com"),
    "optimism": ("blockscout", "https://optimism.blockscout.com"),
    "polygon": ("blockscout", "https://polygon.blockscout.com"),
    "bsc": ("bscscan-search", "https://bscscan.com/searchHandler"),
}
DISCOVERY_TERMS = ("BUIDL", "BlackRock USD Institutional")      # BUIDL's (kept: the first searched)
# Per fund: the search terms and the issuer-name needle a same-named token is matched against (measured on Blockscout
# 25/09/2026: the bare term "BENJI" returns a full page of unrelated memecoins, so BENJI is searched by the fund name;
# "JPMorgan" alone returns tokenized JPMorgan Chase STOCKS, so JLTXX is searched by its ticker and fund name).
FUND_SEARCH = {
    "BUIDL": {"terms": DISCOVERY_TERMS, "needle": ("blackrock",)},
    "JLTXX": {"terms": ("JLTXX", "JPMorgan OnChain"), "needle": ("jpmorgan", "j.p. morgan")},
    # "Franklin Templeton BENJI" is how explorers index the OFFICIAL contracts (the search control needs it);
    # "Franklin OnChain" finds same-named tokens that carry the fund's legal name
    "BENJI": {"terms": ("Franklin Templeton BENJI", "Franklin OnChain"), "needle": ("franklin",)},
    "USYC": {"terms": ("USYC",), "needle": ("usyc",)},
}
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

# Other issuers' official address lists (checked 25/09/2026; sha256 of the raw HTML as fetched)
BENJI_PAGE = "https://digitalassets.franklintempleton.com/benji/benji-contracts/"
BENJI_OFFICIAL = f"listed on {BENJI_PAGE} (Benji DevHub, raw HTML sha256 58176ad2…)"
USYC_PAGE = "https://developers.circle.com/tokenized/usyc/smart-contracts"
USYC_OFFICIAL = f"listed on {USYC_PAGE} (Circle docs, raw HTML sha256 a6105f97…)"

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
    {"chain": "ethereum", "token": "JLTXX", "address": "0x09864f52B035AE22eE739dFa5c748fA080D07bD8",
     "provenance": "J.P. Morgan Asset Management press release 13/05/2026 (am.jpmorgan.com, raw HTML sha256 c3f91b60…, the only address in it)",
     "expected_owner": "0x5ae5d4ada523985dbab22cf046599979897c8418"},
    # MONY: FOUND by this watcher's search (owned by the key recorded for JLTXX), then confirmed on the issuer's
    # release — the only address in it. Same Diamond shape as JLTXX (16 facets, 68 selectors, 25/09/2026).
    {"chain": "ethereum", "token": "MONY", "address": "0x6a7c6aa2b8b8a6A891dE552bDEFFa87c3F53bD46",
     "provenance": "J.P. Morgan Asset Management press release 15/12/2025 (am.jpmorgan.com, raw HTML sha256 3dc77e38…, "
                   "the only address in it); found first by owner() in this watcher's search, 25/09/2026",
     "expected_owner": "0x5ae5d4ada523985dbab22cf046599979897c8418"},
    {"chain": "bsc", "token": "BUIDL", "address": "0x2D5BdC96D9C8AabBDB38c9A27398513e7E5ef84F",
     "provenance": "NOT on the official page (25/09/2026); BscScan search (is_checked, website securitize.io/blackrock/BUIDL) "
                   "and owner() equal to the owner of the six officially listed contracts"},
] + [
    # Franklin Templeton BENJI (FOBXX): no owner() on these contracts and an empty EIP-1967 admin slot (25/09/2026) —
    # control sits in Franklin's own modules, not watched here; expected_owner None = no owner check, said, not faked
    {"chain": ch, "token": "BENJI", "address": a, "provenance": BENJI_OFFICIAL, "expected_owner": None}
    for ch, a in (("ethereum", "0x3DDc84940Ab509C11B20B76B466933f40b750dc9"),
                  ("polygon", "0x408A634B8a8f0dE729B48574a3a7Ec3fE820B00A"),
                  ("arbitrum", "0xB9e4765BCE2609bC1949592059B17Ea72fEe6C6A"),
                  ("avalanche", "0xE08b4c1005603427420e64252a8b120cacE4D122"),
                  ("base", "0x60CfC2b186a4CF647486e42c42B11cC6D571d1E4"))
] + [
    # Circle USYC: owner() an externally owned account on each chain (measured 25/09/2026)
    {"chain": "ethereum", "token": "USYC", "address": "0x136471a34f6ef19fE571EFFC1CA711fdb8E49f2b",
     "provenance": USYC_OFFICIAL, "expected_owner": "0x13ff8cabb86edf94a2df4f98773bda4005182dd6"},
    {"chain": "bsc", "token": "USYC", "address": "0x8D0fA28f221eB5735BC71d3a0Da67EE5bC821311",
     "provenance": USYC_OFFICIAL, "expected_owner": "0xcd636d955a95385ec5e2776b167b92e89ef6f70e"},
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
    "base": ("USDC", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
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
    # BENJI on Solana: the mint is its own mint authority (a program-derived setup, measured 25/09/2026)
    {"chain": "solana", "token": "BENJI", "address": "5Tu84fKBpe9vfXeotjvfvWdWbAjy3hqsExvuHgFqFxA1",
     "provenance": BENJI_OFFICIAL, "expected_owner": "5Tu84fKBpe9vfXeotjvfvWdWbAjy3hqsExvuHgFqFxA1"},
    {"chain": "solana", "token": "USYC", "address": "7LWanZteUKtvFjv4MHYgKXXdAuCQYFPJysL9pxxdRQGn",
     "provenance": USYC_OFFICIAL, "expected_owner": "DZ7j2YLDq7847t2HtCWaDQUTpLJ4BinPGsY8w9Aai63y"},
    # BENJI on Aptos: the object owner is the address the official page lists as "Authorization Module"
    {"chain": "aptos", "token": "BENJI", "address": "0x7b5e9cac3433e9202f28527f707c89e1e47b19de2c33e4db9521a63ad219b739",
     "provenance": BENJI_OFFICIAL, "expected_owner": "0x4705f33d665762a5371d3b8786e63749814e749295ea73269b379c84b756d83a"},
    # BENJI on Stellar: a classic issued asset; its "owner" is the issuer account's signer set + thresholds, recorded as
    # a SHA-256 fingerprint (25/09/2026: master key weight 0, 14 signers, thresholds 2/2/6)
    {"chain": "stellar", "token": "BENJI", "address": "GBHNGLLIE3KWGKCHIKMHJ5HVZHYIK7WTBE4QF5PLAKL4CJGSEU7HZIW5",
     "provenance": BENJI_OFFICIAL,
     "expected_owner": "signers-sha256:04d548a15365ed81974e173dfb4d40e75a520b874f680655e7b296f312431bd5"},
]
STELLAR_HORIZON = "https://horizon.stellar.org"
STELLAR_PASSPHRASE = "Public Global Stellar Network ; September 2015"
STELLAR_CONTROL = ("USDC", "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN")
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


def _stellar_asset(code, issuer):
    recs = _get_json(f"{STELLAR_HORIZON}/assets?asset_code={code}&asset_issuer={issuer}")["_embedded"]["records"]
    return recs[0] if len(recs) == 1 else None


def _stellar_amount(asset):
    """Every place an issued Stellar asset can sit, in stroops (7 decimals, exact integer arithmetic)."""
    def stroops(x):
        whole, _, frac = str(x).partition(".")
        return int(whole) * 10 ** 7 + int((frac + "0000000")[:7])
    b = asset["balances"]
    parts = [b["authorized"], b["authorized_to_maintain_liabilities"], b["unauthorized"],
             asset["claimable_balances_amount"], asset["liquidity_pools_amount"], asset["contracts_amount"]]
    return sum(stroops(x) for x in parts)


def stellar_signers_fingerprint(account):
    """SHA-256 of the issuer account's signer set and thresholds: who can sign for the asset."""
    body = {"signers": sorted((s["key"], s["weight"]) for s in account.get("signers", [])),
            "thresholds": account.get("thresholds")}
    return "signers-sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def read_stellar(entries, now=None):
    """Stellar (Horizon): the network passphrase must be pubnet, the latest ledger fresh, USDC readable with a
    non-zero amount. Horizon serves the CURRENT state only: the ledger is recorded before and after the readings."""
    try:
        root = _get_json(STELLAR_HORIZON + "/")
        ts = int(datetime.strptime(root["history_latest_ledger_closed_at"], "%Y-%m-%dT%H:%M:%SZ")
                 .replace(tzinfo=timezone.utc).timestamp())
        node = {"chain_id": root["network_passphrase"], "expected_chain_id": STELLAR_PASSPHRASE,
                "block": root["history_latest_ledger"], "block_timestamp": ts,
                "block_age_s": int((now if now is not None else time.time()) - ts)}
        if root["network_passphrase"] != STELLAR_PASSPHRASE:
            return {"chain": "stellar", "assessed": False, "node": node, "reason": "network passphrase is not pubnet"}
        if node["block_age_s"] > MAX_BLOCK_AGE_S:
            return {"chain": "stellar", "assessed": False, "node": node,
                    "reason": f"stale node: latest ledger is {node['block_age_s']} s old (> {MAX_BLOCK_AGE_S} s)"}
        label, cissuer = STELLAR_CONTROL
        ca = _stellar_asset(label, cissuer)
        ctl = {"token": label, "address": cissuer, "ok": bool(ca) and _stellar_amount(ca) > 0 and "flags" in ca}
        if not ctl["ok"]:
            return {"chain": "stellar", "assessed": False, "node": node, "control": ctl,
                    "reason": "positive control failed: a known asset could not be read on this node"}
        tokens = []
        for e in entries:
            a = _stellar_asset(e["token"], e["address"])
            acct = _get_json(f"{STELLAR_HORIZON}/accounts/{e['address']}")
            raw = _stellar_amount(a) if a else None
            tokens.append({
                "token": e["token"], "address": e["address"], "provenance": e["provenance"],
                "name": acct.get("home_domain"), "symbol": a["asset_code"] if a else None, "decimals": 7,
                "total_supply_raw": str(raw) if raw is not None else None,
                "total_supply": raw / 10 ** 7 if raw is not None else None,
                "owner": stellar_signers_fingerprint(acct), "expected_owner": e["expected_owner"],
                "flags": a["flags"] if a else None, "contract_id": a.get("contract_id") if a else None,
                "implementation_code_sha256": hashlib.sha256(json.dumps(
                    {"flags": a["flags"], "contract_id": a.get("contract_id")}, sort_keys=True).encode()).hexdigest() if a else None,
                "eip712_entry_points": []})
            if tokens[-1]["symbol"] is None or tokens[-1]["total_supply"] is None:
                return {"chain": "stellar", "assessed": False, "node": node, "control": ctl,
                        "reason": f"{e['token']} issued by {e['address']}: asset not readable"}
        node["block_after"] = _get_json(STELLAR_HORIZON + "/")["history_latest_ledger"]
        return {"chain": "stellar", "assessed": True, "block": node["block"], "rpc": STELLAR_HORIZON, "node": node,
                "control": ctl, "tokens": tokens,
                "discovery": {"status": "not searched (no search source for Stellar)", "unregistered": []}}
    except Exception as ex:
        return {"chain": "stellar", "assessed": False, "reason": f"{type(ex).__name__}: {str(ex)[:160]}"}


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


def _abi_address_array(h):
    b = bytes.fromhex(h[2:])
    n = int.from_bytes(b[32:64], "big")
    return ["0x" + b[64 + 32 * i + 12:64 + 32 * i + 32].hex() for i in range(n)]


def _abi_bytes4_array(h):
    b = bytes.fromhex(h[2:])
    n = int.from_bytes(b[32:64], "big")
    return [b[64 + 32 * i:64 + 32 * i + 4].hex() for i in range(n)]


def read_diamond(chain, address, block):
    """EIP-2535 Diamond (JPMorgan's JLTXX is one): functions live in many facets, so the only sound question is the
    Diamond's own loupe — which selectors are registered, and in which facets. Internal control: name() must map to a
    facet. Returns None when the contract does not answer the loupe."""
    fa = eth_call(chain, address, "0x52ef6b2c", block)                # facetAddresses()
    if not fa or len(fa) < 130:
        return None
    facets = _abi_address_array(fa)
    selectors, codes = set(), []
    for f in sorted(facets, key=str.lower):
        r = eth_call(chain, address, "0xadfca15e" + "0" * 24 + f[2:], block)   # facetFunctionSelectors(address)
        selectors |= set(_abi_bytes4_array(r)) if r else set()
        codes.append(rpc(chain, "eth_getCode", [f, block]) or "0x")
    name_facet = eth_call(chain, address, "0xcdffacc6" + "06fdde03" + "0" * 56, block)   # facetAddress(name())
    return {"facets": len(facets), "selectors_registered": len(selectors),
            "loupe_control_ok": bool(name_facet) and int(name_facet, 16) != 0,
            "code_sha256": hashlib.sha256("".join(codes).encode()).hexdigest(),
            "eip712_entry_points": sorted(k for k, s in SELECTORS.items() if s in selectors)}


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
    ds = eth_call(chain, address, "0x" + SELECTORS["DOMAIN_SEPARATOR"], block)
    if impl is None:
        dm = read_diamond(chain, address, block)
        if dm is not None and dm["loupe_control_ok"]:
            return {"proxy_code_bytes": max(len(proxy_code) // 2 - 1, 0), "implementation": f"diamond:{dm['facets']} facets",
                    "implementation_slot": "eip2535", "implementation_code_sha256": dm["code_sha256"],
                    "diamond": {"facets": dm["facets"], "selectors_registered": dm["selectors_registered"]},
                    "eip712_entry_points": dm["eip712_entry_points"], "domain_separator_answers": bool(ds and len(ds) > 2)}
    exposed = sorted(k for k, s in SELECTORS.items() if s in impl_code)
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
    """(status, {address: fund}) of tokens an explorer lists under the watched funds' names. A token found under
    several funds' terms is attributed to the first fund searched. Status says what was searched."""
    kind, base = DISCOVERY.get(chain, (None, None))
    if kind is None:
        return "not searched (no explorer search configured)", {}
    found, errors = {}, []
    for fund, spec in FUND_SEARCH.items():
        for term in spec["terms"]:
            try:
                if kind == "blockscout":
                    d = _http_json(f"{base}/api/v2/search?q={urllib.parse.quote(term)}")
                    hits = [it["address_hash"] for it in d.get("items", [])
                            if it.get("type") == "token" and it.get("address_hash")]
                else:
                    d = _http_json(f"{base}?term={urllib.parse.quote(term)}&filterby=0")
                    hits = [it["address"] for it in (d if isinstance(d, list) else [])
                            if str(it.get("group", "")).startswith("Tokens") and it.get("address")]
                for a in hits:
                    found.setdefault(a, fund)
            except Exception as ex:                   # the explorer failed: say so, never read it as "none found"
                errors.append(f"{term}: {type(ex).__name__}")
    status = (f"searched {kind}, first result page per term, {len(FUND_SEARCH)} funds"
              + (f" (errors: {'; '.join(errors)})" if errors else ""))
    return status, dict(sorted(found.items(), key=lambda kv: kv[0].lower()))


def _fund_owners(fund):
    """Every control key recorded for a fund, all chains; empty when the fund exposes none (BENJI on EVM)."""
    owners = {str(e.get("expected_owner", EXPECTED_OWNER)).lower() for e in REGISTRY if e["token"] == fund
              and e.get("expected_owner", EXPECTED_OWNER)}
    return owners


def classify_unregistered(chain, address, block, fund="BUIDL"):
    """What a same-named, unregistered token looks like on-chain. Never a verdict of fraud: a shape and a reading."""
    t = read_token(chain, address, block)
    s = read_structure(chain, address, block)
    shape = {"proxy_code_bytes": s["proxy_code_bytes"], "implementation_slot": s["implementation_slot"]}
    owners = _fund_owners(fund)
    t.update({"address": address, "fund": fund, "proxy_code_bytes": s["proxy_code_bytes"],
              "implementation_slot": s["implementation_slot"],
              "securitize_shape": shape in SECURITIZE_SHAPES,
              # None = not comparable: the fund's registered contracts expose no owner()
              "same_owner": (str(t.get("owner")).lower() in owners) if owners else None})
    # A ticker alone proves nothing ("BUIDL" is older than the fund). What can be said is only this: whether the token
    # is owned by a key recorded for the fund, and whether its name carries the issuer's / fund's name.
    name = (t.get("name") or "").lower()
    t["carries_issuer_name"] = any(n in name for n in FUND_SEARCH[fund]["needle"])
    if t["same_owner"]:
        t["class"] = f"owned by a key recorded for {fund} but not in the registry: likely a new issuer deployment — check and add by hand"
    elif t["carries_issuer_name"] and t["same_owner"] is None:
        t["class"] = (f"carries the {fund} issuer's name; owner not comparable ({fund}'s registered contracts expose no "
                      "owner()): an older or other issuer deployment, a wrapper or an imitation — not told apart here")
    elif t["carries_issuer_name"]:
        t["class"] = (f"carries the {fund} issuer's name, not owned by a key recorded for {fund}: not a deployment of "
                      "the registered key (imitation, wrapper, or another product of the issuer — not told apart here)")
    else:
        t["class"] = "shares a search term only (e.g. a common ticker word): not classified"
    return t


def discover(chain, block, registered):
    status, hits = search_same_named(chain)
    known = {a.lower() for a in registered}
    # Positive control of the SEARCH, per fund registered on this chain: its registered token must be among the hits.
    # If not, the explorer cannot see that fund here and "nothing found" means nothing (25/09: BscScan returns [] for
    # every USYC term, yet USYC is on BNB Chain).
    found = {a.lower() for a in hits}
    by_fund = {}
    for e in REGISTRY:
        if e["chain"] == chain and e["address"].lower() in known and e["token"] in FUND_SEARCH:
            by_fund[e["token"]] = by_fund.get(e["token"], False) or e["address"].lower() in found
    blind = sorted(f for f, ok in by_fund.items() if not ok)
    if blind and not status.startswith("not searched"):
        status += f"; search control FAILED for {', '.join(blind)} (the registered token is not in the results: " \
                  "no finding for that fund here is meaningful)"
    out = []
    for a, fund in hits.items():
        if a.lower() in known:
            continue
        try:
            out.append(classify_unregistered(chain, a, block, fund))
        except Exception as ex:
            out.append({"address": a, "fund": fund, "class": f"unreadable: {type(ex).__name__}"})
    # kept: owned by the issuer key, or carrying BlackRock's name; tokens sharing only a search term are counted.
    # A token that could not be READ is neither (25/09: six Polygon reads failed in one cycle and silently joined the
    # "not classified" count while the council said QUIET): listed apart, and the council flags it.
    unreadable = [u["address"] for u in out if str(u.get("class", "")).startswith("unreadable")]
    kept = [u for u in out if u.get("same_owner") or u.get("carries_issuer_name")]
    return {"status": status, "unregistered": kept, "unreadable": unreadable, "search_control": by_fund,
            "other_matches_not_classified": len(out) - len(kept) - len(unreadable)}


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
            if t["implementation"] is None and t["proxy_code_bytes"] < 1024:   # (a Diamond answers its loupe: not here)
                # a small proxy whose implementation this reader cannot locate: the EIP-712 scan would read the proxy
                # itself and report "absent" (NEMESIS 25/09) — not assessed instead of a false clean
                return {"chain": chain, "assessed": False, "node": node, "control": ctl,
                        "reason": f"{e['token']} at {e['address']}: proxy of {t['proxy_code_bytes']} bytes, implementation not located"}
            t.update({"token": e["token"], "address": e["address"], "provenance": e["provenance"],
                      "expected_owner": e.get("expected_owner", EXPECTED_OWNER)})
            tokens.append(t)
        found = discover(chain, block, [e["address"] for e in entries]) if discovery else {"status": "disabled", "unregistered": []}
        return {"chain": chain, "assessed": True, "block": int(block, 16), "rpc": RPC[chain], "node": node,
                "control": ctl, "tokens": tokens, "discovery": found}
    except Exception as ex:                          # network, TLS, JSON: the chain is not assessed, and says why
        return {"chain": chain, "assessed": False, "reason": f"{type(ex).__name__}: {str(ex)[:160]}"}


def fetch_signal(now=None, discovery=True):
    """Real readings for every registered chain. `metric` = total BUIDL supply over the ASSESSED chains (kept as the
    tuned series); `totals` = the same sum for every watched token, over the chains assessed this run."""
    by_chain = {}
    for e in REGISTRY:
        by_chain.setdefault(e["chain"], []).append(e)
    chains = [read_chain(c, es, now, discovery) for c, es in by_chain.items()]
    chains.append(read_solana([e for e in NONEVM_REGISTRY if e["chain"] == "solana"], now))
    chains.append(read_aptos([e for e in NONEVM_REGISTRY if e["chain"] == "aptos"], now))
    chains.append(read_stellar([e for e in NONEVM_REGISTRY if e["chain"] == "stellar"], now))
    totals = {}
    for c in chains:
        for t in c.get("tokens", []):
            if t.get("total_supply") is not None:
                totals[t["token"]] = totals.get(t["token"], 0.0) + t["total_supply"]
    assessed = [c["chain"] for c in chains if c.get("assessed")]
    return {
        "metric": round(totals.get("BUIDL", 0.0), 6),
        "metric_meaning": "sum of BUIDL total supply over the assessed chains, EVM + Solana + Aptos (not AUM; BUIDL-I excluded)",
        "totals": {k: round(v, 6) for k, v in sorted(totals.items())},
        "totals_meaning": "per token, sum of total supply over the chains assessed this run (not AUM, not NAV)",
        "chains_assessed": assessed,
        "chains_not_assessed": [c["chain"] for c in chains if not c.get("assessed")],
        "chains": chains,
        "source": "public JSON-RPC nodes (publicnode.com), Solana/Aptos public RPC, Stellar Horizon; block recorded per chain",
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
