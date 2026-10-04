#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA-RWAWatch · tests — hash-chain integrity, the positive control, council determinism and its facets,
self-improve non-regression, and the evidence path. Stdlib unittest, NO network: a fake RPC answers.
Every write goes to a temporary directory: the module paths are redirected before any cycle runs."""
import copy
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))   # repo root on path
import rwawatch as core                     # noqa: E402
import rwawatch_agents as agents            # noqa: E402
import rwawatch_orchestrator as orch        # noqa: E402

PROD_PATHS = (orch.MEMORY, orch.LATEST, orch.EVIDENCE_DIR, orch.KEY_PATH)   # captured at import, asserted untouched


def _fingerprint(path):
    """(exists, size, sha256) of a production file: a test must leave it exactly as it found it."""
    import hashlib
    if not os.path.exists(path):
        return (False, None, None)
    with open(path, "rb") as f:
        data = f.read()
    return (True, len(data), hashlib.sha256(data).hexdigest())


def _token(chain, supply, impl_hash="aa", eps=(), address=None, owner=core.EXPECTED_OWNER):
    return {"token": "BUIDL", "address": address or f"0x{chain[:4].encode().hex():0<40}", "symbol": "BUIDL", "owner": owner,
            "expected_owner": core.EXPECTED_OWNER,
            "total_supply": supply,
            "total_supply_raw": str(int(round(supply * 10 ** 6))), "decimals": 6,
            "implementation_code_sha256": impl_hash, "eip712_entry_points": list(eps)}


def _snap(supplies, not_assessed=(), impl=None, eps=None, addr=None, owner=None, unregistered=None):
    chains = [{"chain": c, "assessed": True, "block": 1, "node": {"chain_id": core.CHAIN_IDS.get(c, 0)},
               "discovery": {"status": "test", "unregistered": (unregistered or {}).get(c, [])},
               "tokens": [_token(c, s, (impl or {}).get(c, "aa"), (eps or {}).get(c, ()), (addr or {}).get(c),
                                 (owner or {}).get(c, core.EXPECTED_OWNER))]} for c, s in supplies.items()]
    chains += [{"chain": c, "assessed": False, "reason": "test"} for c in not_assessed]
    return {"timestamp_utc": "2026-01-01T00:00:00+00:00", "domain": "rwawatch",
            "signal": {"metric": sum(supplies.values()), "chains_assessed": list(supplies),
                       "chains_not_assessed": list(not_assessed), "chains": chains}}


class TestChain(unittest.TestCase):
    def test_append_and_verify(self):
        recs = []
        for m in (10, 20, 30):
            core.append(recs, {"snapshot": _snap({"ethereum": m})})
        ok, msg = core.verify_chain(recs)
        self.assertTrue(ok, msg)
        self.assertEqual(recs[0]["prev_hash"], core.GENESIS)

    def test_tamper_detected(self):
        recs = []
        core.append(recs, {"snapshot": _snap({"ethereum": 10})})
        core.append(recs, {"snapshot": _snap({"ethereum": 20})})
        recs[0]["snapshot"]["signal"]["metric"] = 999
        self.assertFalse(core.verify_chain(recs)[0])


class FakeNode:
    """Answers eth_* like a node: a proxy at BUIDL whose implementation lacks EIP-712, and a control token with it."""
    def __init__(self, control_has_eip712=True, chain_id=None, block_ts=1_000_000, owner=core.EXPECTED_OWNER,
                 fail_selector=None, impl_slot=True, symbol=b"BUIDL", diamond=None, revert_selector=None,
                 beacon=None, impl_code=None, admin_member=None):
        self.revert_selector = revert_selector
        self.symbol, self.diamond = symbol, diamond      # diamond: None, or {"selectors": [...], "name_mapped": bool}
        self.control_has, self.chain_id, self.block_ts = control_has_eip712, chain_id, block_ts
        self.owner, self.fail_selector, self.impl_slot = owner, fail_selector, impl_slot
        # beacon: None (slot empty) | "ok" (implementation() -> 0x11..) | "revert" | "nocode" (-> an address w/o code)
        # impl_code: the code at 0x11.. ; admin_member: None (no AccessControl) or (address, has_role) for role 0x00
        self.beacon, self.impl_code, self.admin_member = beacon, impl_code or ("0x60" + "00" * 200), admin_member

    def __call__(self, chain, method, params, timeout=25):
        if method == "eth_blockNumber":
            return "0x10"
        if method == "eth_chainId":
            return hex(self.chain_id if self.chain_id is not None else core.CHAIN_IDS[chain])
        if method == "eth_getBlockByNumber":
            return {"number": "0x10", "timestamp": hex(self.block_ts)}
        addr = params[0]["to"] if method == "eth_call" else params[0]
        ctl = core.CONTROLS[chain][1].lower()
        if method == "eth_getCode":
            if addr.lower() == "0x" + "f1" * 20:
                return "0x60" + "01" * 300                                  # a facet's code
            if addr.lower() == "0x" + "11" * 20:
                return self.impl_code                                       # implementation code (default: no EIP-712)
            if addr.lower() == "0x" + "77" * 20:
                return "0x"                                                 # an address WITHOUT code
            if addr.lower() == ctl:
                return "0x" + ("3644e515d505accf" if self.control_has else "00") * 120
            return "0x" + "00" * 170
        if method == "eth_getStorageAt":
            if self.impl_slot and addr.lower() != ctl and params[1] == core.PROXY_SLOTS["eip1967"]:
                return "0x" + "00" * 12 + "11" * 20
            if self.beacon and addr.lower() != ctl and params[1] == core.BEACON_SLOT:
                return "0x" + "00" * 12 + "b1" * 20                           # the BEACON's address
            return "0x" + "00" * 32
        if method == "eth_call":
            data = params[0]["data"]
            if addr.lower() == "0x" + "b1" * 20:                              # the beacon
                if data == core.BEACON_IMPL_SELECTOR and self.beacon == "ok":
                    return "0x" + "00" * 12 + "11" * 20
                if data == core.BEACON_IMPL_SELECTOR and self.beacon == "nocode":
                    return "0x" + "00" * 12 + "77" * 20
                raise core.RpcError("execution reverted")
            if data.startswith(("0x" + core.ACCESS_CONTROL_SELECTORS["getRoleMemberCount"],
                                "0x" + core.ACCESS_CONTROL_SELECTORS["getRoleMember"],
                                "0x" + core.ACCESS_CONTROL_SELECTORS["hasRole"])):
                if not self.admin_member or addr.lower() == ctl:
                    raise core.RpcError("execution reverted")                 # no AccessControl here
                member, has = self.admin_member
                if data.startswith("0x" + core.ACCESS_CONTROL_SELECTORS["getRoleMemberCount"]):
                    return "0x" + "0" * 63 + "1"
                if data.startswith("0x" + core.ACCESS_CONTROL_SELECTORS["getRoleMember"]):
                    if data.endswith("0" * 64):
                        return "0x" + "00" * 12 + member[2:]
                    raise core.RpcError("execution reverted: panic: array out-of-bounds access (0x32)")
                return "0x" + "0" * 63 + ("1" if has and data.endswith(member[2:].lower()) else "0")
            if self.revert_selector and data.startswith(self.revert_selector) and addr.lower() != ctl:
                raise core.RpcError("execution reverted")
            if self.fail_selector and data.startswith(self.fail_selector) and addr.lower() != ctl:
                raise core.RpcError("eth_call: header not found")                # a node fault, not a revert
            if data.startswith(("0x52ef6b2c", "0xadfca15e", "0xcdffacc6")):   # EIP-2535 loupe
                if not self.diamond or addr.lower() == ctl:
                    raise core.RpcError("execution reverted")                    # not a Diamond: the loupe reverts
                word = lambda x: x.rjust(64, "0")
                if data == "0x52ef6b2c":
                    return "0x" + word("20") + word("1") + word("f1" * 20)
                if data.startswith("0xadfca15e"):
                    sels = self.diamond["selectors"]
                    return "0x" + word("20") + word(hex(len(sels))[2:]) + "".join(x.ljust(64, "0") for x in sels)
                return "0x" + word("f1" * 20 if self.diamond["name_mapped"] else "0")
            if data == "0x8da5cb5b":
                if self.owner is None:
                    raise core.RpcError("execution reverted")                    # no owner(): IBITon's shape
                return "0x" + "00" * 12 + self.owner[2:]
            if data == "0x3644e515":
                if addr.lower() == ctl and self.control_has:
                    return "0x" + "ab" * 32
                raise core.RpcError("execution reverted")
            if data == "0x313ce567":
                return "0x" + "0" * 63 + "6"
            if data == "0x18160ddd":
                return hex(5_000_000 * 10 ** 6)
            if data in ("0x06fdde03", "0x95d89b41"):
                s = self.symbol
                return "0x" + (32).to_bytes(32, "big").hex() + len(s).to_bytes(32, "big").hex() + s.hex().ljust(64, "0")
        raise AssertionError(f"unexpected {method} {params}")


NOW = 1_000_100          # injected clock: the fake block is 100 s old; no test reads the wall clock
ENTRY = [{"token": "BUIDL", "address": "0x" + "22" * 20, "provenance": "test"}]


class TestReader(unittest.TestCase):
    def setUp(self):
        self._rpc = core.rpc

    def tearDown(self):
        core.rpc = self._rpc

    def test_reads_supply_and_absence_of_eip712(self):
        core.rpc = FakeNode(True)
        c = core.read_chain("arbitrum", ENTRY, now=NOW, discovery=False)
        self.assertTrue(c["assessed"], c)
        t = c["tokens"][0]
        self.assertEqual((t["symbol"], t["total_supply"], t["implementation_slot"]), ("BUIDL", 5_000_000.0, "eip1967"))
        self.assertEqual(t["eip712_entry_points"], [])
        self.assertFalse(t["domain_separator_answers"])

    def test_failed_positive_control_means_not_assessed(self):
        core.rpc = FakeNode(False)
        c = core.read_chain("arbitrum", ENTRY, now=NOW, discovery=False)
        self.assertFalse(c["assessed"])
        self.assertIn("positive control failed", c["reason"])
        self.assertNotIn("tokens", c)                                      # no reading is reported as clean

    def test_node_failure_is_not_assessed_not_a_crash(self):
        def dead(*a, **k):
            raise OSError("connection refused")
        core.rpc = dead
        c = core.read_chain("bsc", ENTRY, now=NOW, discovery=False)
        self.assertFalse(c["assessed"])
        self.assertIn("OSError", c["reason"])

    def test_one_transport_retry_then_not_assessed(self):
        import urllib.request as ur
        calls = {"n": 0}
        real_urlopen, real_sleep = ur.urlopen, core.time.sleep

        def flaky(*a, **k):
            calls["n"] += 1
            raise OSError("handshake timed out")
        ur.urlopen, core.time.sleep = flaky, (lambda s: None)
        try:
            with self.assertRaises(OSError):
                self._rpc("arbitrum", "eth_blockNumber", [])
        finally:
            ur.urlopen, core.time.sleep = real_urlopen, real_sleep
        self.assertEqual(calls["n"], 2)       # retried exactly once, then the error surfaces (a literal: 25/09 ablation
                                              # showed NETWORK_RETRIES + 1 followed any value of the constant)
        # and a transient fault followed by an answer is read, not lost
        calls["n"] = 0

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b'{"jsonrpc":"2.0","id":1,"result":"0x10"}'

        def once(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("handshake timed out")
            return _Resp()
        ur.urlopen, core.time.sleep = once, (lambda s: None)
        try:
            self.assertEqual(self._rpc("arbitrum", "eth_blockNumber", []), "0x10")
        finally:
            ur.urlopen, core.time.sleep = real_urlopen, real_sleep

    def test_wrong_chain_behind_the_url_is_not_assessed(self):
        core.rpc = FakeNode(True, chain_id=42161)                          # an Arbitrum node answering for Optimism
        c = core.read_chain("optimism", ENTRY, now=NOW, discovery=False)
        self.assertFalse(c["assessed"])
        self.assertIn("chain id 42161, not 10", c["reason"])

    def test_stale_node_is_not_assessed(self):
        core.rpc = FakeNode(True, block_ts=NOW - core.MAX_BLOCK_AGE_S - 1)
        c = core.read_chain("arbitrum", ENTRY, now=NOW, discovery=False)
        self.assertFalse(c["assessed"])
        self.assertIn("stale node", c["reason"])

    def test_node_fault_on_a_read_is_not_absence(self):
        core.rpc = FakeNode(True, fail_selector="0x18160ddd")               # totalSupply: 'header not found'
        c = core.read_chain("polygon", ENTRY, now=NOW, discovery=False)
        self.assertFalse(c["assessed"], c)
        self.assertIn("RpcError", c["reason"])

    def test_reverting_supply_is_not_assessed(self):
        # a REVERT on totalSupply() reads as None (not an RpcError): the chain must still be NOT ASSESSED, never a
        # token with no supply summed as zero (25/09 ablation: no test covered this branch)
        core.rpc = FakeNode(True, revert_selector="0x18160ddd")
        c = core.read_chain("polygon", ENTRY, now=NOW, discovery=False)
        self.assertFalse(c["assessed"], c)
        self.assertIn("symbol or supply not readable", c["reason"])

    def test_proxy_without_located_implementation_is_not_assessed(self):
        core.rpc = FakeNode(True, impl_slot=False)
        c = core.read_chain("arbitrum", ENTRY, now=NOW, discovery=False)
        self.assertFalse(c["assessed"])
        self.assertIn("implementation not located", c["reason"])

    def test_search_classifies_per_fund(self):
        # BENJI: the registered EVM contracts expose no owner() → owner NOT comparable, never "same" nor "different"
        core.rpc = FakeNode(True, owner="0x" + "ab" * 20, symbol=b"Franklin OnChain U.S. Government Money Fund")
        u = core.classify_unregistered("arbitrum", "0x" + "33" * 20, "0x10", "BENJI")
        self.assertIsNone(u["same_owner"])
        self.assertIn("owner not comparable", u["class"])
        # USYC: a key recorded for the fund on ANOTHER chain counts (owners differ per chain)
        core.rpc = FakeNode(True, owner="0xcd636d955a95385ec5e2776b167b92e89ef6f70e", symbol=b"Circle USYC")
        u = core.classify_unregistered("arbitrum", "0x" + "33" * 20, "0x10", "USYC")
        self.assertTrue(u["same_owner"])
        # JLTXX: a BlackRock-named token found under JLTXX's terms does not carry JPMorgan's name → not classified
        core.rpc = FakeNode(True, owner="0x" + "ab" * 20, symbol=b"BlackRock USD Institutional Digital Liquidity Fund")
        u = core.classify_unregistered("arbitrum", "0x" + "33" * 20, "0x10", "JLTXX")
        self.assertIn("not classified", u["class"])

    def test_same_named_token_classified_by_owner(self):
        core.rpc = FakeNode(True, owner="0x" + "ab" * 20, symbol=b"BlackRock USD Institutional Digital Liquidity Fund")
        u = core.classify_unregistered("arbitrum", "0x" + "33" * 20, "0x10")     # name (and symbol) carry BlackRock's name
        self.assertFalse(u["same_owner"])
        self.assertIn("not a deployment of the registered key", u["class"])
        core.rpc = FakeNode(True, owner="0x" + "ab" * 20, symbol=b"BUIDL")        # the common word alone: not classified
        u = core.classify_unregistered("arbitrum", "0x" + "33" * 20, "0x10")
        self.assertIn("not classified", u["class"])
        core.rpc = FakeNode(True)
        u = core.classify_unregistered("arbitrum", "0x" + "33" * 20, "0x10")
        self.assertTrue(u["same_owner"])
        self.assertIn("new issuer deployment", u["class"])


class TestNonEvm(unittest.TestCase):
    """Solana and Aptos readers, offline: the network identity, freshness and positive control gates."""
    def setUp(self):
        self._post, self._get = core._post_json, core._get_json

    def tearDown(self):
        core._post_json, core._get_json = self._post, self._get

    @staticmethod
    def _sol(genesis=core.SOLANA_GENESIS, bt=1_000_000, control_ext=("permanentDelegate", "transferHook")):
        def post(url, method, params, timeout=25):
            if method == "getGenesisHash":
                return genesis
            if method == "getSlot":
                return 450
            if method == "getBlockTime":
                return bt
            if method == "getAccountInfo":
                ext = control_ext if params[0] == core.SOLANA_CONTROL[1] else ("permanentDelegate", "transferHook", "tokenMetadata")
                exts = [{"extension": e, "state": ({"name": "BlackRock USD Institutional Digital Liquidity Fund", "symbol": "BUIDL"}
                                                   if e == "tokenMetadata" else {"delegate": "D", "programId": "H"})} for e in ext]
                return {"context": {"slot": 450}, "value": {"owner": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                        "data": {"parsed": {"info": {"decimals": 6, "supply": "987784165650000", "mintAuthority": "APm3",
                                                     "freezeAuthority": "APm3", "extensions": exts}}}}}
            raise AssertionError(method)
        return post

    def test_solana_reads_and_gates(self):
        e = [x for x in core.NONEVM_REGISTRY if x["chain"] == "solana"]
        core._post_json = self._sol()
        c = core.read_solana(e, now=1_000_010)
        self.assertTrue(c["assessed"], c)
        t = c["tokens"][0]
        self.assertEqual((t["symbol"], t["total_supply"], t["transfer_hook_program"]), ("BUIDL", 987784165.65, "H"))
        core._post_json = self._sol(genesis="devnet-genesis")
        self.assertIn("not mainnet-beta", core.read_solana(e, now=1_000_010)["reason"])
        core._post_json = self._sol(bt=1_000_010 - core.MAX_BLOCK_AGE_S - 1)
        self.assertIn("stale node", core.read_solana(e, now=1_000_010)["reason"])
        core._post_json = self._sol(control_ext=())                          # the reader cannot see extensions
        self.assertIn("positive control failed", core.read_solana(e, now=1_000_010)["reason"])

    @staticmethod
    def _apt(chain_id=1, ts_s=1_000_000, ed=True):
        def get(url, timeout=25):
            if url == core.APTOS_API:
                return {"chain_id": chain_id, "ledger_version": "7", "ledger_timestamp": str(ts_s * 1_000_000)}
            if "/module/account" in url:
                return {"bytecode": "0x" + ("ed25519".encode().hex() if ed else "00")}
            if "/modules" in url:
                return [{"abi": {"name": "ds_token"}, "bytecode": "0xabcd"}]
            if "/resources" in url:
                return [{"type": "0x1::fungible_asset::Metadata", "data": {"symbol": "BUIDL", "name": "BlackRock BUIDL", "decimals": 6}},
                        {"type": "0x1::fungible_asset::ConcurrentSupply", "data": {"current": {"value": "161655590490000"}}},
                        {"type": "0x1::object::ObjectCore", "data": {"owner": "0x4de5"}}]
            raise AssertionError(url)
        return get

    def test_aptos_reads_and_gates(self):
        e = [x for x in core.NONEVM_REGISTRY if x["chain"] == "aptos"]
        core._get_json = self._apt()
        c = core.read_aptos(e, now=1_000_005)
        self.assertTrue(c["assessed"], c)
        t = c["tokens"][0]
        self.assertEqual((t["symbol"], t["total_supply"], t["modules"], t["signature_primitives_in_modules"]),
                         ("BUIDL", 161655590.49, ["ds_token"], []))
        core._get_json = self._apt(chain_id=2)
        self.assertIn("not mainnet", core.read_aptos(e, now=1_000_005)["reason"])
        core._get_json = self._apt(ts_s=1_000_005 - core.MAX_BLOCK_AGE_S - 1)
        self.assertIn("stale node", core.read_aptos(e, now=1_000_005)["reason"])
        core._get_json = self._apt(ed=False)                                 # the bytecode scan cannot see ed25519
        self.assertIn("positive control failed", core.read_aptos(e, now=1_000_005)["reason"])


class TestCouncil(unittest.TestCase):
    def test_deterministic(self):
        a, b = _snap({"ethereum": 100, "bsc": 50}), _snap({"ethereum": 101, "bsc": 50})
        self.assertEqual(agents.judge(b, a), agents.judge(b, a))

    def test_quiet_when_nothing_changes(self):
        s = _snap({"ethereum": 100, "bsc": 50})
        self.assertEqual(agents.judge(copy.deepcopy(s), s)["posture"], "QUIET")

    def test_unassessed_chain_is_elevated_all_missing_is_alert(self):
        self.assertEqual(agents.judge(_snap({"ethereum": 1}, not_assessed=["bsc"]))["posture"], "ELEVATED")
        self.assertEqual(agents.judge(_snap({}, not_assessed=["ethereum", "bsc"]))["posture"], "ALERT")

    def test_implementation_change_is_flagged(self):
        a = _snap({"ethereum": 100}, impl={"ethereum": "aa"})
        b = _snap({"ethereum": 100}, impl={"ethereum": "bb"})
        v = agents.judge(b, a)
        self.assertEqual(v["posture"], "ELEVATED")
        self.assertIn("implementation code changed", v["rationale"])

    def test_eip712_appearing_is_flagged(self):
        a = _snap({"ethereum": 100})
        b = _snap({"ethereum": 100}, eps={"ethereum": ("DOMAIN_SEPARATOR", "permit")})
        self.assertEqual(agents.judge(b, a)["posture"], "ELEVATED")

    def test_supply_move_uses_only_chains_assessed_in_both(self):
        a = _snap({"ethereum": 100, "bsc": 50})
        b = _snap({"ethereum": 100}, not_assessed=["bsc"])                  # bsc missing: not a -33% move
        votes = {v["why"].split()[0]: v for v in agents.judge(b, a)["votes"]}
        self.assertTrue(any("BUIDL 0.000%" in v["why"] for v in agents.judge(b, a)["votes"]), votes)
        c = _snap({"ethereum": 110, "bsc": 50})
        self.assertIn("BUIDL 6.667%", agents.judge(c, a, 2.0)["rationale"] + " ".join(v["why"] for v in agents.judge(c, a, 2.0)["votes"]))


class TestDiamondStellarMultiToken(unittest.TestCase):
    """25/09: JLTXX is an EIP-2535 Diamond; BENJI lives on Stellar too; several funds are watched at once."""
    def setUp(self):
        self._rpc, self._get = core.rpc, core._get_json

    def tearDown(self):
        core.rpc, core._get_json = self._rpc, self._get

    def test_diamond_read_through_its_loupe(self):
        core.rpc = FakeNode(True, impl_slot=False, diamond={"selectors": ["06fdde03", "d505accf"], "name_mapped": True})
        c = core.read_chain("arbitrum", ENTRY, now=NOW, discovery=False)
        self.assertTrue(c["assessed"], c)
        t = c["tokens"][0]
        self.assertEqual((t["implementation"], t["implementation_slot"], t["eip712_entry_points"]),
                         ("diamond:1 facets", "eip2535", ["permit"]))

    def test_diamond_whose_loupe_control_fails_is_not_assessed(self):
        # ablation of the loupe control: name() not mapped to any facet → the loupe is not trusted, and a small proxy
        # without implementation is NOT ASSESSED (never a false "no EIP-712")
        core.rpc = FakeNode(True, impl_slot=False, diamond={"selectors": ["d505accf"], "name_mapped": False})
        c = core.read_chain("arbitrum", ENTRY, now=NOW, discovery=False)
        self.assertFalse(c["assessed"])
        self.assertIn("implementation not located", c["reason"])

    @staticmethod
    def _xlm(passphrase=core.STELLAR_PASSPHRASE, closed="1970-01-12T13:46:40Z", control_amount="5.0000000", signers=None):
        signers = signers if signers is not None else [{"key": "GA", "weight": 3}]
        def get(url, timeout=25):
            if url == core.STELLAR_HORIZON + "/":
                return {"network_passphrase": passphrase, "history_latest_ledger": 900, "history_latest_ledger_closed_at": closed}
            if "/assets?" in url:
                code = "USDC" if "asset_code=USDC" in url else "BENJI"
                amt = control_amount if code == "USDC" else "430694230.4855482"
                return {"_embedded": {"records": [{"asset_code": code, "contract_id": "C", "flags": {"auth_required": True},
                        "balances": {"authorized": amt, "authorized_to_maintain_liabilities": "0.0000000", "unauthorized": "0.0000000"},
                        "claimable_balances_amount": "0.0000000", "liquidity_pools_amount": "0.0000000" if code == "USDC" else "0.0000001", "contracts_amount": "0.0000000"}]}}
            if "/accounts/" in url:
                return {"home_domain": "www.franklintempleton.com", "signers": signers,
                        "thresholds": {"low_threshold": 2, "med_threshold": 2, "high_threshold": 6}}
            raise AssertionError(url)
        return get

    def test_stellar_reads_and_gates(self):
        e = [dict(x, expected_owner=core.stellar_signers_fingerprint({"signers": [{"key": "GA", "weight": 3}],
             "thresholds": {"low_threshold": 2, "med_threshold": 2, "high_threshold": 6}})) for x in core.NONEVM_REGISTRY
             if x["chain"] == "stellar"]
        now = 1_000_000 + 10                                                 # closed_at above = 1_000_000 s
        core._get_json = self._xlm()
        c = core.read_stellar(e, now=now)
        self.assertTrue(c["assessed"], c)
        t = c["tokens"][0]
        self.assertEqual((t["symbol"], t["total_supply_raw"], t["owner"] == t["expected_owner"]),
                         ("BENJI", "4306942304855483", True))                # exact stroops, pool amount included
        core._get_json = self._xlm(passphrase="Test SDF Network ; September 2015")
        self.assertIn("not pubnet", core.read_stellar(e, now=now)["reason"])
        core._get_json = self._xlm()
        self.assertIn("stale node", core.read_stellar(e, now=1_000_000 + core.MAX_BLOCK_AGE_S + 1)["reason"])
        core._get_json = self._xlm(control_amount="0.0000000")               # the control asset reads as empty
        self.assertIn("positive control failed", core.read_stellar(e, now=now)["reason"])
        core._get_json = self._xlm(signers=[{"key": "GA", "weight": 3}, {"key": "GZ", "weight": 6}])   # a signer added
        snap = {"signal": {"chains_assessed": ["stellar"], "chains_not_assessed": [],
                           "chains": [core.read_stellar(e, now=now)]}}
        self.assertEqual(agents._agent_owner(snap)[0], "ELEVATED")

    def test_unreadable_search_match_is_flagged_not_folded(self):
        # 25/09 live: six Polygon reads failed and joined "not classified" under a QUIET council
        core.search_same_named, orig = (lambda chain: ("test", {"0x" + "44" * 20: "BUIDL", "0x" + "55" * 20: "BUIDL"})), core.search_same_named
        core.classify_unregistered, orig_c = (lambda ch, a, b, f="BUIDL": (_ for _ in ()).throw(core.RpcError("timeout"))
                                              if a.endswith("44") else {"address": a, "class": "x"}), core.classify_unregistered
        try:
            d = core.discover("polygon", "0x10", [])
        finally:
            core.search_same_named, core.classify_unregistered = orig, orig_c
        self.assertEqual((d["unreadable"], d["other_matches_not_classified"]), (["0x" + "44" * 20], 1))
        s = _snap({"polygon": 7})
        s["signal"]["chains"][0]["discovery"]["unreadable"] = d["unreadable"]
        self.assertEqual(agents._agent_imitations(s)[0], "ELEVATED")

    def test_search_has_a_positive_control_per_fund(self):
        # 25/09 live: BscScan returns [] for every USYC term although USYC is on BNB Chain → blind, said, never "none"
        reg = [e for e in core.REGISTRY if e["chain"] == "bsc"]
        buidl = next(e["address"] for e in reg if e["token"] == "BUIDL")
        orig_s, orig_c = core.search_same_named, core.classify_unregistered
        core.search_same_named = lambda chain: ("searched test", {buidl: "BUIDL"})
        core.classify_unregistered = lambda ch, a, b, f="BUIDL": {"address": a, "class": "x"}
        try:
            d = core.discover("bsc", "0x10", [e["address"] for e in reg])
        finally:
            core.search_same_named, core.classify_unregistered = orig_s, orig_c
        self.assertEqual(d["search_control"], {"BUIDL": True, "USYC": False})
        self.assertIn("search control FAILED for USYC", d["status"])
        prev, cur = _snap({"bsc": 1}), _snap({"bsc": 1})
        prev["signal"]["chains"][0]["discovery"]["search_control"] = {"USYC": True}
        cur["signal"]["chains"][0]["discovery"]["search_control"] = {"USYC": False}
        self.assertEqual(agents._agent_imitations(cur, prev)[0], "ELEVATED")        # sight lost since last cycle
        self.assertIn("search blind", agents._agent_imitations(cur, cur)[1])         # still blind: said, not raised

    def test_supply_move_is_per_token(self):
        a, b = _snap({"ethereum": 100}), _snap({"ethereum": 100})
        for s, v in ((a, 50.0), (b, 60.0)):                                  # BENJI +20 %, BUIDL unchanged
            s["signal"]["chains"][0]["tokens"].append(dict(_token("ethereum", v), token="BENJI", expected_owner=None))
        p, why = agents._agent_supply_move(b, a, 2.0)
        self.assertEqual(p, "ELEVATED")
        self.assertIn("BENJI 20.000%", why)
        self.assertNotIn("BUIDL", why.split(":", 1)[1])

    def test_token_without_control_key_is_not_owner_checked(self):
        s = _snap({"ethereum": 100})
        s["signal"]["chains"][0]["tokens"].append(dict(_token("ethereum", 5), token="BENJI", owner=None, expected_owner=None))
        self.assertEqual(agents._agent_owner(s)[0], "QUIET")


class TestBaselineAcrossOutage(unittest.TestCase):
    """26/09 Gemini Pro review, reproduced: a chain not assessed for ONE cycle dropped out of the comparison, so an
    upgrade plus a 667x mint during the outage came back QUIET, with the false sentence 'implementation code unchanged'.
    The council must compare each chain with the last cycle in which THAT chain was assessed."""
    def test_change_during_an_outage_is_flagged_on_recovery(self):
        c1 = _snap({"ethereum": 100, "polygon": 7.5}, impl={"polygon": "aa"})
        c2 = _snap({"ethereum": 100}, not_assessed=["polygon"])
        c3 = _snap({"ethereum": 100, "polygon": 5007.5}, impl={"polygon": "bb"})
        base = orch.baseline([{"snapshot": c1}, {"snapshot": c2}])
        v = agents.judge(c3, base)
        self.assertEqual(v["posture"], "ELEVATED")
        why = " ".join(x["why"] for x in v["votes"])
        self.assertIn("polygon/BUIDL: implementation code changed", why)
        self.assertIn("polygon", why.split("supply over")[1].split("]")[0])

    def test_baseline_is_the_previous_snapshot_when_nothing_was_missed(self):
        c1 = _snap({"ethereum": 100, "polygon": 7.5})
        c2 = _snap({"ethereum": 101, "polygon": 7.5})
        self.assertEqual(orch.baseline([{"snapshot": c1}, {"snapshot": c2}])["signal"]["chains"], c2["signal"]["chains"])


class TestCouncilNemesis(unittest.TestCase):
    """25/09 NEMESIS: a registry edit swapping an address passed QUIET with a false 'code unchanged'."""
    def test_swapped_address_is_flagged(self):
        a = _snap({"ethereum": 100})
        b = _snap({"ethereum": 100}, addr={"ethereum": "0x" + "a4" * 20})
        v = agents.judge(b, a)
        self.assertEqual(v["posture"], "ELEVATED")
        self.assertIn("address", v["rationale"])

    def test_chain_not_assessed_last_time_is_not_a_registry_change(self):
        prev = _snap({"ethereum": 100}, not_assessed=["polygon"])            # 25/09: a transient timeout on polygon
        cur = _snap({"ethereum": 100, "polygon": 7.5})
        self.assertNotIn("not in the previous cycle", " ".join(v["why"] for v in agents.judge(cur, prev)["votes"]))

    def test_chain_not_searched_last_time_has_no_new_tokens(self):
        u = {"address": "0x" + "44" * 20, "same_owner": False, "carries_issuer_name": True, "class": "x"}
        prev = _snap({"ethereum": 100}, not_assessed=["polygon"])
        cur = _snap({"ethereum": 100, "polygon": 7.5}, unregistered={"polygon": [u]})
        self.assertEqual(agents.judge(cur, prev)["posture"], "QUIET")
        prev2 = _snap({"ethereum": 100, "polygon": 7.5})                   # searched last time, now a new one appears
        self.assertEqual(agents.judge(cur, prev2)["posture"], "ELEVATED")

    def test_owner_change_is_flagged(self):
        v = agents.judge(_snap({"ethereum": 100}, owner={"ethereum": "0x" + "ab" * 20}), _snap({"ethereum": 100}))
        self.assertEqual(v["posture"], "ELEVATED")
        self.assertIn("owner", v["rationale"])

    def test_imitation_owned_by_issuer_key_is_flagged(self):
        u = {"address": "0x" + "33" * 20, "same_owner": True, "class": "x"}
        v = agents.judge(_snap({"ethereum": 100}, unregistered={"ethereum": [u]}), _snap({"ethereum": 100}))
        self.assertEqual(v["posture"], "ELEVATED")


class TestSelfImprove(unittest.TestCase):
    def test_warmup_holds_init(self):
        thr, note = orch.improve_threshold([{"snapshot": _snap({"ethereum": 10})}])
        self.assertEqual(thr, orch.THR_INIT)

    def test_non_regression_and_band(self):
        supplies = [100, 100.1, 100.2, 100.2, 110, 110.1, 110.1, 121, 121.1, 121.2, 121.2, 121.3]
        mem = [{"snapshot": _snap({"ethereum": s}), "threshold": 2.0} for s in supplies]
        thr, note = orch.improve_threshold(mem)
        self.assertTrue(orch.THR_MIN <= thr <= orch.THR_MAX, note)
        again, _ = orch.improve_threshold(mem + [{"snapshot": _snap({"ethereum": 121.3}), "threshold": thr}])
        self.assertTrue(orch.THR_MIN <= again <= orch.THR_MAX)
        # the recorded note must be true: with the incumbent already the best, the cycle HOLDS, it does not "tune"
        held, note2 = orch.improve_threshold(mem + [{"snapshot": _snap({"ethereum": 121.3}), "threshold": again}])
        self.assertEqual(held, again)
        self.assertTrue(note2.startswith("hold"), note2)


class TestCycleSandboxed(unittest.TestCase):
    def test_run_cycle_uses_the_per_chain_baseline(self):
        """The same outage, through run_cycle itself (the ablation showed a test on baseline() alone let run_cycle
        stop using it). Sandboxed like the test above; evidence off."""
        before = [_fingerprint(p) for p in (orch.MEMORY, orch.LATEST, orch.KEY_PATH, orch.PQ_KEY_PATH)]
        with tempfile.TemporaryDirectory() as d:
            saved = (orch.MEMORY, orch.LATEST, orch.EVIDENCE_DIR, orch.KEY_PATH, orch.PQ_KEY_PATH)
            orch.MEMORY, orch.LATEST = os.path.join(d, "m.jsonl"), os.path.join(d, "latest.json")
            orch.EVIDENCE_DIR, orch.KEY_PATH = os.path.join(d, "evidence"), os.path.join(d, "key", "seed")
            orch.PQ_KEY_PATH = os.path.join(d, "key", "mldsa65.key")
            try:
                orch.run_cycle(lambda: _snap({"ethereum": 100, "polygon": 7.5}, impl={"polygon": "aa"}), evidence=False)
                orch.run_cycle(lambda: _snap({"ethereum": 100}, not_assessed=["polygon"]), evidence=False)
                out = orch.run_cycle(lambda: _snap({"ethereum": 100, "polygon": 5007.5}, impl={"polygon": "bb"}), evidence=False)
            finally:
                orch.MEMORY, orch.LATEST, orch.EVIDENCE_DIR, orch.KEY_PATH, orch.PQ_KEY_PATH = saved
        self.assertEqual(out["verdict"]["posture"], "ELEVATED")
        self.assertIn("implementation code changed", " ".join(v["why"] for v in out["verdict"]["votes"]))
        self.assertEqual([_fingerprint(p) for p in (orch.MEMORY, orch.LATEST, orch.KEY_PATH, orch.PQ_KEY_PATH)], before)

    def test_cycle_writes_only_in_tmp_and_signs_when_available(self):
        before = [_fingerprint(p) for p in (orch.MEMORY, orch.LATEST, orch.KEY_PATH, orch.PQ_KEY_PATH)]
        with tempfile.TemporaryDirectory() as d:
            saved = (orch.MEMORY, orch.LATEST, orch.EVIDENCE_DIR, orch.KEY_PATH, orch.PQ_KEY_PATH)
            orch.MEMORY, orch.LATEST = os.path.join(d, "m.jsonl"), os.path.join(d, "latest.json")
            orch.EVIDENCE_DIR, orch.KEY_PATH = os.path.join(d, "evidence"), os.path.join(d, "key", "seed")
            orch.PQ_KEY_PATH = orch_pq = os.path.join(d, "key", "mldsa65.key")
            try:
                # fractional supplies, as real chains report them (25/09: floats broke the signed pack; ints hid it)
                orch.run_cycle(lambda: _snap({"ethereum": 208338526.123456, "bsc": 146529570.5}))
                out = orch.run_cycle(lambda: _snap({"ethereum": 208338526.123456, "bsc": 146529570.5}))
            finally:
                orch.MEMORY, orch.LATEST, orch.EVIDENCE_DIR, orch.KEY_PATH, orch.PQ_KEY_PATH = saved
            self.assertTrue(out["chain_ok"])
            self.assertEqual(len(orch.load_memory(os.path.join(d, "m.jsonl"))), 2)
            ev = out["evidence"]
            try:
                import omega_evidence  # noqa: F401
                have = True
            except ImportError:
                have = False
            self.assertEqual(ev["written"], have, ev)
            if have:
                self.assertEqual(oct(os.stat(os.path.join(d, "key", "seed")).st_mode & 0o777), "0o600")
                from omega_evidence.pqbackends import mldsa
                if mldsa.available():                                            # hybrid pack: ML-DSA-65 co-signature
                    self.assertTrue(ev.get("pq_public_key_b64"), ev)
                    self.assertEqual(oct(os.stat(orch_pq).st_mode & 0o777), "0o600")
        self.assertEqual((orch.MEMORY, orch.LATEST, orch.EVIDENCE_DIR, orch.KEY_PATH), PROD_PATHS)
        self.assertEqual([_fingerprint(p) for p in (orch.MEMORY, orch.LATEST, orch.KEY_PATH, orch.PQ_KEY_PATH)], before,
                         "a test must leave the production memory, latest record and signing seed untouched")


class TestETF(unittest.TestCase):
    """Tokenized-ETF layer: the permissioned byte scan with its own positive control, and the Solana authority tie.
    No network — core.rpc / core._sol_mint are faked."""

    def setUp(self):
        self._rpc, self._sol = core.rpc, core._sol_mint

    def tearDown(self):
        core.rpc, core._sol_mint = self._rpc, self._sol

    def _fake_code(self, code_hex):
        def rpc(chain, method, params, timeout=25):
            if method == "eth_getCode":
                return "0x" + code_hex
            if method == "eth_getStorageAt":
                return "0x0"                                   # no proxy: implementation code == the code returned
            raise AssertionError(f"unexpected {method}")
        return rpc

    def test_permissioned_scan_sees_selectors_and_controls_itself(self):
        # code carries ERC-3643 canTransfer (e46638e6) AND the permit control selector (d505accf)
        core.rpc = self._fake_code("00" * 4 + "e46638e6" + "11" * 4 + "d505accf" + "22" * 4)
        r = core.read_permissioned("ethereum", "0xabc", "0x1")
        self.assertIn("erc3643+7943:canTransfer", r["permissioned_interfaces"])
        self.assertTrue(r["scan_control_permit_visible"])

    def test_permissioned_scan_control_fails_when_permit_absent(self):
        # no permit selector in the code: the scan cannot be trusted to report ABSENCE of 3643/7943
        core.rpc = self._fake_code("00" * 8)
        r = core.read_permissioned("ethereum", "0xabc", "0x1")
        self.assertEqual(r["permissioned_interfaces"], [])
        self.assertFalse(r["scan_control_permit_visible"])

    def test_solana_etf_authority_tie(self):
        def sol_ok(addr):
            return (10, core.XSTOCKS_TOKEN2022, {"decimals": 8, "supply": "100000000",
                    "mintAuthority": core.XSTOCKS_MINTER, "freezeAuthority": core.XSTOCKS_FREEZER},
                    {"permanentDelegate": None, "pausableConfig": None, "metadataPointer": None})
        core._sol_mint = sol_ok
        out = core.read_etf_solana(core.ETF_REGISTRY_SOLANA)[0]
        self.assertTrue(out["same_mint_authority"] and out["same_freeze_authority"] and out["token2022"])
        self.assertEqual(out["total_supply"], 1.0)                              # 100000000 / 10**8
        self.assertIn("permanentDelegate", out["permissioned_controls"])
        self.assertNotIn("metadataPointer", out["permissioned_controls"])       # plain metadata is not a control

    def test_solana_wrong_mint_authority_is_flagged(self):
        def sol_bad(addr):
            return (10, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", {"decimals": 8, "supply": "29990000000000000",
                    "mintAuthority": None, "freezeAuthority": None}, {})          # the AAmD… imitation shape
        core._sol_mint = sol_bad
        out = core.read_etf_solana(core.ETF_REGISTRY_SOLANA)[0]
        self.assertFalse(out["same_mint_authority"])
        self.assertFalse(out["token2022"])

    def test_etf_registry_addresses_are_distinct_and_lowercased_ties(self):
        addrs = [e["address"].lower() for e in core.ETF_REGISTRY_EVM]
        self.assertEqual(len(addrs), len(set(addrs)))                            # no duplicate contracts
        self.assertEqual(len(core.PERMISSIONED_SELECTORS), 10)                   # 2 shared + 4 ERC-3643 + 4 ERC-7943 Final
        self.assertNotIn("39f648aa", core.PERMISSIONED_SELECTORS.values())   # pre-Final draft isTransferAllowed

    def test_permissioned_scan_sees_erc7943_final_entry_points(self):
        # a uRWA token as in the FINAL text exposes canSend / canReceive (2bc06a92 / 90d370ba), plus permit (control)
        core.rpc = self._fake_code("00" * 4 + "2bc06a92" + "11" * 4 + "90d370ba" + "22" * 4 + "d505accf")
        r = core.read_permissioned("ethereum", "0xabc", "0x1")
        self.assertTrue({"erc7943:canSend", "erc7943:canReceive"} <= set(r["permissioned_interfaces"]))
        self.assertTrue(r["scan_control_permit_visible"])

    def test_etf_solana_layer_passes_the_same_gate_as_the_fund_layer(self):
        # 28/09: the ETF Solana read had no genesis / freshness / positive-control gate — a node on another cluster
        # or a reader blind to Token-2022 extensions was still "assessed". Now the same gate as read_solana.
        saved_evm, saved_post = core.ETF_REGISTRY_EVM, core._post_json
        core.ETF_REGISTRY_EVM = []
        try:
            core._post_json = TestNonEvm._sol(control_ext=())                   # PYUSD's extensions not seen
            s = core.fetch_etf_signal(now=1_000_010)
            self.assertEqual(s["chains_not_assessed"], ["solana"])
            self.assertIn("positive control failed", s["chains"][0]["reason"])
            self.assertNotIn("tokens", s["chains"][0])
            core._post_json = TestNonEvm._sol()
            s = core.fetch_etf_signal(now=1_000_010)
            self.assertEqual(s["chains_assessed"], ["solana"])
            self.assertEqual(s["chains"][0]["block"], 450)
            self.assertEqual(len(s["chains"][0]["tokens"]), len(core.ETF_REGISTRY_SOLANA))
        finally:
            core.ETF_REGISTRY_EVM, core._post_json = saved_evm, saved_post


class TestBeaconProxy(unittest.TestCase):
    """28/09: IBITon (Ondo) is an EIP-1967 BEACON proxy — no direct implementation slot, the beacon answers
    implementation(). Positive: resolved through the beacon. Negatives: empty beacon slot, a beacon whose
    implementation() reverts, a beacon pointing at an address without code — NOT ASSESSED, never a clean read."""
    ADMIN = "0x3715b2154d2ff4c5b027c7a1f734b53f27bc34f1"
    IBITON = [{"token": "IBITon", "address": "0x" + "22" * 20, "underlying": "u", "issuer": "i", "status": "live",
               "status_source": "s", "provenance": "p", "expected_owner": ADMIN, "expected_owner_kind": "AccessControl"}]

    def setUp(self):
        self._rpc = core.rpc

    def tearDown(self):
        core.rpc = self._rpc

    def test_beacon_proxy_resolved_to_its_implementation(self):
        core.rpc = FakeNode(True, impl_slot=False, beacon="ok", impl_code="0x60" + "00" * 100 + "d505accf" + "00" * 100)
        c = core.read_chain("arbitrum", ENTRY, now=NOW, discovery=False)
        self.assertTrue(c["assessed"], c)
        t = c["tokens"][0]
        self.assertEqual((t["implementation"], t["implementation_slot"], t["beacon"]),
                         ("0x" + "11" * 20, "beacon", "0x" + "b1" * 20))
        self.assertEqual(t["eip712_entry_points"], ["permit"])              # scanned on the BEACON's implementation
        # read_permissioned goes through the same resolver: its scan control sees permit on that code
        p = core.read_permissioned("arbitrum", "0x" + "22" * 20, "0x10")
        self.assertTrue(p["scan_control_permit_visible"])

    def test_direct_slot_wins_over_beacon(self):
        # negative control of the ORDER: a contract with an eip1967 slot keeps its fingerprint even if a beacon slot
        # is also set — the beacon is tried only after the direct slots
        core.rpc = FakeNode(True, impl_slot=True, beacon="ok")
        s = core.read_structure("arbitrum", "0x" + "22" * 20, "0x10")
        self.assertEqual((s["implementation_slot"], "beacon" in s), ("eip1967", False))

    def test_beacon_whose_implementation_reverts_is_not_assessed(self):
        core.rpc = FakeNode(True, impl_slot=False, beacon="revert")
        c = core.read_chain("arbitrum", ENTRY, now=NOW, discovery=False)
        self.assertFalse(c["assessed"])
        self.assertIn("implementation not located", c["reason"])

    def test_beacon_pointing_at_address_without_code_is_not_assessed(self):
        core.rpc = FakeNode(True, impl_slot=False, beacon="nocode")
        c = core.read_chain("arbitrum", ENTRY, now=NOW, discovery=False)
        self.assertFalse(c["assessed"])
        self.assertIn("implementation not located", c["reason"])
        s = core.read_structure("arbitrum", "0x" + "22" * 20, "0x10")
        self.assertIsNone(s["implementation"])

    def test_empty_beacon_slot_is_not_assessed(self):
        core.rpc = FakeNode(True, impl_slot=False, beacon=None)
        c = core.read_chain("arbitrum", ENTRY, now=NOW, discovery=False)
        self.assertFalse(c["assessed"])
        self.assertIn("implementation not located", c["reason"])

    def test_etf_control_key_from_access_control_when_owner_reverts(self):
        core.rpc = FakeNode(True, owner=None, impl_slot=False, beacon="ok", admin_member=(self.ADMIN, True))
        r = core.read_etf_evm("ethereum", "0x10", self.IBITON)[0]
        self.assertTrue(r["readable"], r)
        self.assertIsNone(r["owner"])
        self.assertEqual((r["control_key"], r["same_owner"], r["implementation_slot"]), (self.ADMIN, True, "beacon"))
        self.assertIn("DEFAULT_ADMIN_ROLE", r["control_key_kind"])
        self.assertEqual(r["admin_role_members"], {"count": 1, "members": [self.ADMIN]})

    def test_etf_control_key_not_recorded_when_hasrole_denies_it(self):
        # the enumeration names a member the contract denies: no key, "not comparable" — never a false tie
        core.rpc = FakeNode(True, owner=None, impl_slot=False, beacon="ok", admin_member=(self.ADMIN, False))
        r = core.read_etf_evm("ethereum", "0x10", self.IBITON)[0]
        self.assertIsNone(r["control_key"])
        self.assertIsNone(r["same_owner"])

    def test_etf_without_expected_key_is_not_comparable_not_a_crash(self):
        entry = [dict(self.IBITON[0], expected_owner=None, expected_owner_kind=None)]
        core.rpc = FakeNode(True, owner=None, impl_slot=False, beacon="ok", admin_member=None)
        r = core.read_etf_evm("ethereum", "0x10", entry)[0]
        self.assertEqual((r["control_key"], r["same_owner"], r["expected_owner"]), (None, None, None))
        # and a Backed-shaped token (owner() answers) reads exactly as before
        core.rpc = FakeNode(True, owner="0x" + "ab" * 20)
        r = core.read_etf_evm("ethereum", "0x10", [dict(self.IBITON[0], expected_owner="0x" + "ab" * 20)])[0]
        self.assertEqual((r["control_key_kind"], r["same_owner"], r["implementation_slot"]), ("owner()", True, "eip1967"))

    def test_etf_proxy_without_located_implementation_is_unreadable(self):
        core.rpc = FakeNode(True, owner=None, impl_slot=False, beacon="revert", admin_member=(self.ADMIN, True))
        r = core.read_etf_evm("ethereum", "0x10", self.IBITON)[0]
        self.assertFalse(r["readable"])
        self.assertIn("implementation not located", r["reason"])

    def test_ibiton_registry_entries_carry_a_measured_key_and_the_primary_source(self):
        evm = [e for e in core.ETF_REGISTRY_EVM if e["token"] == "IBITon"]
        self.assertEqual(sorted(e["chain"] for e in evm), ["bsc", "ethereum"])
        for e in evm:
            self.assertIn("app.ondo.finance", e["provenance"])
            self.assertIn("DEFAULT_ADMIN_ROLE", e["expected_owner_kind"])
            self.assertRegex(e["expected_owner"], r"^0x[0-9a-f]{40}$")
        sol = [e for e in core.ETF_REGISTRY_SOLANA if e["token"] == "IBITon"]
        self.assertEqual(len(sol), 1)
        self.assertIn("app.ondo.finance", sol[0]["provenance"])


class TestScaledUi(unittest.TestCase):
    """Token-2022 scaledUiAmountConfig: the raw amount and the amount holders see are two different quantities."""
    CFG = {"scaledUiAmountConfig": {"multiplier": "1.0039", "newMultiplier": "1.0057",
                                    "newMultiplierEffectiveTimestamp": 1_000_000}}

    def test_new_multiplier_applies_only_from_its_timestamp(self):
        self.assertEqual(core.scaled_ui_multiplier(self.CFG, 999_999), (1.0039, "multiplier"))
        self.assertEqual(core.scaled_ui_multiplier(self.CFG, 1_000_000), (1.0057, "newMultiplier"))

    def test_mint_without_the_extension_has_no_multiplier(self):
        self.assertEqual(core.scaled_ui_multiplier({"permanentDelegate": None}, 5), (None, None))

    def test_reader_keeps_raw_amount_and_ui_amount_apart(self):
        saved = core._sol_mint
        try:
            core._sol_mint = lambda a: (10, core.XSTOCKS_TOKEN2022, {"decimals": 8, "supply": "200000000",
                                        "mintAuthority": core.XSTOCKS_MINTER,
                                        "freezeAuthority": core.XSTOCKS_FREEZER}, dict(self.CFG))
            out = core.read_etf_solana(core.ETF_REGISTRY_SOLANA[:1], now=2_000_000)[0]
        finally:
            core._sol_mint = saved
        self.assertEqual(out["total_supply"], 2.0)                          # raw: 200000000 / 10**8
        self.assertAlmostEqual(out["ui_amount"], 2.0 * 1.0057)              # what holders see
        self.assertEqual(out["ui_multiplier_field"], "newMultiplier")


# The hash-chained memory survives an interrupted write, and verify_chain answers on a malformed record (2026-10-03).
# Before: save_memory opened the real file with "w" (an exception mid-write left it truncated) and verify_chain
# raised KeyError on a record without self_hash.
class _Unserialisable:
    pass


class TestMemoryIntegrity(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="rwmem_")
        self.path = os.path.join(self.d, "m.jsonl")
        self.recs = []
        for i in range(3):
            core.append(self.recs, {"timestamp_utc": f"2026-10-0{i + 1}", "signal": {"metric": i}})

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_interrupted_save_leaves_previous_memory_intact(self):
        orch.save_memory(self.recs, self.path)
        with open(self.path, encoding="utf-8") as f:
            before = f.read()
        broken = [{"x": _Unserialisable()}] + self.recs          # fails on the FIRST record: a direct "w" leaves it empty
        with self.assertRaises(TypeError):
            orch.save_memory(broken, self.path)
        with open(self.path, encoding="utf-8") as f:
            self.assertEqual(f.read(), before)
        self.assertTrue(core.verify_chain(orch.load_memory(self.path))[0])
        self.assertEqual(os.listdir(self.d), ["m.jsonl"])                  # no temporary file left behind

    def test_save_then_load_round_trip(self):                      # positive control
        orch.save_memory(self.recs, self.path)
        self.assertEqual(orch.load_memory(self.path), self.recs)
        with open(f"{self.path}.{os.getpid()}.tmp", "w", encoding="utf-8") as f:  # a temporary left by a killed run is overwritten, never appended to
            f.write("garbage\n")
        orch.save_memory(self.recs, self.path)
        self.assertEqual(orch.load_memory(self.path), self.recs)
        self.assertEqual(os.listdir(self.d), ["m.jsonl"])

    def test_duplicate_key_is_refused_on_load(self):
        orch.save_memory(self.recs, self.path)
        self.assertEqual(orch.load_memory(self.path), self.recs)                     # positive control
        with open(self.path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        lines[1] = lines[1].replace("{", '{"signal": {"metric": 999}, ', 1)         # two values for "signal"
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        with self.assertRaises(ValueError):
            orch.load_memory(self.path)

    def test_malformed_record_is_a_verdict(self):
        self.assertEqual(core.verify_chain(self.recs), (True, "PASS"))
        g = self.recs[1]
        body = {k: v for k, v in g.items() if k not in ("self_hash", "prev_hash")}
        crafted = dict(body, self_hash=core.chain_hash(body))     # no prev_hash but a consistent self_hash: only the guard refuses it
        for bad in ({k: v for k, v in g.items() if k != "self_hash"}, {k: v for k, v in g.items() if k != "prev_hash"},
                    crafted, None, [1], "x", 7, {}):
            with self.subTest(bad=json.dumps(bad, default=str)[:40]):
                for chain, at in (([self.recs[0], bad, self.recs[2]], 1), ([bad], 0), (self.recs[:2] + [bad], 2)):
                    # must not raise, must not skip the record (a malformed LAST record is not a PASS), same message everywhere
                    self.assertEqual(core.verify_chain(chain), (False, f"malformed record at #{at}"))



if __name__ == "__main__":
    unittest.main(verbosity=2)
