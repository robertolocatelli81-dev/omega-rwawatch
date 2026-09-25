#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA-RWAWatch · tests — hash-chain integrity, the positive control, council determinism and its facets,
self-improve non-regression, and the evidence path. Stdlib unittest, NO network: a fake RPC answers.
Every write goes to a temporary directory: the module paths are redirected before any cycle runs."""
import copy
import os
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
    data = open(path, "rb").read()
    return (True, len(data), hashlib.sha256(data).hexdigest())


def _token(chain, supply, impl_hash="aa", eps=(), address=None, owner=core.EXPECTED_OWNER):
    return {"token": "BUIDL", "address": address or f"0x{chain[:4].encode().hex():0<40}", "symbol": "BUIDL", "owner": owner,
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
                 fail_selector=None, impl_slot=True, symbol=b"BUIDL"):
        self.symbol = symbol
        self.control_has, self.chain_id, self.block_ts = control_has_eip712, chain_id, block_ts
        self.owner, self.fail_selector, self.impl_slot = owner, fail_selector, impl_slot

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
            if addr.lower() == "0x" + "11" * 20:
                return "0x60" + "00" * 200                                  # implementation code, no EIP-712
            if addr.lower() == ctl:
                return "0x" + ("3644e515d505accf" if self.control_has else "00") * 120
            return "0x" + "00" * 170
        if method == "eth_getStorageAt":
            if self.impl_slot and addr.lower() != ctl and params[1] == core.PROXY_SLOTS["eip1967"]:
                return "0x" + "00" * 12 + "11" * 20
            return "0x" + "00" * 32
        if method == "eth_call":
            data = params[0]["data"]
            if self.fail_selector and data.startswith(self.fail_selector) and addr.lower() != ctl:
                raise core.RpcError("eth_call: header not found")                # a node fault, not a revert
            if data == "0x8da5cb5b":
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
        self.assertEqual(calls["n"], core.NETWORK_RETRIES + 1)             # retried once, then the error surfaces

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

    def test_proxy_without_located_implementation_is_not_assessed(self):
        core.rpc = FakeNode(True, impl_slot=False)
        c = core.read_chain("arbitrum", ENTRY, now=NOW, discovery=False)
        self.assertFalse(c["assessed"])
        self.assertIn("implementation not located", c["reason"])

    def test_same_named_token_classified_by_owner(self):
        core.rpc = FakeNode(True, owner="0x" + "ab" * 20, symbol=b"BlackRock USD Institutional Digital Liquidity Fund")
        u = core.classify_unregistered("arbitrum", "0x" + "33" * 20, "0x10")     # name (and symbol) carry BlackRock's name
        self.assertFalse(u["same_owner"])
        self.assertIn("NOT an issuer deployment", u["class"])
        core.rpc = FakeNode(True, owner="0x" + "ab" * 20, symbol=b"BUIDL")        # the common word alone: not classified
        u = core.classify_unregistered("arbitrum", "0x" + "33" * 20, "0x10")
        self.assertIn("not classified", u["class"])
        core.rpc = FakeNode(True)
        u = core.classify_unregistered("arbitrum", "0x" + "33" * 20, "0x10")
        self.assertTrue(u["same_owner"])
        self.assertIn("new issuer deployment", u["class"])


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
        self.assertTrue(any("moved 0.000%" in v["why"] for v in agents.judge(b, a)["votes"]), votes)
        c = _snap({"ethereum": 110, "bsc": 50})
        self.assertIn("moved 6.667%", agents.judge(c, a, 2.0)["rationale"] + " ".join(v["why"] for v in agents.judge(c, a, 2.0)["votes"]))


class TestCouncilNemesis(unittest.TestCase):
    """25/09 NEMESIS: a registry edit swapping an address passed QUIET with a false 'code unchanged'."""
    def test_swapped_address_is_flagged(self):
        a = _snap({"ethereum": 100})
        b = _snap({"ethereum": 100}, addr={"ethereum": "0x" + "a4" * 20})
        v = agents.judge(b, a)
        self.assertEqual(v["posture"], "ELEVATED")
        self.assertIn("address", v["rationale"])

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


class TestCycleSandboxed(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
