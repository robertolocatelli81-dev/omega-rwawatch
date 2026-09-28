#!/usr/bin/env python3
"""Live NEGATIVE CONTROL of the implementation resolver. For every contract already registered (funds, ETF tokens,
EVM positive controls) the structure read by rwawatch.py at a git ref (default HEAD) and by the working copy must be
IDENTICAL at the same block: implementation / implementation_slot / implementation_code_sha256 / eip712 entry
points / proxy size, and no `beacon` key. Run before changing how proxies are resolved, and after.

    python3 tools/negctl_structure.py [git-ref]     # network: one block per chain, two reads per contract
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import rwawatch as after  # noqa: E402

REF = sys.argv[1] if len(sys.argv) > 1 else "HEAD"
FIELDS = ("implementation", "implementation_slot", "implementation_code_sha256", "eip712_entry_points", "proxy_code_bytes")


def load_ref(ref):
    src = subprocess.run(["git", "show", f"{ref}:rwawatch.py"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    d = tempfile.mkdtemp(prefix="negctl_")
    p = os.path.join(d, "rwawatch_ref.py")
    open(p, "w").write(src)
    spec = importlib.util.spec_from_file_location("rwawatch_ref", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    before = load_ref(REF)
    known_before = {e["address"].lower() for e in before.REGISTRY} | \
        {e["address"].lower() for e in getattr(before, "ETF_REGISTRY_EVM", [])}
    by_chain = {}
    for e in after.REGISTRY + after.ETF_REGISTRY_EVM:
        if e["address"].lower() in known_before:                 # only what BOTH versions register is comparable
            by_chain.setdefault(e["chain"], []).append((e["token"], e["address"]))
    for ch, (label, addr) in after.CONTROLS.items():
        by_chain.setdefault(ch, []).append((f"control:{label}", addr))
    same = diff = skipped = 0
    for chain, items in by_chain.items():
        try:
            block = after.node_identity(chain)["block"]
        except Exception as ex:
            print(f"{chain}: node not reachable ({type(ex).__name__}) - NOT COMPARED")
            skipped += len(items)
            continue
        for token, addr in items:
            try:
                b = before.read_structure(chain, addr, block)
                a = after.read_structure(chain, addr, block)
            except Exception as ex:
                print(f"{chain}/{token} {addr}: read failed ({type(ex).__name__}: {str(ex)[:80]}) - NOT COMPARED")
                skipped += 1
                continue
            ok = all(a.get(f) == b.get(f) for f in FIELDS) and "beacon" not in a
            same += ok
            diff += not ok
            print(f"{'SAME' if ok else 'DIFF'} {chain}/{token} block={int(block, 16)} slot={a['implementation_slot']} "
                  f"impl={a['implementation']} sha256={str(a['implementation_code_sha256'])[:16]}"
                  + ("" if ok else f"  REF={json.dumps({f: b.get(f) for f in FIELDS})}"))
    print(f"negative control vs {REF}: {same} identical, {diff} different, {skipped} not compared")
    return 1 if diff or skipped else 0


if __name__ == "__main__":
    sys.exit(main())
