import os, shutil, subprocess, sys
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); S = sys.argv[1]  # a scratch dir
M = [  # (name, file, old, new)
 ("EVM positive control", "rwawatch.py", 'ok = "DOMAIN_SEPARATOR" in s["eip712_entry_points"] and s["domain_separator_answers"]', "ok = True"),
 ("EVM chain id", "rwawatch.py", 'if node["chain_id"] != node["expected_chain_id"]:', "if False:"),
 ("EVM stale block", "rwawatch.py", 'if node["block_age_s"] > MAX_BLOCK_AGE_S:\n            return {"chain": chain,', 'if False:\n            return {"chain": chain,'),
 ("node fault != revert", "rwawatch.py", 'if t["symbol"] is None or t["total_supply"] is None:\n                return {"chain": chain,', 'if False:\n                return {"chain": chain,'),
 ("small proxy w/o impl", "rwawatch.py", 'if t["implementation"] is None and t["proxy_code_bytes"] < 1024:', "if False:"),
 ("Solana control", "rwawatch.py", '"ok": all(n in cext for n in need)', '"ok": True'),
 ("Solana genesis", "rwawatch.py", "if genesis != SOLANA_GENESIS:", "if False:"),
 ("Aptos control", "rwawatch.py", 'ctl["ok"] = ctl["metadata_readable"] and ctl["bytecode_scan_sees_ed25519"]', 'ctl["ok"] = True'),
 ("Aptos chain id", "rwawatch.py", 'if li["chain_id"] != APTOS_CHAIN_ID:', "if False:"),
 ("Stellar control", "rwawatch.py", '"ok": bool(ca) and _stellar_amount(ca) > 0 and "flags" in ca}', '"ok": True}'),
 ("Stellar passphrase", "rwawatch.py", 'if root["network_passphrase"] != STELLAR_PASSPHRASE:', "if False:"),
 ("Diamond loupe control", "rwawatch.py", 'if dm is not None and dm["loupe_control_ok"]:', "if dm is not None:"),
 ("unreadable listed apart", "rwawatch.py", 'unreadable = [u["address"] for u in out if str(u.get("class", "")).startswith("unreadable")]', "unreadable = []"),
 ("owner not comparable", "rwawatch.py", '"same_owner": (str(t.get("owner")).lower() in owners) if owners else None})', '"same_owner": str(t.get("owner")).lower() in owners})'),
 ("transport retry", "rwawatch.py", "NETWORK_RETRIES = 1", "NETWORK_RETRIES = 0"),
 ("agent: owner", "rwawatch_agents.py", 'return ("ELEVATED", "; ".join(off)) if off else', 'return ("QUIET", "") if off else'),
 ("agent: structure address", "rwawatch_agents.py", 'for k in ("address", "symbol", "decimals"):', 'for k in ():'),
 ("agent: implementation change", "rwawatch_agents.py", 'changes.append(f"{c}/{t[\'token\']}: implementation code changed")', "pass"),
 ("agent: assessed before", "rwawatch_agents.py", "if c in assessed_before:", "if True:"),
 ("agent: supply per token", "rwawatch_agents.py", "big = {k: m for k, m in moves.items() if m >= threshold_pct}", "big = {}"),
 ("agent: supply common chains", "rwawatch_agents.py", "if c in common and t.get(\"total_supply\") is not None:", "if t.get(\"total_supply\") is not None:"),
 ("agent: coverage", "rwawatch_agents.py", 'return "ELEVATED", f"not assessed this run', 'return "QUIET", f"not assessed this run'),
 ("agent: unreadable flag", "rwawatch_agents.py", "    if unreadable:\n        return \"ELEVATED\"", "    if False:\n        return \"ELEVATED\""),
 ("agent: eip712 change", "rwawatch_agents.py", "if (c, a) in before and before[(c, a)] != eps]", "if False]"),
 ("search positive control", "rwawatch.py", 'by_fund[e["token"]] = by_fund.get(e["token"], False) or e["address"].lower() in found', 'by_fund[e["token"]] = True'),
 ("agent: search sight lost", "rwawatch_agents.py", "    if lost:\n        return \"ELEVATED\"", "    if False:\n        return \"ELEVATED\""),
 ("threshold non-regression", "rwawatch_orchestrator.py", "if best_q > -1e9 and (base_q is None or best_q > base_q):", "if best_q > -1e9:"),
]
bad = 0
for name, f, old, new in M:
    d = os.path.join(S, "p"); shutil.rmtree(d, ignore_errors=True)
    shutil.copytree(SRC, d, ignore=shutil.ignore_patterns(".git", "evidence", "*.jsonl", "rwawatch_latest*.json", "__pycache__"))
    p = os.path.join(d, f); src = open(p).read()
    if src.count(old) != 1:
        print(f"?? {name}: pattern found {src.count(old)} times"); bad += 1; continue
    open(p, "w").write(src.replace(old, new))
    r = subprocess.run([sys.executable, "tests/test_rwawatch.py"], cwd=d, capture_output=True, text=True, timeout=300,
                       env=dict(os.environ, HOME=os.path.join(S, "home")))
    red = [l.split("(")[0].replace("FAIL: ", "").replace("ERROR: ", "") for l in r.stderr.splitlines() if l.startswith(("FAIL:", "ERROR:"))]
    ok = r.returncode != 0
    bad += not ok
    print(("RED  " if ok else "GREEN!") + f" {name}: {', '.join(red[:3]) or '-'}")
print("mutations surviving:", bad, "of", len(M))
