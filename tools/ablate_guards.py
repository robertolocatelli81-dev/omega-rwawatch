import os, shutil, subprocess, sys
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); S = sys.argv[1]  # a scratch dir
M = [  # (name, file, old, new)
 ("EVM positive control", "rwawatch.py", 'ok = "DOMAIN_SEPARATOR" in s["eip712_entry_points"] and s["domain_separator_answers"]', "ok = True"),
 ("EVM chain id", "rwawatch.py", 'if node["chain_id"] != node["expected_chain_id"]:', "if False:"),
 ("EVM stale block", "rwawatch.py", 'if node["block_age_s"] > MAX_BLOCK_AGE_S:\n        return {"chain": chain,', 'if False:\n        return {"chain": chain,'),
 ("node fault != revert", "rwawatch.py", 'if t["symbol"] is None or t["total_supply"] is None:\n        return {"unreadable"', 'if False:\n        return {"unreadable"'),
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
 ("search positive control", "rwawatch.py", '(by_fund.get(e["token"], False) or e["address"].lower() in found) if searched else None', 'True if searched else None'),
 ("agent: search sight lost", "rwawatch_agents.py", "    if lost:                                                                     # [S3]", "    if False:"),
 ("orchestrator: per-chain baseline", "rwawatch_orchestrator.py", "    previous = baseline(memory)", "    previous = next((r[\"snapshot\"] for r in reversed(memory) if r.get(\"snapshot\")), None)"),
 ("scaled UI effective multiplier", "rwawatch.py", 'if ts is not None and cfg.get("newMultiplier") is not None and now >= int(ts):', "if False:"),
 ("threshold non-regression", "rwawatch_orchestrator.py", "if best_q > -1e9 and (base_q is None or best_q > base_q):", "if best_q > -1e9:"),
 ("beacon resolver", "rwawatch.py", 'bv = rpc(chain, "eth_getStorageAt", [address, BEACON_SLOT, block])', "bv = None"),
 ("beacon impl must have code", "rwawatch.py", 'if len(c) > 200:\n                return {"implementation": cand, "code": c, "slot": "beacon"', 'if True:\n                return {"implementation": cand, "code": c, "slot": "beacon"'),
 ("AccessControl member confirmed by hasRole", "rwawatch.py", "if not h or int(h, 16) != 1:\n            return None", "if False:\n            return None"),
 ("ETF Solana gate", "rwawatch.py", "gate = solana_node_gate(now)", 'gate = {"ok": True, "slot": None, "node": None, "ctl": None}'),
 # rwawatch-control/1 (spec/control-record.md), 0.3.0
 ("CR-14 one key = no code", "rwawatch.py", 'if len(code) <= 2:\n        return _holder("eoa"', 'if False:\n        return _holder("eoa"'),
 ("CR-14 threshold in range", "rwawatch.py", "if t is not None and 1 <= t <= len(members):", "if t is not None:"),
 ("CR-14 getOwners well-formed", "rwawatch.py", "if n == 0 or n > 256 or len(b) != 64 + 32 * n:", "if False:"),
 ("CR-14 getOwners words are addresses", "rwawatch.py", 'if any(w[:12] != b"\\0" * 12 for w in words):', "if False:"),
 ("CR-7 EIP-1967 admin slot", "rwawatch.py", 'if a and int(a, 16):\n            return _power("present", "0x" + a[-40:].lower(), "eip1967.admin")', 'if False:\n            return _power("present", "0x" + a[-40:].lower(), "eip1967.admin")'),
 ("CR-6 zero owner is absent", "rwawatch.py", "zero = owner_key is not None and int(owner_key, 16) == 0", "zero = False"),
 ("CR-15 vault derived from the declared multisig", "rwawatch.py", 'if squads_vault(d["multisig"], d["vault_index"]) != address:', "if False:"),
 ("CR-15 PDA off the curve", "rwawatch.py", "if not _on_ed25519_curve(h):", "if True:"),
 ("CR-15 Squads discriminator", "rwawatch.py", "if raw[:8] != SQUADS_MULTISIG_DISCRIMINATOR:", "if False:"),
 ("CR-15 Squads members and threshold", "rwawatch.py", "if n == 0 or len(raw) < o + 33 * n or not 1 <= threshold <= n:", "if False:"),
 ("CR-17 holder node error said", "rwawatch.py", "except RpcError as ex:                                   # [CR-17]", "except ZeroDivisionError as ex:                          # [CR-17]"),
 ("S1 explorer failing every term", "rwawatch.py", "if errors and len(errors) == n_terms:", "if False:"),
 ("S1 not searched is null", "rwawatch.py", 'searched = not status.startswith("not searched")', "searched = True"),
 ("agent: control in the council", "rwawatch_agents.py", "           _agent_control, _agent_etf]", "           ]"),
 ("P1 power change", "rwawatch_agents.py", 'if a != b:\n                changes.append(f"{name}: {pw}', 'if False:\n                changes.append(f"{name}: {pw}'),
 ("P2 holder change", "rwawatch_agents.py", "if a != b:\n                diff =", "if False:\n                diff ="),
 ("P3 legacy control fields", "rwawatch_agents.py", "if p is not None and f in t and f in p and t[f] != p[f]:", "if False:"),
 ("P6 current record validated", "rwawatch_agents.py", 'err = "no control record" if c is None else validate_control(c, key[1])', "err = None"),
 ("P6 baseline record validated", "rwawatch_agents.py", "perr = validate_control(pc, key[1])", "perr = None"),
 ("CR-5 address form checked by the council", "rwawatch_agents.py", 'err = "no control record" if c is None else validate_control(c, key[1])', 'err = "no control record" if c is None else validate_control(c)'),
 ("CR-5 address form", "rwawatch_agents.py", "                if not address_ok(chain, a):", "                if False:"),
 ("CR-5 absent carries no reason", "rwawatch_agents.py", 'if p["status"] == "absent" and (p["holder"] is not None or p["reason"] is not None):', 'if p["status"] == "absent" and (p["holder"] is not None):'),
 ("CR-19 holder owner compared", "rwawatch_agents.py", 'HOLDER_COMPARED = ("kind", "members", "threshold", "min_delay_s", "owner")', 'HOLDER_COMPARED = ("kind", "members", "threshold", "min_delay_s")'),
 ("CR-19 holder kind compared", "rwawatch_agents.py", 'HOLDER_COMPARED = ("kind", "members", "threshold", "min_delay_s", "owner")', 'HOLDER_COMPARED = ("members", "threshold", "min_delay_s", "owner")'),
 ("P3 control_key compared", "rwawatch_agents.py", '"mint_authority", "control_key")', '"mint_authority")'),
 ("P3 transfer hook and flags compared", "rwawatch_agents.py", '"permanent_delegate", "transfer_hook_program", "flags",', '"permanent_delegate",'),
 ("S2 null named apart in S3", "rwawatch_agents.py", "unsearched_now = [x for x in lost if x not in gone]", "unsearched_now = []"),
 ("P7 first reading said", "rwawatch_agents.py", "first.append(name)\n            continue", "continue"),
 ("CR-2 unknown spec", "rwawatch_agents.py", 'if c["spec"] != CONTROL_SPEC:', "if False:"),
 ("CR-5 status vocabulary", "rwawatch_agents.py", 'if p["status"] not in POWER_STATUS:', "if False:"),
 ("CR-5 present needs holder", "rwawatch_agents.py", 'if p["status"] == "present" and not (isinstance(p["holder"], str) and p["holder"] and p["reason"] is None):', "if False:"),
 ("CR-5 not_evaluated needs reason", "rwawatch_agents.py", 'if p["status"] == "not_evaluated" and (p["holder"] is not None or not (isinstance(p["reason"], str) and p["reason"])):', "if False:"),
 ("CR-5 source type", "rwawatch_agents.py", "        if not str_or_none(src):", "        if False:"),
 ("CR-5 present/absent say their source", "rwawatch_agents.py", 'if pw[name]["status"] in ("present", "absent") and not (isinstance(src, str) and src):', "if False:"),
 ("CR-12 holders = holders of powers", "rwawatch_agents.py", "if set(hd) != holders:", "if False:"),
 ("CR-13 holder keys", "rwawatch_agents.py", "if not isinstance(e, dict) or set(e) != set(HOLDER_KEYS):", "if not isinstance(e, dict):"),
 ("CR-13 holder kind vocabulary", "rwawatch_agents.py", "if k not in HOLDER_KINDS:", "if False:"),
 ("CR-13 fields per kind", "rwawatch_agents.py", "        if extra:\n", "        if False:\n"),
 ("CR-14 multisig shape", "rwawatch_agents.py", 'if k == "multisig":\n            m = e["members"]\n            if not', 'if k == "multisig":\n            m = e["members"]\n            if False and not'),
 ("CR-14 timelock delay", "rwawatch_agents.py", 'if k == "timelock" and not', 'if False and not'),
 ("P4 ETF key not the issuer's", "rwawatch_agents.py", "if t.get(f) is False:", "if False:"),
 ("P5 ETF chain not assessed", "rwawatch_agents.py", "if not c.get(\"assessed\"):\n            out.append", "if False:\n            out.append"),
 ("P5 ETF token unreadable", "rwawatch_agents.py", "if not t.get(\"readable\"):\n                out.append", "if False:\n                out.append"),
 ("P5 ETF layer missing now", "rwawatch_agents.py", 'if previous and "etf_signal" in previous:', "if False:"),
 ("S2 blind only when false", "rwawatch_agents.py", "ctl(snapshot).items() if ok is False)", "ctl(snapshot).items() if not ok)"),
 ("S3 sight lost true -> not true", "rwawatch_agents.py", "if ok is not True and ctl(previous).get((c, f)) is True)", "if ok is False and ctl(previous).get((c, f)) is True)"),
 ("orchestrator: ETF baseline", "rwawatch_orchestrator.py", 'if any("etf_signal" in s for s in snaps):', "if False:"),
]
bad = 0
for name, f, old, new in M:
    d = os.path.join(S, "p"); shutil.rmtree(d, ignore_errors=True)
    shutil.copytree(SRC, d, ignore=shutil.ignore_patterns(".git", "evidence", "*.jsonl", "rwawatch_latest*.json", "__pycache__"))
    p = os.path.join(d, f)
    with open(p) as fh:
        src = fh.read()
    if src.count(old) != 1:
        print(f"?? {name}: pattern found {src.count(old)} times"); bad += 1; continue
    with open(p, "w") as fh:
        fh.write(src.replace(old, new))
    r = subprocess.run([sys.executable, "tests/test_rwawatch.py"], cwd=d, capture_output=True, text=True, timeout=300,
                       env=dict(os.environ, HOME=os.path.join(S, "home")))
    red = [l.split("(")[0].replace("FAIL: ", "").replace("ERROR: ", "") for l in r.stderr.splitlines() if l.startswith(("FAIL:", "ERROR:"))]
    ok = r.returncode != 0
    bad += not ok
    print(("RED  " if ok else "GREEN!") + f" {name}: {', '.join(red[:3]) or '-'}")
print("mutations surviving:", bad, "of", len(M))
