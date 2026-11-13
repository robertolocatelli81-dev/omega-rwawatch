#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OMEGA-RWAWatch · council — deterministic multi-agent posture judgement.

Each analyst inspects one facet of the current snapshot (and, where it needs one, the previous snapshot) and votes a
posture (QUIET / ELEVATED / ALERT). The council takes the most severe vote, deterministically (no randomness, no
clock), so the verdict is reproducible from the two snapshots. A posture is a flag for a human to look, not a
judgement on the fund.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rwawatch import (CONTROL_KEYS, CONTROL_SPEC, HOLDER_KEYS, HOLDER_KINDS, POWER_KEYS,  # noqa: E402
                      POWER_STATUS, POWERS, b58decode, b58encode)

POSTURES = ("QUIET", "ELEVATED", "ALERT")


def _tokens(snapshot):
    for c in (snapshot or {}).get("signal", {}).get("chains", []):
        for t in c.get("tokens", []):
            yield c["chain"], t


def _agent_coverage(snapshot, previous=None):
    """A chain whose node failed or whose positive control failed is NOT assessed: say so, never read it as quiet."""
    sig = snapshot.get("signal", {}) or {}
    missing = sig.get("chains_not_assessed", [])
    if not sig.get("chains_assessed"):
        return "ALERT", "no chain could be assessed"
    if missing:
        return "ELEVATED", f"not assessed this run: {', '.join(missing)}"
    return "QUIET", "every registered chain assessed, positive control passed on each"


def _agent_structure(snapshot, previous=None):
    """For each (chain, token): the address, symbol or decimals changed (a registry edit — NEMESIS 25/09: keyed by
    address, a swapped address found no predecessor and passed QUIET), or the code behind it changed (an upgrade)."""
    if not previous:
        return "QUIET", "no previous snapshot to compare structure with"
    before = {(c, t["token"]): t for c, t in _tokens(previous)}
    assessed_before = set(previous["signal"].get("chains_assessed", []))
    changes = []
    for c, t in _tokens(snapshot):
        p = before.get((c, t["token"]))
        if p is None:
            if c in assessed_before:        # a chain not assessed last time has no reading to compare: not a change
                changes.append(f"{c}/{t['token']}: not in the previous cycle")
            continue
        for k in ("address", "symbol", "decimals"):
            if str(t.get(k)).lower() != str(p.get(k)).lower():
                changes.append(f"{c}/{t['token']}: {k} {p.get(k)} -> {t.get(k)}")
        if p.get("implementation_code_sha256") and t.get("implementation_code_sha256") != p.get("implementation_code_sha256"):
            changes.append(f"{c}/{t['token']}: implementation code changed")
        if t.get("symbol") is None or t.get("total_supply") is None:
            changes.append(f"{c}/{t['token']}: no symbol or supply readable")
    return ("ELEVATED", "; ".join(changes)) if changes else ("QUIET", "address, symbol, decimals and implementation code unchanged for every watched token")


def _agent_signed_authorizations(snapshot, previous=None):
    """Informational: a watched token started (or stopped) exposing EIP-712 / EIP-2612 / EIP-3009 entry points."""
    now = {(c, t["token"]): tuple(t.get("eip712_entry_points") or []) for c, t in _tokens(snapshot)}
    if not previous:
        exposing = [f"{c}/{a[:10]}" for (c, a), eps in now.items() if eps]
        return ("ELEVATED", f"EIP-712 entry points exposed by {exposing}") if exposing else ("QUIET", "no watched token exposes EIP-712 entry points")
    before = {(c, t["token"]): tuple(t.get("eip712_entry_points") or []) for c, t in _tokens(previous)}
    diffs = [f"{c}/{a[:10]}: {list(before.get((c, a), ()))} -> {list(eps)}" for (c, a), eps in now.items()
             if (c, a) in before and before[(c, a)] != eps]
    return ("ELEVATED", "; ".join(diffs)) if diffs else ("QUIET", "EIP-712 entry points unchanged")


def _agent_supply_move(snapshot, previous=None, threshold_pct=2.0):
    """Per watched token: total supply over the chains assessed in BOTH snapshots moved more than the tuned threshold
    (in %). The threshold is tuned on BUIDL's series and applied to every token."""
    if not previous:
        return "QUIET", "no previous snapshot to compare supply with"
    common = set(snapshot["signal"].get("chains_assessed", [])) & set(previous["signal"].get("chains_assessed", []))

    def totals(s):
        out = {}
        for c, t in _tokens(s):
            if c in common and t.get("total_supply") is not None:
                out[t["token"]] = out.get(t["token"], 0.0) + t["total_supply"]
        return out
    a, b = totals(previous), totals(snapshot)
    moves = {k: abs(b.get(k, 0.0) - v) / v * 100 for k, v in sorted(a.items()) if v > 0}
    if not moves:
        return "QUIET", "no comparable supply in the previous snapshot"
    big = {k: m for k, m in moves.items() if m >= threshold_pct}
    shown = ", ".join(f"{k} {m:.3f}%" for k, m in moves.items())
    if big:
        return "ELEVATED", f"supply over {sorted(common)} moved >= {threshold_pct}%: " + ", ".join(f"{k} {m:.3f}%" for k, m in big.items())
    return "QUIET", f"supply over {sorted(common)} moved {shown} (< {threshold_pct}%)"


def _agent_owner(snapshot, previous=None):
    """The controlling key of a watched token (EVM owner(), Solana mint authority, Aptos object owner) is not the one
    recorded on 25/09/2026 (a transfer of control, or a wrong address in the registry): a human must look."""
    off = [f"{c}/{t['token']}: owner {t.get('owner')}" for c, t in _tokens(snapshot)
           if t.get("expected_owner") and str(t.get("owner")).lower() != str(t.get("expected_owner")).lower()]
    return ("ELEVATED", "; ".join(off)) if off else ("QUIET", "every watched token with a recorded control key still has it (BENJI on EVM exposes none: not checked)")


def _agent_imitations(snapshot, previous=None):
    """Unregistered tokens found by explorer search that are owned by the issuer key (a deployment to register) or carry
    a watched issuer's name (not deployments of a recorded key): a NEW one raises ELEVATED; the known list does not. A chain that could
    not be searched is said, never 'none'."""
    def found(s):
        out = {}
        for c in (s or {}).get("signal", {}).get("chains", []):
            for u in (c.get("discovery") or {}).get("unregistered", []):
                out[(c["chain"], u["address"].lower())] = u
        return out
    now, before = found(snapshot), found(previous)
    searched_before = {c["chain"] for c in (previous or {}).get("signal", {}).get("chains", [])
                       if c.get("assessed") and "discovery" in c}
    own = [f"{c}/{a[:10]}" for (c, a), u in now.items() if u.get("same_owner")]
    unreadable = [f"{c['chain']}/{a[:10]}" for c in snapshot.get("signal", {}).get("chains", [])
                  for a in (c.get("discovery") or {}).get("unreadable", [])]
    # "new" only where the previous cycle actually searched that chain (same class as the structure fix)
    new = [f"{c}/{a[:10]}" for (c, a) in now if (c, a) not in before and c in searched_before] if previous else []
    if own:
        return "ELEVATED", f"unregistered token(s) owned by a key recorded for the fund: {own}"
    if new:
        return "ELEVATED", f"new same-named token(s) since the previous cycle: {new}"
    if unreadable:
        return "ELEVATED", f"search match(es) that could not be read this run, so not classified: {unreadable}"
    # the search stopped seeing a fund it saw last cycle: coverage lost, not "no imitation"
    def ctl(s):
        return {(c["chain"], f): ok for c in (s or {}).get("signal", {}).get("chains", [])
                for f, ok in ((c.get("discovery") or {}).get("search_control") or {}).items()}
    lost = sorted(f"{c}/{f}" for (c, f), ok in ctl(snapshot).items() if ok is not True and ctl(previous).get((c, f)) is True)
    if lost:                                                                     # [S3]
        now_ctl = ctl(snapshot)
        gone = [x for x in lost if now_ctl.get(tuple(x.split("/", 1))) is False]
        unsearched_now = [x for x in lost if x not in gone]                      # [S2] null: not searched this cycle
        return "ELEVATED", "; ".join(
            ([f"explorer search no longer finds the registered token of: {gone}"] if gone else [])
            + ([f"found by the explorer search last cycle, not searched this cycle: {unsearched_now}"] if unsearched_now else []))
    # [S2] blind = the explorer answered and the registered token is not in its results; not searched = no explorer, or
    # it failed every term: two different facts, named apart
    blind = sorted(f"{c}/{f}" for (c, f), ok in ctl(snapshot).items() if ok is False)
    unsearched = sorted({c["chain"]: (c.get("discovery") or {}).get("status", "") for c in snapshot.get("signal", {}).get("chains", [])
                         if any(v is None for v in ((c.get("discovery") or {}).get("search_control") or {}).values())}.items())
    return "QUIET", (f"{len(now)} unregistered token(s) carrying a watched issuer's name known, none new, none owned by a "
                     f"recorded key" + (f"; search blind (control failed) for {blind}" if blind else "")
                     + (f"; not searched: {', '.join(f'{c} ({st})' for c, st in unsearched)}" if unsearched else ""))


# ───────────────────────── control record (spec/control-record.md, rwawatch-control/1) ──
def address_ok(chain, a):
    """[CR-5] `a` is written as the chain of the token writes an address: EVM `0x` + 40 lower-case hex; Solana base58 of
    32 bytes, canonical; Aptos `0x` + 1 to 64 lower-case hex; Stellar an account `G` + 55 base32 characters, or the
    owner's `signers-sha256:` + 64 lower-case hex. re.fullmatch, so a trailing newline is not accepted."""
    if not isinstance(a, str):
        return False
    if chain == "solana":
        try:
            b = b58decode(a)
        except ValueError:
            return False
        return len(b) == 32 and b58encode(b) == a
    if chain == "aptos":
        return re.fullmatch(r"0x[0-9a-f]{1,64}", a) is not None
    if chain == "stellar":
        return re.fullmatch(r"G[A-Z2-7]{55}|signers-sha256:[0-9a-f]{64}", a) is not None
    return re.fullmatch(r"0x[0-9a-f]{40}", a) is not None


def validate_control(c, chain=None):
    """[CR-2..CR-17, P6] None when `c` is a well-formed control record, else the first reason it is not. Closed: an
    unknown spec, an unknown or missing key, a value outside its vocabulary is a reason; with `chain`, an address not
    written as that chain writes it [CR-5] is a reason too (the council always passes the chain)."""
    if not isinstance(c, dict) or set(c) != set(CONTROL_KEYS):
        return f"control keys {sorted(c, key=str) if isinstance(c, dict) else type(c).__name__} are not {list(CONTROL_KEYS)}"
    if c["spec"] != CONTROL_SPEC:
        return f"unknown control spec {c['spec']!r}"
    pw, hd = c["powers"], c["holders"]
    if not isinstance(pw, dict) or set(pw) != set(POWERS):
        return f"powers {sorted(pw, key=str) if isinstance(pw, dict) else type(pw).__name__} are not {list(POWERS)}"
    holders = set()
    for name in POWERS:
        p = pw[name]
        if not isinstance(p, dict) or set(p) != set(POWER_KEYS):
            return f"power {name}: keys are not {list(POWER_KEYS)}"
        if p["status"] not in POWER_STATUS:
            return f"power {name}: status {p['status']!r} outside {list(POWER_STATUS)}"
        if p["status"] == "present" and not (isinstance(p["holder"], str) and p["holder"] and p["reason"] is None):
            return f"power {name}: present needs a holder and no reason"
        if p["status"] == "absent" and (p["holder"] is not None or p["reason"] is not None):
            return f"power {name}: absent carries no holder and no reason"
        if p["status"] == "not_evaluated" and (p["holder"] is not None or not (isinstance(p["reason"], str) and p["reason"])):
            return f"power {name}: not_evaluated needs a reason and no holder"
        if p["holder"] is not None:
            holders.add(p["holder"])
    if not isinstance(hd, dict):
        return "holders is not an object"
    for h in list(holders):
        o = hd.get(h).get("owner") if isinstance(hd.get(h), dict) else None
        if isinstance(o, str) and o:
            holders.add(o)
    if set(hd) != holders:
        return f"holders {sorted(hd, key=str)} are not the holders of the powers {sorted(holders, key=str)}"
    def is_int(x):
        return isinstance(x, int) and not isinstance(x, bool)

    def str_or_none(x):
        return x is None or (isinstance(x, str) and x != "")
    for name in POWERS:
        src = pw[name]["source"]
        if pw[name]["status"] in ("present", "absent") and not (isinstance(src, str) and src):
            return f"power {name}: {pw[name]['status']} needs the source it was read from"
        if not str_or_none(src):
            return f"power {name}: source is neither a non-empty string nor null"
    for h, e in hd.items():
        if not isinstance(e, dict) or set(e) != set(HOLDER_KEYS):
            return f"holder {h}: keys are not {list(HOLDER_KEYS)}"
        k = e["kind"]
        if k not in HOLDER_KINDS:
            return f"holder {h}: kind {k!r} outside {list(HOLDER_KINDS)}"
        if not (str_or_none(e["source"]) and str_or_none(e["reason"]) and str_or_none(e["owner"])):
            return f"holder {h}: source, reason and owner are each a non-empty string or null"
        allowed = {"multisig": {"members", "threshold", "min_delay_s"}, "timelock": {"min_delay_s"},
                   "contract": {"owner"}}.get(k, set())
        extra = [f for f in ("members", "threshold", "min_delay_s", "owner") if f not in allowed and e[f] is not None]
        if extra:
            return f"holder {h}: a {k} carries no {extra}"
        if k == "multisig":
            m = e["members"]
            if not (isinstance(m, list) and m and all(isinstance(x, str) and x for x in m) and m == sorted(set(m))
                    and is_int(e["threshold"]) and 1 <= e["threshold"] <= len(m)):
                return f"holder {h}: a multisig needs sorted distinct members and a threshold between 1 and their number"
            if e["min_delay_s"] is not None and not (is_int(e["min_delay_s"]) and e["min_delay_s"] >= 0):
                return f"holder {h}: min_delay_s is not a non-negative integer"
        if k == "timelock" and not (is_int(e["min_delay_s"]) and e["min_delay_s"] >= 0):
            return f"holder {h}: a timelock needs a non-negative min_delay_s"
        if k == "not_evaluated" and not e["reason"]:
            return f"holder {h}: not_evaluated needs a reason"
    if chain is not None:                                                                   # [CR-5]
        for h, e in hd.items():
            for a in [h] + ([e["owner"]] if e["owner"] is not None else []) + list(e["members"] or []):
                if not address_ok(chain, a):
                    return f"address {a!r} is not written as {chain} writes an address"
    return None


# fields written before rwawatch-control/1 that carry control: compared too, so an older baseline is not blind [P3]
LEGACY_CONTROL_FIELDS = ("freeze_authority", "permanent_delegate", "transfer_hook_program", "flags",
                         "mint_authority", "control_key")
HOLDER_COMPARED = ("kind", "members", "threshold", "min_delay_s", "owner")          # [CR-19]


def _layer_tokens(snapshot):
    """(layer, chain, token name) -> token, for every token of an assessed chain of both layers."""
    out = {}
    for layer in ("signal", "etf_signal"):
        for c in ((snapshot or {}).get(layer) or {}).get("chains", []):
            if not c.get("assessed"):
                continue
            for t in c.get("tokens", []):
                if layer == "etf_signal" and not t.get("readable"):
                    continue                                     # [P5] said by the ETF analyst
                out[(layer, c["chain"], t["token"])] = t
    return out


def _agent_control(snapshot, previous=None):
    """[P1, P2, P3, P6, P7] Who can own, upgrade, mint, freeze, seize or pause each watched token, and the guard on each
    holder (single key, multisig members and threshold, timelock delay): any change since the baseline is raised."""
    now, before = _layer_tokens(snapshot), _layer_tokens(previous)
    bad, changes, first = [], [], []
    for key, t in sorted(now.items()):
        name = f"{key[1]}/{key[2]}" + (" (ETF)" if key[0] == "etf_signal" else "")
        p = before.get(key)
        for f in LEGACY_CONTROL_FIELDS:                                                   # [P3]
            if p is not None and f in t and f in p and t[f] != p[f]:
                changes.append(f"{name}: {f} {p[f]} -> {t[f]}")
        c = t.get("control")
        err = "no control record" if c is None else validate_control(c, key[1])                  # [CR-1, P6]
        if err:
            bad.append(f"{name}: {err}")
            continue
        if p is None:
            continue
        pc = p.get("control")
        if pc is None:                                                                    # [P7]
            first.append(name)
            continue
        perr = validate_control(pc, key[1])
        if perr:
            bad.append(f"{name}: baseline control record refused ({perr})")
            continue
        for pw in POWERS:                                                                 # [P1, CR-18]
            a, b = (pc["powers"][pw]["status"], pc["powers"][pw]["holder"]), (c["powers"][pw]["status"], c["powers"][pw]["holder"])
            if a != b:
                changes.append(f"{name}: {pw} {a[0]} {a[1]} -> {b[0]} {b[1]}")
        for h in sorted(set(c["holders"]) & set(pc["holders"])):                          # [P2, CR-19]
            a = {k: pc["holders"][h][k] for k in HOLDER_COMPARED}
            b = {k: c["holders"][h][k] for k in HOLDER_COMPARED}
            if a != b:
                diff = ", ".join(f"{k} {a[k]} -> {b[k]}" for k in HOLDER_COMPARED if a[k] != b[k])
                changes.append(f"{name}: holder {h}: {diff}")
    if bad or changes:
        return "ELEVATED", "; ".join(bad + changes)
    return "QUIET", ("control unchanged for every token with a control record in both cycles"
                     + (f"; first control reading for {first}" if first else ""))


def _agent_etf(snapshot, previous=None):
    """[P4, P5] The tokenized-ETF layer: a chain not assessed, a token not readable, or a control key that is not the one
    recorded for the issuer (EVM owner / sole admin, Solana mint and freeze authority) is raised."""
    if "etf_signal" not in (snapshot or {}):
        if previous and "etf_signal" in previous:
            return "ELEVATED", "the ETF layer was read in the baseline and is missing now"
        return "QUIET", "no ETF layer in this snapshot or in the baseline"
    e = snapshot.get("etf_signal") or {}
    out, unknown = [], []
    for c in e.get("chains", []):
        if not c.get("assessed"):
            out.append(f"{c.get('chain')}: ETF chain not assessed ({c.get('reason', 'a token not readable')})")
        for t in c.get("tokens", []):
            name = f"{c.get('chain')}/{t.get('token')}"
            if not t.get("readable"):
                out.append(f"{name}: not readable ({t.get('reason', '')})")
                continue
            for f in ("same_owner", "same_mint_authority", "same_freeze_authority"):
                if t.get(f) is False:
                    out.append(f"{name}: {f} false (the key read is not the one recorded for the issuer)")
                elif f in t and t[f] is None:
                    unknown.append(f"{name}: {f}")
    if out:
        return "ELEVATED", "; ".join(out)
    return "QUIET", ("every ETF chain assessed, every control key the one recorded for the issuer"
                     + (f"; not comparable: {unknown}" if unknown else ""))


COUNCIL = [_agent_coverage, _agent_structure, _agent_signed_authorizations, _agent_owner, _agent_imitations,
           _agent_control, _agent_etf]


def judge(snapshot, previous=None, threshold_pct=2.0):
    """Run every analyst, return the most severe posture + rationale."""
    votes = [agent(snapshot, previous) for agent in COUNCIL]
    votes.append(_agent_supply_move(snapshot, previous, threshold_pct))
    worst = max(votes, key=lambda v: POSTURES.index(v[0]))
    return {"posture": worst[0], "rationale": worst[1], "votes": [{"posture": p, "why": w} for p, w in votes]}
