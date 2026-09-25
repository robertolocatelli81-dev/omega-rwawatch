#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OMEGA-RWAWatch · council — deterministic multi-agent posture judgement.

Each analyst inspects one facet of the current snapshot (and, where it needs one, the previous snapshot) and votes a
posture (QUIET / ELEVATED / ALERT). The council takes the most severe vote, deterministically (no randomness, no
clock), so the verdict is reproducible from the two snapshots. A posture is a flag for a human to look, not a
judgement on the fund.
"""

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
    """Total supply over the chains assessed in BOTH snapshots moved more than the tuned threshold (in %)."""
    if not previous:
        return "QUIET", "no previous snapshot to compare supply with"
    common = set(snapshot["signal"].get("chains_assessed", [])) & set(previous["signal"].get("chains_assessed", []))

    def total(s):
        return sum(t["total_supply"] for c, t in _tokens(s)
                   if c in common and t["token"] == "BUIDL" and t.get("total_supply") is not None)
    a, b = total(previous), total(snapshot)
    if a <= 0:
        return "QUIET", "no comparable supply in the previous snapshot"
    pct = abs(b - a) / a * 100
    if pct >= threshold_pct:
        return "ELEVATED", f"BUIDL supply over {sorted(common)} moved {pct:.3f}% (>= {threshold_pct}%)"
    return "QUIET", f"BUIDL supply over {sorted(common)} moved {pct:.3f}% (< {threshold_pct}%)"


def _agent_owner(snapshot, previous=None, expected_owner="0xe01605f6b6dc593b7d2917f4a0940db2a625b09e"):
    """owner() of a watched contract is not the issuer key recorded on 25/09/2026 (a transfer of control, or a wrong
    address in the registry): a human must look."""
    off = [f"{c}/{t['token']}: owner {t.get('owner')}" for c, t in _tokens(snapshot)
           if t.get("owner") is not None and t.get("owner") != expected_owner]
    return ("ELEVATED", "; ".join(off)) if off else ("QUIET", "every watched contract is owned by the recorded issuer key")


def _agent_imitations(snapshot, previous=None):
    """Unregistered tokens found by explorer search that are owned by the issuer key (a deployment to register) or carry
    BlackRock's name (not issuer deployments): a NEW one raises ELEVATED; the known list does not. A chain that could
    not be searched is said, never 'none'."""
    def found(s):
        out = {}
        for c in (s or {}).get("signal", {}).get("chains", []):
            for u in (c.get("discovery") or {}).get("unregistered", []):
                out[(c["chain"], u["address"].lower())] = u
        return out
    now, before = found(snapshot), found(previous)
    own = [f"{c}/{a[:10]}" for (c, a), u in now.items() if u.get("same_owner")]
    new = [f"{c}/{a[:10]}" for k, u in now.items() if k not in before for c, a in [k]] if previous else []
    if own:
        return "ELEVATED", f"unregistered token(s) owned by the issuer key: {own}"
    if new:
        return "ELEVATED", f"new same-named token(s) since the previous cycle: {new}"
    return "QUIET", f"{len(now)} unregistered token(s) carrying BlackRock's name known, none new, none owned by the issuer key"


COUNCIL = [_agent_coverage, _agent_structure, _agent_signed_authorizations, _agent_owner, _agent_imitations]


def judge(snapshot, previous=None, threshold_pct=2.0):
    """Run every analyst, return the most severe posture + rationale."""
    votes = [agent(snapshot, previous) for agent in COUNCIL]
    votes.append(_agent_supply_move(snapshot, previous, threshold_pct))
    worst = max(votes, key=lambda v: POSTURES.index(v[0]))
    return {"posture": worst[0], "rationale": worst[1], "votes": [{"posture": p, "why": w} for p, w in votes]}
