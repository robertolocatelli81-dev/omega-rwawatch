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
    """The code behind a watched address changed (a proxy upgrade), or the address stopped looking like a token."""
    if not previous:
        return "QUIET", "no previous snapshot to compare structure with"
    before = {(c, t["address"].lower()): t for c, t in _tokens(previous)}
    changes = []
    for c, t in _tokens(snapshot):
        p = before.get((c, t["address"].lower()))
        if p and p.get("implementation_code_sha256") and t.get("implementation_code_sha256") != p.get("implementation_code_sha256"):
            changes.append(f"{c}/{t['token']}: implementation code changed")
        if t.get("symbol") is None or t.get("total_supply") is None:
            changes.append(f"{c}/{t['token']}: no symbol or supply readable")
    return ("ELEVATED", "; ".join(changes)) if changes else ("QUIET", "implementation code unchanged on every watched address")


def _agent_signed_authorizations(snapshot, previous=None):
    """Informational: a watched token started (or stopped) exposing EIP-712 / EIP-2612 / EIP-3009 entry points."""
    now = {(c, t["address"].lower()): tuple(t.get("eip712_entry_points") or []) for c, t in _tokens(snapshot)}
    if not previous:
        exposing = [f"{c}/{a[:10]}" for (c, a), eps in now.items() if eps]
        return ("ELEVATED", f"EIP-712 entry points exposed by {exposing}") if exposing else ("QUIET", "no watched token exposes EIP-712 entry points")
    before = {(c, t["address"].lower()): tuple(t.get("eip712_entry_points") or []) for c, t in _tokens(previous)}
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


COUNCIL = [_agent_coverage, _agent_structure, _agent_signed_authorizations]


def judge(snapshot, previous=None, threshold_pct=2.0):
    """Run every analyst, return the most severe posture + rationale."""
    votes = [agent(snapshot, previous) for agent in COUNCIL]
    votes.append(_agent_supply_move(snapshot, previous, threshold_pct))
    worst = max(votes, key=lambda v: POSTURES.index(v[0]))
    return {"posture": worst[0], "rationale": worst[1], "votes": [{"posture": p, "why": w} for p, w in votes]}
