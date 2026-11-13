#!/usr/bin/env python3
"""Orphans between spec/control-record.md, the code and the tests (no network).

Counts, and lists:
  - clauses of the specification ([CR-n], [Pn], [Sn]) that no test cites (a test cites a clause by writing its
    identifier, e.g. `CR-7`, in its name or docstring);
  - identifiers cited by a test that the specification does not define;
  - keys and vocabularies of the record whose code constant and specification text differ (each key written in the
    specification between backticks in the clause that defines it, and nothing more).
Exit status 0 only when the count is 0.

    python3 tools/spec_orphans.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import rwawatch as core  # noqa: E402

SPEC = os.path.join(ROOT, "spec", "control-record.md")
TESTS = os.path.join(ROOT, "tests", "test_rwawatch.py")
CLAUSE = re.compile(r"\[((?:CR|P|S)-?\d+)\]")
CITE = re.compile(r"\b((?:CR-\d+)|(?:P\d+)|(?:S\d+))\b")


def clause_text(spec, cid):
    """The text of one clause: from its identifier to the next bullet, heading or table row."""
    m = re.search(r"\[" + re.escape(cid) + r"\](.*?)(?=\n- \*\*\[|\n## |\n\| |\Z)", spec, re.S)
    return m.group(1) if m else ""


def backticked(text):
    return set(re.findall(r"`([a-z_]+)`", text))


def orphans():
    with open(SPEC, encoding="utf-8") as f:
        spec = f.read()
    with open(TESTS, encoding="utf-8") as f:
        tests = f.read()
    defined = set(CLAUSE.findall(spec))
    cited = set(CITE.findall(tests))
    out = [f"clause {c} has no test" for c in sorted(defined - cited)]
    out += [f"test cites {c}, which the specification does not define" for c in sorted(cited - defined)]
    checks = (("CR-3", core.CONTROL_KEYS, "control keys"), ("CR-4", core.POWERS, "powers"),
              ("CR-13", core.HOLDER_KEYS + core.HOLDER_KINDS, "holder keys and kinds"))
    for cid, const, what in checks:
        words = backticked(clause_text(spec, cid))
        for w in sorted(set(const) - words):
            out.append(f"{what}: `{w}` is in the code, not in {cid}")
        for w in sorted(words - set(const)):
            out.append(f"{what}: `{w}` is in {cid}, not in the code")
    cr5 = backticked(clause_text(spec, "CR-5"))
    for w in sorted(set(core.POWER_KEYS + core.POWER_STATUS) - cr5):
        out.append(f"power keys and statuses: `{w}` is in the code, not in CR-5")
    for w in sorted({"status", "holder", "source", "reason", "present", "absent", "not_evaluated"} ^ set(core.POWER_KEYS + core.POWER_STATUS)):
        out.append(f"power keys and statuses: `{w}` differs between CR-5 and the code")
    if f"`{core.CONTROL_SPEC}`" not in clause_text(spec, "CR-2"):
        out.append(f"CR-2 does not name the spec version of the code ({core.CONTROL_SPEC})")
    return sorted(defined), out


if __name__ == "__main__":
    defined, found = orphans()
    for o in found:
        print("ORPHAN", o)
    print(f"clauses: {len(defined)}; orphans: {len(found)}")
    sys.exit(1 if found else 0)
