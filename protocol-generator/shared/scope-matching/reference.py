#!/usr/bin/env python3
"""Reference matcher for the 0.8.1 §5.2 typed scope-match rule (F40), plus a runner
for `id-scope-vectors.json`.

Not a peer and not vendored arch bytes — this is keystone's transcription of the pinned
grammar, kept executable so a peer's port has something to disagree with. Every peer's
ported matcher MUST agree with this case-for-case.

    python3 reference.py            # run the vector file
    python3 reference.py -v         # ... and print every case

Derived from the SPEC (entity-core-protocol 6285c94 §5.2/§5.4/§1.4), not from the oracle.
"""

from __future__ import annotations

import json
import pathlib
import sys

LOCAL = "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA"
REMOTE = "12D3KooWRemotePeerIdExampleBBBBBBBBBBBBBBBBBBB"


# ── §1.4 canonicalize / §5.4 matches_pattern — path-scope only, unchanged by 0.8.1 ──

def canonicalize(path: str, local_peer_id: str) -> str:
    """Resolve a peer-relative path to absolute form.

    Reserved/ambiguous forms (`./`, `../`, `*/`) are spec errors; the caller wants a
    non-match, so they fall through unchanged rather than raising.
    """
    if path.startswith(("./", "../", "*/")):
        return path
    if path.startswith("/"):
        return path
    return "/" + local_peer_id + "/" + path


def matches_pattern(path: str, pattern: str) -> bool:
    """§5.4. Both arguments MUST already be canonical (absolute)."""
    if pattern == "*":
        return True
    if pattern.startswith("/*/"):                  # interior peer-wildcard
        remainder = pattern[3:]
        i = path.find("/", 1)
        if i < 0:
            return False
        return matches_pattern(path[i + 1:], remainder)
    if pattern.endswith("/*"):                     # subtree prefix
        return path.startswith(pattern[:-1])
    return path == pattern


# ── §5.2 id-scope literal matcher — the 0.8.1 F40 addition ──────────────────────

def matches_id_pattern(value: str, pattern: str) -> bool:
    """§5.2 (0.8.1, F40). Literal comparison; exactly two wildcard forms.

    No §5.4 path transforms: no leading-/ universal reading, no `/*/` interior
    peer-wildcard, no peer-relative qualification. A pattern carrying path syntax is
    matched *as a literal string* — it is a non-match, never a fault.
    """
    if pattern == "*":
        return True
    if pattern.endswith("/*"):
        return value.startswith(pattern[:-1])      # keep the "/", drop the "*"
    return value == pattern


ID_SCOPE_DIMS = frozenset({"operations", "peers"})
PATH_SCOPE_DIMS = frozenset({"handlers", "resources"})


def matches_scope(value, scope, kind, local_peer_id) -> bool:
    """§5.2, typed. `kind` is required — deliberately no default (see README note 1)."""
    if kind == "id-scope":
        def cover(pats):
            return any(matches_id_pattern(value, p) for p in pats)
    elif kind == "path-scope":
        cv = canonicalize(value, local_peer_id)

        def cover(pats):
            return any(matches_pattern(cv, canonicalize(p, local_peer_id)) for p in pats)
    else:
        raise ValueError(f"unknown scope type {kind!r}")

    if not cover(scope.get("include", [])):
        return False
    excl = scope.get("exclude") or []
    if excl and cover(excl):
        return False
    return True


# ── fixture runner ──────────────────────────────────────────────────────────────

def _sub(s: str) -> str:
    return s.replace("{local}", LOCAL).replace("{remote}", REMOTE)


def run(verbose: bool = False) -> int:
    path = pathlib.Path(__file__).with_name("id-scope-vectors.json")
    doc = json.loads(path.read_text())

    failed = []
    for case in doc["cases"]:
        scope = {
            "include": [_sub(p) for p in case["include"]],
            "exclude": [_sub(p) for p in case.get("exclude") or []],
        }
        got = matches_scope(_sub(case["value"]), scope, case["scope_type"], LOCAL)
        ok = got == case["expect"]
        if not ok:
            failed.append(case["id"])
        if verbose or not ok:
            flag = "ok  " if ok else "FAIL"
            print(f"{flag}  {case['id']:<32} expect={str(case['expect']):<5} got={got}")

    total = len(doc["cases"])
    info = sum(1 for c in doc["cases"] if c.get("informative"))
    print(f"\n{total - len(failed)}/{total} cases agree with the reference "
          f"({info} informative, {total - info} gating)")
    if failed:
        print("FAILED: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(verbose="-v" in sys.argv))
