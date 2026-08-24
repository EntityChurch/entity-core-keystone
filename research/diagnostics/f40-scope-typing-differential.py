"""F40 differential: cohort behaviour (canonicalize every dimension) vs the
0.8.1-conformant reading (path-scope canonicalized, id-scope literal).

The conformant column now implements the PINNED §5.2 grammar (entity-core-protocol
`6285c94`), which confirmed this harness's original assumption — so the published
divergence table is unchanged. The portable cohort-facing form of these cases is
`protocol-generator/shared/scope-matching/id-scope-vectors.json`; this file stays as the
before/after differential against the real peer.

The "cohort" column is built from the REAL keystone python peer's `_canon` +
`matches_pattern` — the primitives, which are unchanged. It is NOT the peer's current
verdict path: since the F40 fix landed, `_matches_scope` branches on dimension kind and
the peer agrees with the 0.8.1 column. So this file is now a **before/after** record of
the divergence class, not a live measurement of this peer. To measure a peer as it
actually behaves today, run its Part-B fixture test against
`shared/scope-matching/id-scope-vectors.json`.

--- Live cohort attribution (2026-07-28, oracle `fceb61f`) ---

The static model above answers "what SHOULD happen"; it cannot attribute a live
peer's 403 to canonicalization vs. an unrelated delegation denial (the confound
that false-positived `swift` at `af8a582` — see
research/stewardship/HANDOFF-TO-ARCH-2026-07-27-af8a582-cohort-remeasurement.md §3).
Arch's fix at `fceb61f` adds a control row (`f40_id_scope_include_control`, Row A:
the same grant minus the exclude) and rewrites `f40_id_scope_exclude_literal` (Row B)
to carry BOTH rows' (status, code, allow) in its `details`, scored as the A→B
differential rather than Row B in isolation. Run this file with a directory of
per-peer `validate-peer` JSON reports to attribute all 46 peers directly from that
measured data, no grep, no modelling:

    python3 research/diagnostics/f40-scope-typing-differential.py <reports_dir>

`<reports_dir>` holds one JSON report per peer, named `<peer>.json` (the raw
`-json-out` of a `-category authz` or `--profile core` run against the pinned
oracle). See `attribute_cohort()` below for the rubric.
"""
import json
import pathlib
import sys
import types

# Stub the optional crypto dep (unused by the pure matching functions) so the
# REAL peer module imports — the cohort column must be measured, not modelled.
_stubs = [
    "cryptography",
    "cryptography.exceptions",
    "cryptography.hazmat",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.primitives.asymmetric",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "cryptography.hazmat.primitives.asymmetric.ed448",
    "cryptography.hazmat.primitives.serialization",
]
for _m in _stubs:
    _mod = types.ModuleType(_m)
    _mod.__path__ = []  # make each a package so submodule imports resolve
    sys.modules[_m] = _mod
sys.modules["cryptography.exceptions"].InvalidSignature = type(
    "InvalidSignature", (Exception,), {}
)
for _name in ("Ed25519PrivateKey", "Ed25519PublicKey"):
    setattr(sys.modules["cryptography.hazmat.primitives.asymmetric.ed25519"], _name, object)
for _name in ("Ed448PrivateKey", "Ed448PublicKey"):
    setattr(sys.modules["cryptography.hazmat.primitives.asymmetric.ed448"], _name, object)
for _name in ("Encoding", "PrivateFormat", "PublicFormat", "NoEncryption"):
    setattr(sys.modules["cryptography.hazmat.primitives.serialization"], _name, object)

sys.path.insert(0, "protocol-generator/python/src")

from entity_core.peer.capability import _canon, matches_pattern  # noqa: E402

LOCAL = "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA"
REMOTE = "12D3KooWRemotePeerIdExampleBBBBBBBBBBBBBBBBBBB"


def cohort_covered(local, value, pats):
    """What all 43 peers do today: canonicalize BOTH sides, every dimension."""
    cv = _canon(local, value)
    return any(matches_pattern(cv, _canon(local, p)) for p in pats)


def matches_id_pattern(value, pattern):
    """The PINNED 0.8.1 §5.2 id-scope matcher (entity-core-protocol `6285c94`): literal,
    with exactly two wildcard forms — bare `*` and a trailing `/*` segment-prefix.

    Note this is NOT `matches_pattern` minus canonicalization: `matches_pattern` also
    carries the `/*/` interior peer-wildcard branch, which the pinned grammar drops. On
    the audit's published cases the two agree (both deny), so the 2026-07-27 divergence
    table stands unchanged — but they part company on a `/`-namespaced operation value
    (`matches_pattern("a/x", "/*/x")` is True; the pinned reading is False), so the model
    is stated directly rather than borrowed."""
    if pattern == "*":
        return True
    if pattern.endswith("/*"):
        return value.startswith(pattern[:-1])
    return value == pattern


def conformant_id_covered(local, value, pats):
    """0.8.1 F40: id-scope compared as literal identifiers — no canonicalization."""
    return any(matches_id_pattern(value, p) for p in pats)


# (dimension, scope-type, value, include-patterns) — exclude handled separately
CASES = [
    # --- the shipped discovery floor: bare identifiers, both sides agree ---
    ("operations", "id",   "get",     ["get"]),
    ("operations", "id",   "request", ["request"]),
    ("operations", "id",   "put",     ["get"]),
    ("operations", "id",   "get",     ["*"]),
    ("peers",      "id",   REMOTE,    [REMOTE]),
    ("peers",      "id",   REMOTE,    ["*"]),
    ("peers",      "id",   REMOTE,    [LOCAL]),
    # --- path-ish forms in an ID dimension: where the two readings split ---
    ("operations", "id",   "get",     ["/*/get"]),
    ("operations", "id",   "get",     ["/" + LOCAL + "/get"]),
    ("peers",      "id",   REMOTE,    ["/*/*"]),
    ("peers",      "id",   REMOTE,    ["/*/" + REMOTE]),
    ("operations", "id",   "get",     ["/get"]),
    ("operations", "id",   "read/x",  ["read/*"]),
    # --- path-scope dimensions: canonicalization is CORRECT here, control group ---
    ("handlers",   "path", "system/tree",       ["system/tree"]),
    ("handlers",   "path", "system/tree",       ["/*/system/tree"]),
    ("resources",  "path", "system/type/a",     ["system/type/*"]),
]


def fmt(b):
    return "ALLOW" if b else "deny "


def run_static_model():
    print(f"{'dim':<11} {'ty':<5} {'value':<24} {'patterns':<34} {'cohort':<7} {'0.8.1':<7} {'':<4}")
    print("-" * 100)

    diverged = []
    for dim, ty, value, pats in CASES:
        coh = cohort_covered(LOCAL, value, pats)
        if ty == "id":
            con = conformant_id_covered(LOCAL, value, pats)
        else:
            con = coh  # path-scope: 0.8.1 keeps canonicalization
        mark = ""
        if coh != con:
            mark = "<-- DIVERGES"
            diverged.append((dim, ty, value, pats, coh, con))
        vs = value if len(value) < 24 else value[:21] + "..."
        ps = str(pats) if len(str(pats)) < 34 else str(pats)[:31] + "..."
        print(f"{dim:<11} {ty:<5} {vs:<24} {ps:<34} {fmt(coh):<7} {fmt(con):<7} {mark}")

    print()
    print(f"DIVERGENCES: {len(diverged)} of {len(CASES)} cases")
    print()

    # exclude-direction: the privilege-relevant one
    print("=== exclude-direction (scope = include:['*'], exclude:[P]) ===")
    print("a scope matches iff covered(include) AND NOT covered(exclude)")
    print()
    EXCL = [
        ("operations", "get", ["/*/get"]),
        ("peers", REMOTE, ["/*/*"]),
        ("operations", "get", ["get"]),
    ]
    for dim, value, excl in EXCL:
        coh_final = cohort_covered(LOCAL, value, ["*"]) and not cohort_covered(LOCAL, value, excl)
        con_final = conformant_id_covered(LOCAL, value, ["*"]) and not conformant_id_covered(LOCAL, value, excl)
        mark = "<-- DIVERGES" if coh_final != con_final else ""
        vs = value if len(value) < 20 else value[:17] + "..."
        print(f"{dim:<11} {vs:<20} exclude={str(excl):<16} cohort={fmt(coh_final)} 0.8.1={fmt(con_final)} {mark}")


# --- Live cohort attribution against measured `fceb61f` reports ---------------

def _row(details, key):
    """Pull one row's (allow, status, code) out of a check's `details`, tolerating
    the two shapes the oracle emits: rowA/rowB nested under
    f40_id_scope_exclude_literal, or the single "row":"A" shape under
    f40_id_scope_include_control."""
    if not isinstance(details, dict):
        return None
    row = details.get(key)
    if isinstance(row, dict):
        return row.get("allow"), row.get("status"), row.get("code")
    return None


def classify_pair(allow_a, allow_b):
    """The A->B attribution rubric from entity-core-go `fceb61f`
    (cmd/internal/validate/authz.go, f40_id_scope_exclude_literal):
      (ALLOW,ALLOW) -> conformant literal match, exclude never fired
      (ALLOW,DENY)  -> FAIL, attributable to canonicalization (the exclude alone flipped it)
      (DENY,DENY)   -> WARN, unrelated deny — exonerate, NOT an F40 defect
      (DENY,ALLOW)  -> WARN, incoherent — harness/setup error, do not score
    """
    if allow_a and allow_b:
        return "conformant", "Row A and Row B both ALLOW — literal id-scope match"
    if allow_a and not allow_b:
        return "FAIL:canonicalization", "the exclude entry alone flipped ALLOW->DENY"
    if not allow_a and not allow_b:
        return "WARN:unrelated-deny", "baseline (Row A) already denies — not an F40 defect, exonerate"
    return "WARN:harness-error", "adding an exclude WIDENED access (Row A deny, Row B allow) — incoherent"


def attribute_peer(report):
    """Attribute one peer's measured report. Returns (verdict, detail, rowA, rowB)."""
    checks = report.get("checks", [])
    excl = next((c for c in checks if c.get("name") == "f40_id_scope_exclude_literal"), None)
    ctrl = next((c for c in checks if c.get("name") == "f40_id_scope_include_control"), None)
    if excl is None:
        return "not-measured", "f40_id_scope_exclude_literal absent (skipped category / budget_exhausted / crash-cascade)", None, None
    if excl.get("severity") == "SKIP":
        return "not-measured", excl.get("message", "SKIP"), None, None

    row_a = _row(excl.get("details"), "rowA")
    row_b = _row(excl.get("details"), "rowB")
    if row_a is None and ctrl is not None:
        # Older oracle shape, or a report where only the control check carries Row A.
        row_a = _row(ctrl.get("details"), "row") or (
            (ctrl.get("severity") == "PASS", None, None) if ctrl.get("severity") in ("PASS", "WARN") else None
        )
    if row_a is None or row_b is None:
        # No structured details at all (pre-fceb61f oracle) — fall back to the
        # bare severity, but flag it as unattributable per the swift lesson.
        sev = excl.get("severity")
        return "unattributable", f"no Row A/B details on this report (severity={sev}) — re-run against fceb61f", None, None

    allow_a, status_a, code_a = row_a
    allow_b, status_b, code_b = row_b
    verdict, detail = classify_pair(bool(allow_a), bool(allow_b))
    return verdict, detail, (allow_a, status_a, code_a), (allow_b, status_b, code_b)


def attribute_cohort(reports_dir):
    """Scan a directory of <peer>.json validate-peer reports and print the
    46-peer F40 attribution table. Retires the fc445a8 grep-derived labels per
    arch's instruction — this reads only measured (status, code, allow) pairs."""
    reports_dir = pathlib.Path(reports_dir)
    paths = sorted(reports_dir.glob("*.json"))
    if not paths:
        print(f"no *.json reports found under {reports_dir}", file=sys.stderr)
        return 1

    rows = []
    for p in paths:
        peer = p.stem
        try:
            report = json.loads(p.read_text())
        except Exception as e:  # noqa: BLE001 — surfaced in the table, not swallowed
            rows.append((peer, "error", str(e), None, None))
            continue
        verdict, detail, row_a, row_b = attribute_peer(report)
        rows.append((peer, verdict, detail, row_a, row_b))

    print(f"{'peer':<22} {'verdict':<22} {'rowA':<20} {'rowB':<20} detail")
    print("-" * 130)
    tally = {}
    for peer, verdict, detail, row_a, row_b in rows:
        tally[verdict] = tally.get(verdict, 0) + 1
        fa = f"{row_a[0]}/{row_a[2]}" if row_a else "-"
        fb = f"{row_b[0]}/{row_b[2]}" if row_b else "-"
        print(f"{peer:<22} {verdict:<22} {fa:<20} {fb:<20} {detail}")

    print()
    print(f"TOTAL: {len(rows)} peers")
    for k, v in sorted(tally.items()):
        print(f"  {k:<22} {v}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(attribute_cohort(sys.argv[1]))
    run_static_model()
