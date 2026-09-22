#!/usr/bin/env python3
"""skip-provenance-gate.py — every SKIP in a published report must be explained.

WHY THIS EXISTS
    [ADR-0012] and the oracle's own summary line both say it: **a skip counts as a
    failure.** An unexercised surface is an untested surface. But a `--profile core`
    run legitimately skips 106 checks, because the core profile carves out the
    standard-extension categories this repo deliberately does not implement. So the
    skip count is not zero and cannot be, and "0F" beside "106S" is honest.

    Nothing checked WHICH skips. Measured 2026-09-03 across all 46 tracked reports:
    seven skips in the whole cohort were not explained by a declared carve-out, and
    six of them were real coverage loss —

      rust-wasm, rust-wasm-wasmtime   multisig/valid_2of3_peer_signed_accepted
                                      multisig/below_threshold_rejected
                                      multisig/below_threshold_denied_write
        "accept-path requires the peer's on-disk key (M6 root-at-local):
         peer keypair not found"

    — an UNCONFIGURED SURFACE, not a profile carve-out. Those two peers were the only
    2 of 46 harnesses that never wrote `~/.entity/peers/<name>/keypair`, they alone
    reported 109 skips against the cohort's 106, and they published 0-FAIL in a matrix
    whose prose said exactly one row carried a gap. The figure was printed honestly in
    the row and contradicted by the sentence above it. Provisioning the keypair took
    both to 313P/337W/0F/106S.

    The seventh is `cobol`'s `concurrency/t1_3_no_head_of_line`, a disclosed and
    spec-legal payload-capacity bound (CONFORMANCE-MATRIX.md §1, finding F53). It is
    allowlisted BY NAME below, with its disclosure named, because that is the whole
    difference between a disclosure and a defect.

THE RULE
    A skip is acceptable only if it says why, in the oracle's own words, and the reason
    is a profile carve-out — or it is allowlisted here against a written disclosure.
    Anything else is an unconfigured surface wearing a green verdict.

    This is deliberately a check on the MESSAGE the oracle emitted, not on a count.
    A count tells you a peer differs from the cohort; it does not tell you whether the
    difference is disclosed. And a cohort that drifts together — every peer missing the
    same surface — moves the "cohort standard" and the count check sees nothing at all.

USAGE
    tools/skip-provenance-gate.py            # gate every tracked report
    tools/skip-provenance-gate.py --self-test
EXIT
    0  every skip explained
    1  at least one unexplained skip
"""
import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

# A skip whose message contains any of these is a declared `--profile core` carve-out:
# the oracle saying "this category/check is extension-targeted and core does not run it".
CARVE_OUT_MARKERS = (
    "outside --profile core",
    "carve-out",
    "§9.0",  # V7 v7.72 §9.0, the profile-scoping section
)

# Allowlisted skips: an unexercised check that IS disclosed in published prose. The
# value is where the disclosure lives — a bare "known issue" is not a disclosure.
ALLOWLIST = {
    ("cobol", "concurrency", "t1_3_no_head_of_line"):
        "CONFORMANCE-MATRIX.md §1 + shared/findings/conformance-payload-capacity-floor.md "
        "(F53): a 264109-byte probe against a spec-legal 65535-byte frame cap, refused "
        "with a correlated 413.",
}


def checks(obj, out):
    if isinstance(obj, dict):
        if "name" in obj and "severity" in obj:
            out.append(obj)
        for v in obj.values():
            checks(v, out)
    elif isinstance(obj, list):
        for v in obj:
            checks(v, out)
    return out


def explained(msg):
    return any(m in msg for m in CARVE_OUT_MARKERS)


def audit(reports):
    """-> (unexplained, n_reports, n_skips) — the counts are returned so the caller
    can print them. A gate that examined zero things prints the same word as one that
    examined forty-six; this repo has shipped that defect five times."""
    unexplained, n_skips = [], 0
    for peer, path in sorted(reports):
        rows = checks(json.loads(path.read_text()), [])
        for r in rows:
            if r.get("severity") != "SKIP":
                continue
            n_skips += 1
            key = (peer, r.get("category", "?"), r["name"])
            if key in ALLOWLIST:
                continue
            if explained(r.get("message") or ""):
                continue
            unexplained.append((peer, key[1], key[2], (r.get("message") or "").strip()[:100]))
    return unexplained, len(reports), n_skips


def tracked_reports():
    return [
        (p.parent.parent.name, p)
        for p in REPO.glob("protocol-generator/*/status/CONFORMANCE-REPORT.json")
    ]


def self_test():
    """Plant the defect rather than read the code — a gate with no regression suite is
    a script that has not been wrong yet."""
    ok = True
    good = {"checks": [{"name": "x", "category": "type", "severity": "SKIP",
                        "message": "outside --profile core (V7 v7.72 §9.0)"}]}
    bad = {"checks": [{"name": "valid_2of3_peer_signed_accepted", "category": "multisig",
                       "severity": "SKIP",
                       "message": "accept-path requires the peer's on-disk key"}]}
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        gp = pathlib.Path(d, "g.json"); gp.write_text(json.dumps(good))
        bp = pathlib.Path(d, "b.json"); bp.write_text(json.dumps(bad))
        u, n, s = audit([("fake", gp)])
        if u or n != 1 or s != 1:
            print("  self-test FAIL: carve-out skip was not accepted"); ok = False
        u, n, s = audit([("fake", bp)])
        if not u:
            print("  self-test FAIL: unconfigured-surface skip was NOT caught"); ok = False
        # vacuity: an empty report set must not read as success
        u, n, s = audit([])
        if n != 0 or s != 0:
            print("  self-test FAIL: empty audit miscounted"); ok = False
    print("skip-provenance-gate: self-test", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv):
    if "--self-test" in argv:
        return self_test()
    reports = tracked_reports()
    if not reports:
        print("skip-provenance-gate: ERROR no tracked reports found", file=sys.stderr)
        return 1
    unexplained, n_reports, n_skips = audit(reports)
    print(f"skip-provenance-gate: {n_reports} tracked report(s), {n_skips} skip(s) examined, "
          f"{len(ALLOWLIST)} disclosed allowlist entr(y/ies)")
    if not unexplained:
        print("PASS — every skip is a declared --profile core carve-out or a disclosed gap.")
        return 0
    print(f"\n{len(unexplained)} UNEXPLAINED SKIP(S) — an unexercised surface behind a green verdict:")
    for peer, cat, name, msg in unexplained:
        print(f"  {peer}: {cat}/{name}")
        print(f"      {msg}")
    print("\nEach is either an unconfigured surface (fix the harness) or a real gap")
    print("(disclose it in CONFORMANCE-MATRIX.md and allowlist it here, by name).")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
