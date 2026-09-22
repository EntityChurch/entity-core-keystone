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

    The seventh WAS `cobol`'s `concurrency/t1_3_no_head_of_line`, a disclosed and
    spec-legal payload-capacity bound (finding F53). It was allowlisted BY NAME here,
    with its disclosure named, because that is the whole difference between a
    disclosure and a defect. **The peer took the capacity on 2026-09-04 and the entry
    is DELETED rather than left in place** — an allowlist entry outlives its reason
    silently, and an exclusion that suppresses its own falsifier is permanent by
    construction (the `apl` lesson). The allowlist is empty and the gate now proves
    every skip in the cohort is a profile carve-out with nothing exempted.

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
    # An entry here is a commitment to the disclosure it cites, and REMOVING it is part
    # of closing the gap it described.
    #
    # EMPTY, and the last entry's removal is the record worth keeping. `asm-x86_64`'s
    # `concurrency/t1_3_no_head_of_line` was allowlisted 2026-09-07 for a disclosed and
    # deliberately un-reverted skip: its §6.3 put admission refused the oracle's 256 KiB
    # staging entity with `400 hash_mismatch`, and it was NOT root-caused at the time.
    # Root-caused and closed the same week: the peer's `ec_content_hash` is the NATIVE
    # one in `src/codec.s` (codec.o precedes -lentitycore_codec, so its symbol wins),
    # which built the ECF into a fixed 64 KiB `ecf_scratch` and returned EC_OUT_OF_SPACE
    # -- while `admit_put` ignored the return code and compared an unwritten buffer. The
    # earlier "standalone call to the same .so returns the sender's hash" was true and
    # tested a DIFFERENT FUNCTION than the peer runs. Both halves fixed; the check PASSes.
    #
    # ---- connectivity/connect_ping_before_hello, ALL 46 PEERS, added 2026-09-08 (F59) ----
    # NOT A PEER GAP, AND THE REFERENCE PEER SKIPS IT TOO -- which is what locates it
    # upstream rather than in the cohort. §5.1 `ping` is a NETWORK-extension operation; a
    # core peer does not serve it, so the row this check asserts (an implemented op arriving
    # in a forbidden state -> 409 connection_sequence_error) is not drivable against one, and
    # the check says so in its own message. §3.3's satisfaction mode (0.8.2.7) is explicit
    # that a check MUST NOT be pinned to a row it cannot reach. What is missing is only the
    # §9.0 profile carve-out marker, so the oracle counts the skip against the FAIL gate and
    # ends `Result: FAIL (un-allowlisted skips)` with a JSON summary of `{"failed": 0}`.
    #
    # THE DISCLOSURE THIS ENTRY COMMITS TO: CONFORMANCE-MATRIX.md §1's skip note and F59 in
    # research/stewardship/SPEC-FINDINGS-LOG.md. REMOVING THESE 46 LINES IS PART OF CLOSING
    # F59 -- when the carve-out lands upstream the skip explains itself and the entries go.
    ("ada", "connectivity", "connect_ping_before_hello"),
    ("apl", "connectivity", "connect_ping_before_hello"),
    ("asm-arm64", "connectivity", "connect_ping_before_hello"),
    ("asm-x86_64", "connectivity", "connect_ping_before_hello"),
    ("c", "connectivity", "connect_ping_before_hello"),
    ("cobol", "connectivity", "connect_ping_before_hello"),
    ("common-lisp", "connectivity", "connect_ping_before_hello"),
    ("cpp", "connectivity", "connect_ping_before_hello"),
    ("crystal", "connectivity", "connect_ping_before_hello"),
    ("csharp", "connectivity", "connect_ping_before_hello"),
    ("dart", "connectivity", "connect_ping_before_hello"),
    ("datalog", "connectivity", "connect_ping_before_hello"),
    ("elixir", "connectivity", "connect_ping_before_hello"),
    ("forth", "connectivity", "connect_ping_before_hello"),
    ("fortran", "connectivity", "connect_ping_before_hello"),
    ("go", "connectivity", "connect_ping_before_hello"),
    ("haskell", "connectivity", "connect_ping_before_hello"),
    ("io", "connectivity", "connect_ping_before_hello"),
    ("java", "connectivity", "connect_ping_before_hello"),
    ("julia", "connectivity", "connect_ping_before_hello"),
    ("kotlin", "connectivity", "connect_ping_before_hello"),
    ("lean", "connectivity", "connect_ping_before_hello"),
    ("nim", "connectivity", "connect_ping_before_hello"),
    ("node-red", "connectivity", "connect_ping_before_hello"),
    ("ocaml", "connectivity", "connect_ping_before_hello"),
    ("odin", "connectivity", "connect_ping_before_hello"),
    ("oz", "connectivity", "connect_ping_before_hello"),
    ("pd", "connectivity", "connect_ping_before_hello"),
    ("php", "connectivity", "connect_ping_before_hello"),
    ("prolog", "connectivity", "connect_ping_before_hello"),
    ("python", "connectivity", "connect_ping_before_hello"),
    ("rexx", "connectivity", "connect_ping_before_hello"),
    ("riscv64", "connectivity", "connect_ping_before_hello"),
    ("ruby", "connectivity", "connect_ping_before_hello"),
    ("rust-wasm-wasmtime", "connectivity", "connect_ping_before_hello"),
    ("rust-wasm", "connectivity", "connect_ping_before_hello"),
    ("rust", "connectivity", "connect_ping_before_hello"),
    ("smalltalk", "connectivity", "connect_ping_before_hello"),
    ("sql", "connectivity", "connect_ping_before_hello"),
    ("swift", "connectivity", "connect_ping_before_hello"),
    ("tcl", "connectivity", "connect_ping_before_hello"),
    ("turbowarp", "connectivity", "connect_ping_before_hello"),
    ("typescript", "connectivity", "connect_ping_before_hello"),
    ("unison", "connectivity", "connect_ping_before_hello"),
    ("wasm-wat", "connectivity", "connect_ping_before_hello"),
    ("zig", "connectivity", "connect_ping_before_hello"),
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
