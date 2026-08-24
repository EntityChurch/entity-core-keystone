#!/usr/bin/env python3
"""RT-6 (§4.6 replayed authenticate) six-class census — consumes measured
validate-peer JSON reports and classifies every peer by details.rt6_class on
the connectivity/handshake_nonce_single_use check, per entity-core-go `fceb61f`
(cmd/internal/validate/connectivity_f12.go).

Companion to f40-scope-typing-differential.py's attribution mode — same idea,
applied to RT-6's ladder instead of F40's A/B rows. Retires the af8a582 handoff's
hand-built §6 roll-up table (research/stewardship/HANDOFF-TO-ARCH-2026-07-27-
af8a582-cohort-remeasurement.md §2/§6), which was accurate for that oracle build
but is now superseded by the six-class ladder.

The six classes (severity, rt6_class detail — see oracle-pin.env's 2026-07-28
entry for the full explanation of each):
  1. PASS                                         — 401 invalid_nonce (conformant)
  2. WARN (no rt6_class)                          — 401, a different code (gate-green, not RT-6-conformant)
  3. FAIL rt6_class=replay-accepted, status 2xx   — the replay was genuinely honoured (security)
  4. FAIL rt6_class=replay-accepted, status 0     — post-delivery close, no response (no positive proof
                                                     of acceptance OR rejection — see the caveat below)
  5. FAIL rt6_class=wrong-status                  — a non-401 rejection, e.g. 409 (wrong-but-safe)
  6. WARN (pre-delivery write-fail)                — the replay never reached the peer (unattributable)

Class 3 and class 4 currently share the SAME rt6_class label
("replay-accepted") in the fceb61f oracle build, which is the one item arch's
ruling (2026-07-28, verbal) flags as still needing a rename upstream: a
post-delivery silent close does not *prove* acceptance the way a 2xx does, and
should carry its own label (`no-rejection-proof`) once entity-core-go's rename
lands. Until then, THIS SCRIPT distinguishes them itself from `details.status`
(0/absent => close => provisionally class 4; 2xx => class 3) rather than
trusting the shared label — see `classify()`.

Usage:
    python3 research/diagnostics/rt6-class-census.py <reports_dir>
"""
import json
import pathlib
import sys

CLASS_LABELS = {
    "pass": "1-pass (401 invalid_nonce)",
    "warn-wrong-code": "2-warn (401, other code)",
    "replay-accepted": "3-FAIL replay-accepted (2xx, genuine accept)",
    "no-rejection-proof": "4-FAIL no-rejection-proof (post-delivery close, no response)",
    "wrong-status": "5-FAIL wrong-status (non-401 rejection, e.g. 409)",
    "warn-unattributable": "6-warn (pre-delivery write-fail, replay never delivered)",
    "not-measured": "not-measured (check absent/SKIP)",
    "replay-accepted-unparsed": "UNEXPECTED shape under rt6_class=replay-accepted (investigate)",
    "unclassified-fail": "UNEXPECTED FAIL with no rt6_class (pre-fceb61f oracle report?)",
}


def classify(check):
    sev = check.get("severity")
    details = check.get("details") or {}
    rt6_class = details.get("rt6_class")
    message = check.get("message", "")

    if sev == "PASS":
        return "pass"
    if sev == "WARN":
        # Two WARN shapes share severity: the pre-delivery write-fail (message
        # says "replay write failed") vs. 401-with-a-different-code. No
        # details.rt6_class on either in the fceb61f build; disambiguate on message.
        if "write failed" in message or "unattributable" in message:
            return "warn-unattributable"
        return "warn-wrong-code"
    if sev == "FAIL":
        if rt6_class == "wrong-status":
            return "wrong-status"
        if rt6_class == "replay-accepted":
            # Disambiguate the shared label ourselves (see module docstring).
            # `details` carries only the string "rt6_class" in the fceb61f
            # build — no structured status field — so the two messages this
            # branch can produce are told apart by their own fixed wording
            # (cmd/internal/validate/connectivity_f12.go): a genuine 2xx
            # accept says "ACCEPTED (status N)"; a post-delivery close says
            # "CLOSE emitting nothing".
            if "CLOSE emitting nothing" in message:
                return "no-rejection-proof"
            if "ACCEPTED (status" in message:
                return "replay-accepted"
            return "replay-accepted-unparsed"  # shouldn't happen; surfaced rather than guessed
        # FAIL with no rt6_class at all: pre-fceb61f oracle report, or a shape
        # this script doesn't yet recognize — surface rather than guess.
        return "unclassified-fail"
    return "not-measured"


def census(reports_dir):
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
        except Exception as e:  # noqa: BLE001
            rows.append((peer, "error", str(e)))
            continue
        checks = report.get("checks", [])
        check = next((c for c in checks if c.get("name") == "handshake_nonce_single_use"), None)
        if check is None:
            rows.append((peer, "not-measured", "handshake_nonce_single_use absent"))
            continue
        cls = classify(check)
        rows.append((peer, cls, check.get("message", "")[:90]))

    print(f"{'peer':<22} {'class':<45} detail")
    print("-" * 130)
    tally = {}
    for peer, cls, detail in rows:
        tally[cls] = tally.get(cls, 0) + 1
        label = CLASS_LABELS.get(cls, cls)
        print(f"{peer:<22} {label:<45} {detail}")

    print()
    print(f"TOTAL: {len(rows)} peers")
    for k in sorted(tally, key=lambda k: CLASS_LABELS.get(k, k)):
        print(f"  {CLASS_LABELS.get(k, k):<45} {tally[k]}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    sys.exit(census(sys.argv[1]))
