#!/usr/bin/env python3
"""Gate the keystone specification layer: the pin matches, and the contract is self-consistent.

WHAT THIS ANSWERS THAT NO OTHER GATE DOES. `pin-gate.py` watches the ORACLE anchors --
the conformance pin and the digests §1 publishes. This document is a different artifact
with the same failure mode: a consumer (`entity-system-generator`) builds probes against
`H1...H9 @ <digest>`, so a normative body that moves without its digest moving is a
consumer silently measuring against text nobody published.

THREE CHECKS, and each exists because of a defect this repo has actually shipped:

  1. THE DIGEST MATCHES THE FILE. The whole point of a content anchor. A hand-copied
     64-hex digest drifting from its source is strictly worse than a wrong commit hash,
     because nobody proofreads 64 hex characters and a bad commit at least fails loudly
     when someone tries to resolve it.

  2. EVERY DECLARED REQUIREMENT HAS A SECTION, AND EVERY SECTION IS DECLARED. The
     append-only rule is only meaningful if the pin's H-list and the document cannot
     drift. A requirement present in the prose and absent from the pin is one a consumer
     cannot discover; the reverse is a pin promising text that is not there.

  3. EVERY REQUIREMENT CARRIES A NORMATIVE STATEMENT AND AN ENFORCEMENT ROW. Repo law:
     a discipline with no enforcement point is theater. Applied to the document that
     makes the rules, this is the check that stops it becoming a wish list.

DELIBERATELY NOT CHECKED: whether the peers SATISFY any of it. That is a measurement,
it belongs to the host-seam harness, and a gate that conflated "the contract is
well-formed" with "the cohort conforms" would be the `oracle-bootstrap` HAVE/WANT defect
again -- an equality test whose two operands come from the same source.

Usage:  tools/keystone-spec-gate.py [--quiet]
        tools/keystone-spec-gate.py --self-test    # plants defects, asserts each is caught
"""

import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
PIN = REPO / "tools" / "keystone-spec-pin.env"


def read_pin(pin_path):
    fields = {}
    for line in pin_path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip()
    return fields


def check(pin_path=PIN, repo=REPO):
    """Return (errors, facts). Never raises on a malformed tree -- it reports."""
    errors, facts = [], {}
    pin = read_pin(pin_path)

    rel = pin.get("keystone_peer_path")
    digest = pin.get("keystone_peer_digest")
    declared = pin.get("keystone_peer_requirements", "").split()
    if not rel or not digest:
        return ["pin is missing keystone_peer_path or keystone_peer_digest"], facts

    doc = repo / rel
    if not doc.is_file():
        return [f"declared spec does not exist: {rel}"], facts

    raw = doc.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    facts["digest"] = actual
    if actual != digest:
        errors.append(
            f"DIGEST DRIFT — {rel}\n"
            f"    pinned : {digest}\n"
            f"    actual : {actual}\n"
            "    The normative body moved without its pin. Either restore the text, or move\n"
            "    the version, record the old digest as retired_*, and re-pin -- an H-number is\n"
            "    append-only and a measured requirement is never edited in place."
        )

    text = raw.decode("utf-8", errors="replace")

    # A requirement section: "## H<n> — <title>"
    present = re.findall(r"^##\s+(H\d+)\s+—", text, re.MULTILINE)
    facts["sections"] = present
    facts["declared"] = declared

    if not declared:
        errors.append("pin declares no requirements — keystone_peer_requirements is empty")

    missing = [h for h in declared if h not in present]
    extra = [h for h in present if h not in declared]
    if missing:
        errors.append(
            f"declared in the pin but absent from the document: {', '.join(missing)}\n"
            "    A consumer citing the pin cannot discover a requirement that has no section."
        )
    if extra:
        errors.append(
            f"present in the document but not declared in the pin: {', '.join(extra)}\n"
            "    Add it to keystone_peer_requirements and move the version + digest."
        )

    # Each section must carry a normative statement, and appear in the enforcement table.
    bodies = re.split(r"^##\s+(?=H\d+\s+—)", text, flags=re.MULTILINE)
    enforcement = text.split("## Enforcement", 1)
    enforced = set()
    if len(enforcement) == 2:
        enforced = set(re.findall(r"\*\*(H\d+)\*\*", enforcement[1]))
    facts["enforced"] = sorted(enforced, key=lambda h: int(h[1:]))

    for body in bodies:
        m = re.match(r"(H\d+)\s+—", body)
        if not m:
            continue
        h = m.group(1)
        if "**Normative.**" not in body and "**Normative " not in body:
            errors.append(f"{h} has no **Normative.** statement — it is commentary, not a requirement")
        if h not in enforced:
            errors.append(
                f"{h} has no row in the Enforcement table — "
                "a requirement with no enforcement point is theater"
            )

    return errors, facts


def self_test():
    """Plant each defect the gate exists to catch; assert the gate catches it.

    A regression suite nobody runs is not a regression suite, and a gate is where that is
    least visible because the gate keeps passing. Every plant is asserted PRESENT before
    the mutated case runs -- a mutation that silently fails to apply produces a confident
    green, which this repo has shipped twice.
    """
    errs, facts = check()
    if errs:
        print("self-test: the CLEAN tree must pass first, and it does not:", file=sys.stderr)
        for e in errs:
            print("  " + e, file=sys.stderr)
        return 1

    doc_rel = read_pin(PIN)["keystone_peer_path"]
    original_doc = (REPO / doc_rel).read_text(encoding="utf-8")
    original_pin = PIN.read_text(encoding="utf-8")
    n_declared = len(facts["declared"])

    cases = []

    # 1. body edited without re-pinning
    cases.append(("digest drift", original_doc + "\nAn edit nobody re-pinned.\n", original_pin,
                  "DIGEST DRIFT"))

    # 2. a requirement declared in the pin with no section in the document
    cases.append(("undeclared-in-doc", original_doc,
                  original_pin.replace(
                      "keystone_peer_requirements = H1 H2 H3 H4 H5 H6 H7 H8 H9",
                      "keystone_peer_requirements = H1 H2 H3 H4 H5 H6 H7 H8 H9 H99"),
                  "absent from the document"))

    # 3. a requirement whose enforcement row is gone
    stripped = original_doc.replace(
        "| **H9** | one accept plus one deny per scope dimension | executed |\n", "")
    cases.append(("enforcement row removed", stripped, original_pin, "no row in the Enforcement"))

    # 4. a requirement demoted to commentary
    demoted = original_doc.replace(
        "**Normative.** A keystone peer MUST expose a public predicate",
        "A keystone peer might expose a public predicate")
    cases.append(("normative statement removed", demoted, original_pin, "no **Normative.**"))

    failures = 0
    for name, doc_text, pin_text, expect in cases:
        if name != "undeclared-in-doc" and doc_text == original_doc:
            print(f"self-test: PLANT DID NOT APPLY ({name}) — the anchor moved", file=sys.stderr)
            failures += 1
            continue
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            target = tmp / doc_rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(doc_text, encoding="utf-8")
            # keep the pin's recorded digest honest for the non-digest plants
            if name != "digest drift":
                pin_text = re.sub(
                    r"keystone_peer_digest  = [0-9a-f]{64}",
                    "keystone_peer_digest  = "
                    + hashlib.sha256(doc_text.encode("utf-8")).hexdigest(),
                    pin_text,
                )
            pin_file = tmp / "tools" / "keystone-spec-pin.env"
            pin_file.parent.mkdir(parents=True, exist_ok=True)
            pin_file.write_text(pin_text, encoding="utf-8")
            errs, _ = check(pin_path=pin_file, repo=tmp)
            if any(expect in e for e in errs):
                print(f"  ok   plant caught: {name}")
            else:
                print(f"  FAIL plant NOT caught: {name} (expected {expect!r})", file=sys.stderr)
                for e in errs:
                    print("        got: " + e.splitlines()[0], file=sys.stderr)
                failures += 1

    # vacuity control: a gate that examined zero requirements prints the same word as one
    # that examined nine.
    if n_declared < 9:
        print(f"  FAIL vacuity: only {n_declared} requirement(s) declared", file=sys.stderr)
        failures += 1
    else:
        print(f"  ok   vacuity control: {n_declared} requirements examined, not zero")

    print("keystone-spec-gate --self-test:", "OK" if not failures else f"{failures} FAILED")
    return 1 if failures else 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    quiet = "--quiet" in sys.argv
    errors, facts = check()
    if errors:
        print("keystone-spec-gate: FAIL", file=sys.stderr)
        for e in errors:
            print("  " + e, file=sys.stderr)
        return 1
    if not quiet:
        pin = read_pin(PIN)
        print(
            f"keystone-spec-gate: OK — {len(facts['declared'])} requirements "
            f"({' '.join(facts['declared'])}) at v{pin.get('keystone_peer_version')} "
            f"@ {facts['digest'][:8]}…, all with a normative statement and an enforcement row"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
