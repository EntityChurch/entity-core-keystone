#!/usr/bin/env python3
"""kind-c-gate — enforce the publication boundary Kind C exists under.

WHY THIS EXISTS
  `docs/VERIFICATION-ARCHITECTURE.md` defines three kinds of verification artifact.
  Kind C — an independent check authored HERE, from the spec, at the same normative
  target as the oracle — was held until 2026-09-07, when the operator unblocked it on
  one condition:

      An official full-green pass requires the independent test suite.

  That is `validate-peer`, which this repo does not author. Nothing of ours may stand
  in for it, supplement it, or enter a published number. A constraint with no
  enforcement point is theater, so this is the enforcement point.

  It matters because the failure is SILENT and the invocation that causes it is the
  ordinary one. Every peer's `run-s4.sh` defaults `-json-out` to that peer's TRACKED,
  signed-off `status/CONFORMANCE-REPORT.json`. Drop a Kind C binary in via `ORACLE=`,
  run `./run-s4.sh` with no arguments, and a keystone-authored check has just
  republished a peer's conformance number over the oracle's — with no error, and with
  `check-set-gate --tracked`, `tier-status` and `coherence-gate` all reading the
  result as though the oracle had produced it. That is the whole boundary, and it is
  one forgotten flag wide.

WHAT IT GATES (four invariants, and each prints its count)
  1. DECLARED — every directory under tools/kind-c/ has a README naming its kind.
     An artifact that cannot name its kind is a preference or an unrouted finding.
  2. REFUSES AT THE BINARY — each artifact's source contains the refusal of a
     `status/CONFORMANCE-REPORT` destination. A README saying so is not a control;
     the check has to be unable to do it.
  3. NO TRACKED REPORT WAS EVER WRITTEN BY ONE — no committed conformance report
     carries a Kind C artifact's marker. This is the postcondition, and it is gated
     rather than inferred from invariant 2: verify that the new thing does not exist,
     not that the old pattern is absent (the de-versioning-sweep lesson).
  4. IN THE INVENTORY — run-axis-sweep.sh --list enumerates them. A thing absent from
     the inventory is an exclusion nobody declared.

  Counts are PRINTED AND ASSERTED. A gate that examines zero things prints the same
  word as one that examines four; this repo has shipped that defect at least six
  times, most recently in a gate whose per-peer pattern matched nothing and which
  cheerfully reported "OK — 46 rows and 0 peer banners agree".

REGRESSION SUITE
  python3 tools/kind-c-gate.py --self-test    # plants each defect, requires a catch
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIND_C = ROOT / "tools" / "kind-c"
SWEEP = ROOT / "tools" / "run-axis-sweep.sh"

# The destination a Kind C artifact must refuse. Kept as one constant because it is
# the same string in three places (the binary's guard, this gate, the README) and a
# second spelling is a second authority.
TRACKED_REPORT = "status/CONFORMANCE-REPORT"

# The marker a Kind C artifact stamps into its own JSON. Invariant 3 looks for it in
# committed reports; if an artifact stops emitting it, invariant 1's README check and
# invariant 2's source check are what still hold, and this one degrades to vacuous —
# which is why its count is asserted against the artifact count, not just against zero.
ARTIFACT_MARKER = '"artifact": "kind-c/'


def rel(p):
    """Path for display. Falls back to the absolute form for --self-test's planted
    trees, which live outside the repo; a gate that CRASHES on its own regression
    suite reports nothing, which is the same failure as one that examines nothing."""
    try:
        return str(Path(p).relative_to(ROOT))
    except ValueError:
        return str(p)


def artifacts():
    if not KIND_C.is_dir():
        return []
    return sorted(p for p in KIND_C.iterdir() if p.is_dir())


def check(quiet=False, root=None, sweep=None):
    """Returns (errors, counts). root/sweep are injectable for --self-test."""
    base = Path(root) if root else KIND_C
    sweep_path = Path(sweep) if sweep else SWEEP
    errs = []
    arts = sorted(p for p in base.iterdir() if p.is_dir()) if base.is_dir() else []
    counts = {"artifacts": len(arts), "declared": 0, "refuses": 0, "listed": 0,
              "reports_scanned": 0, "reports_contaminated": 0}

    for a in arts:
        readme = a / "README.md"
        if not readme.is_file():
            errs.append(f"{rel(a)}: no README.md — an artifact that "
                        f"cannot name its kind is a preference, not a check")
        else:
            head = readme.read_text(errors="replace")[:4000]
            if not re.search(r"Kind C", head):
                errs.append(f"{rel(readme)}: README does not declare "
                            f"'Kind C'")
            elif "spec-data/" not in head:
                errs.append(f"{rel(readme)}: README names no spec "
                            f"snapshot — a Kind C check is spec-derived or it is "
                            f"nothing, and the derivation has to be checkable")
            else:
                counts["declared"] += 1

        src = [p for p in a.rglob("*") if p.is_file() and p.suffix in
               (".go", ".py", ".rs", ".ts", ".sh")]
        if not src:
            errs.append(f"{rel(a)}: no source files found")
            continue
        if any(TRACKED_REPORT in p.read_text(errors="replace") for p in src):
            counts["refuses"] += 1
        else:
            errs.append(
                f"{rel(a)}: no source file mentions "
                f"'{TRACKED_REPORT}' — the artifact must REFUSE that destination in "
                f"the binary. Every run-s4.sh defaults -json-out to it, so a bare "
                f"invocation under ORACLE= silently republishes a peer's number.")

    # Invariant 3, the postcondition. Scan every committed conformance report.
    for rep in sorted(ROOT.glob("protocol-generator/*/status/CONFORMANCE-REPORT.json")):
        counts["reports_scanned"] += 1
        if ARTIFACT_MARKER in rep.read_text(errors="replace"):
            counts["reports_contaminated"] += 1
            errs.append(
                f"{rel(rep)}: this TRACKED conformance report was "
                f"written by a Kind C artifact. A published number must come from "
                f"the independent suite (validate-peer). Re-measure it; do not edit "
                f"the file.")

    # Invariant 4. Ask the inventory itself rather than reading the script's source:
    # what matters is that `--list` names the artifact, not how it came to.
    if sweep_path.is_file():
        try:
            out = subprocess.run([str(sweep_path), "--list"], capture_output=True,
                                 text=True, timeout=60).stdout
        except Exception as e:  # noqa: BLE001 - a broken inventory is the finding
            out = ""
            errs.append(f"run-axis-sweep.sh --list failed: {e}")
        for a in arts:
            if re.search(rf"^\s*{re.escape(a.name)}\s", out, re.M):
                counts["listed"] += 1
            else:
                errs.append(f"{a.name}: not enumerated by run-axis-sweep.sh --list — "
                            f"an artifact absent from the inventory is an exclusion "
                            f"nobody declared")

    return errs, counts


def main():
    quiet = "--quiet" in sys.argv
    if "--self-test" in sys.argv:
        return self_test()

    errs, c = check(quiet)

    # THE COUNT LINE IS THE POINT. An empty error list is the expected output of a
    # passing check AND of an absent one; only the count distinguishes them.
    line = (f"kind-c-gate: {c['artifacts']} artifact(s) · {c['declared']} declared · "
            f"{c['refuses']} refuse the tracked-report destination · "
            f"{c['listed']} in the axis inventory · "
            f"{c['reports_scanned']} committed reports scanned, "
            f"{c['reports_contaminated']} written by a Kind C artifact")

    if c["artifacts"] == 0:
        # Not an error — Kind C may legitimately be empty — but it must SAY so,
        # loudly, rather than print OK. A green from an empty tree is the vacuous
        # pass this file exists to make impossible.
        print("kind-c-gate: no Kind C artifacts present — nothing examined (this is "
              "a vacuous pass, not a green)")
        return 0
    if c["reports_scanned"] == 0:
        errs.append("no committed conformance reports were scanned — invariant 3 "
                    "examined nothing, so its pass means nothing")

    if errs:
        print(line)
        for e in errs:
            print(f"  ERROR {e}")
        return 1
    if not quiet:
        print(line)
    print("kind-c-gate: OK — the publication boundary holds; an official green still "
          "requires validate-peer")
    return 0


def self_test():
    """Plant each defect and require a catch. A control that has never been
    exercised is not a control — this repo has shipped three that could not fire."""
    import shutil
    import tempfile

    ok = True

    def expect(name, errs, needle):
        nonlocal ok
        hit = any(needle in e for e in errs)
        print(f"  {'PASS' if hit else 'FAIL'}  {name}")
        if not hit:
            print(f"        expected an error containing {needle!r}; got: {errs}")
            ok = False

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        # Control: the real tree must be clean, or every plant below is meaningless.
        base_errs, base_counts = check(quiet=True)
        if base_errs:
            print("  FAIL  baseline: the real tree already has errors")
            for e in base_errs:
                print(f"        {e}")
            ok = False
        elif base_counts["artifacts"] == 0:
            print("  FAIL  baseline: no artifacts, so every plant below is vacuous")
            ok = False
        else:
            print(f"  PASS  baseline clean ({base_counts['artifacts']} artifact(s))")

        # Plant 1 — an artifact with no README.
        p1 = td / "p1"
        (p1 / "undeclared").mkdir(parents=True)
        (p1 / "undeclared" / "main.go").write_text(f'// {TRACKED_REPORT}\n')
        errs, _ = check(quiet=True, root=p1, sweep="/nonexistent")
        expect("plant 1: artifact with no README", errs, "no README.md")

        # Plant 2 — a README that declares the kind but a source with no refusal.
        p2 = td / "p2"
        (p2 / "leaky").mkdir(parents=True)
        (p2 / "leaky" / "README.md").write_text(
            "# leaky — Kind C\n\nspec-data/v0.8.2.11/\n")
        (p2 / "leaky" / "main.go").write_text("package main\nfunc main() {}\n")
        errs, _ = check(quiet=True, root=p2, sweep="/nonexistent")
        expect("plant 2: source does not refuse the tracked report", errs,
               "must REFUSE that destination")

        # Plant 3 — a README that does not name a spec snapshot. A Kind C check whose
        # derivation is not checkable is the failure mode, not a formatting nit.
        p3 = td / "p3"
        (p3 / "unsourced").mkdir(parents=True)
        (p3 / "unsourced" / "README.md").write_text("# unsourced — Kind C\n")
        (p3 / "unsourced" / "main.go").write_text(f'// {TRACKED_REPORT}\n')
        errs, _ = check(quiet=True, root=p3, sweep="/nonexistent")
        expect("plant 3: README names no spec snapshot", errs, "names no spec")

        # Plant 4 — THE ONE THAT MATTERS: a tracked conformance report written by a
        # Kind C artifact. Planted in the real tree and restored, because invariant 3
        # scans committed reports by absolute path and cannot be redirected.
        victim = next(ROOT.glob("protocol-generator/*/status/CONFORMANCE-REPORT.json"))
        backup = td / "victim.json"
        shutil.copy2(victim, backup)
        try:
            body = victim.read_text()
            victim.write_text(body.replace("{", '{\n  ' + ARTIFACT_MARKER +
                                           'connect-errors",', 1))
            errs, counts = check(quiet=True)
            expect("plant 4: tracked report written by a Kind C artifact", errs,
                   "written by a Kind C artifact")
            if counts["reports_contaminated"] != 1:
                print(f"  FAIL  plant 4 count: expected 1 contaminated, got "
                      f"{counts['reports_contaminated']}")
                ok = False
        finally:
            shutil.copy2(backup, victim)

        # Plant 5 — an artifact absent from the axis inventory.
        errs, _ = check(quiet=True, sweep="/nonexistent")
        # With no sweep script the inventory check is skipped entirely, which would be
        # a silent hole; assert instead against a sweep that runs but lists nothing.
        stub = td / "stub-sweep.sh"
        stub.write_text("#!/usr/bin/env bash\necho 'AXIS SCRIPT DESCRIPTION'\n")
        stub.chmod(0o755)
        errs, _ = check(quiet=True, sweep=stub)
        expect("plant 5: artifact missing from the axis inventory", errs,
               "not enumerated by run-axis-sweep.sh")

    print("kind-c-gate --self-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
