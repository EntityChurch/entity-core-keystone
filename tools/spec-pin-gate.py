#!/usr/bin/env python3
"""spec-pin-gate — the per-peer SPEC pin is declared, machine-readable, and reconciled.

WHY THIS GATE EXISTS
  `CONFORMANCE-MATRIX.md` §1's `Spec` column published `v0.8.0` on all 46 rows while the
  cohort sat at `0.8.2.25`, and nothing objected: the column was HAND-MAINTAINED and no gate
  watched it. It was corrected on 2026-09-16 with a footnote ending "a value that is correct
  today and ungated is a value that is correct today" — and it was FALSE ON TWO ROWS THE SAME
  DAY, because `fortran` and `unison` had never been swept at all and the column published
  them at `0.8.2.25` regardless.

  So there are two separate defects and this gate answers both:
    (1) a per-peer fact kept only as prose drifts, and
    (2) a sweep run TRANCHE-BY-TRANCHE cannot see a peer that no tranche touched — every
        tranche reports honestly about its own peers and none ranges over the roster.

  `tools/peer-tiers.tsv` gains a `spec_pin` column: the spec revision each peer was last
  SWEPT to, written by the sweep that moves the peer, with an explicit `unknown` token and
  never an empty cell. Requested in exactly this shape by `entity-system-conformance`
  (`ROUTING-2026-09-16-a-entity-core-keystone-the-per-peer-spec-pin-is-a-column-in-the-roster-…`
  §1), whose census consumes it; named as owed by our own matrix footnote 12 the same day.

WHY `unknown` MUST BE SPELLABLE, AND AN EMPTY CELL IS AN ERROR
  Conformance's §4, and it is the argument: an empty cell reads as "not applicable" to one
  reader and "nobody has established this" to another, and those are different claims. An
  explicit `unknown` costs one token and makes the gap countable. This gate refuses a blank.

WHY NOT `profile.toml`
  Every peer already has a `[spec]` table with `v7_version_pinned`, and conformance measured
  it before answering: present on 24 of 46, spanning five distinct v7-era values plus three
  peers carrying the free-text `"v0.8.0 / V8"`, and 0 of 46 mention `0.8.2`. A STALE field is
  worse than an absent one — it parses, it is plausible, and it answers with confidence, so
  nothing in the path goes red. That is the argument for a column with a WRITER and a GATE
  rather than a second value in a table nobody is obliged to update.

WHAT IT CHECKS
  1. COMPLETE + WELL-FORMED. Every roster row declares a `spec_pin`; each is a revision token
     (`0.8.2.25`) or the literal `unknown`. Blank is an ERROR.
  2. COHERENT WITH WHAT WE PUBLISH. Every §1 row's `Spec` cell equals that peer's roster
     `spec_pin`. Two hand-maintained copies of one fact drift; this is the only thing that
     can see it. Fails.
  3. BEHIND THE COHORT. Peers whose pin is not the newest declared revision are REPORTED with
     a count, not failed — a gate held permanently red by disclosed backlog gets ignored,
     which is worse than no gate (written down three times in AGENTS.md before this file).

  `--since <ref>`  THE SWEEP RECONCILIATION, and it is the check that would have caught the
     two unswept peers. It is a SET DIFFERENCE, not a measurement:
       (a) peer's source changed in the range, `spec_pin` row did NOT  -> the sweep moved the
           peer and failed to record it. Unambiguous; ERROR.
       (b) `spec_pin` advanced in the range, peer's source did NOT     -> "recorded but not
           swept". This is the `fortran`/`unison` shape.
     (b) is NOT automatically a defect: the 0.8.2.25 sweep had rules that several peers
     satisfied BY CONSTRUCTION, and a peer measured-and-needing-nothing is a real outcome.
     It is an ERROR *unless acknowledged* with `--ack-unchanged <peer>[,<peer>…]`, which
     forces the claim to be made out loud by whoever closes the sweep instead of being the
     silent default. That is the whole point: the claim "we measured it and it needed
     nothing" is fine, and it must be SAID.

USAGE
    python3 tools/spec-pin-gate.py [--quiet]
    python3 tools/spec-pin-gate.py --since <ref> [--ack-unchanged a,b]
    python3 tools/spec-pin-gate.py --self-test
"""

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROSTER = REPO / "tools" / "peer-tiers.tsv"
MATRIX = REPO / "CONFORMANCE-MATRIX.md"

UNKNOWN = "unknown"
# A spec revision as the ecosystem spells it: 0.8.2 / 0.8.2.25. Deliberately NOT accepting a
# leading `v`: the matrix published `v0.8.0` for months and the bare form is what the
# snapshot directories and every routing packet use.
REVISION = re.compile(r"^\d+\.\d+(?:\.\d+){0,2}$")

# Display names in §1 that do not normalize to their directory. Kept in step with
# tools/coherence-gate.py's copy by hand; both are three entries and a rename would break
# check 2 loudly rather than silently, which is the acceptable direction.
ALIASES = {"c#": "csharp", "c++": "cpp", "oz / mozart": "oz", "pure data": "pd"}

ROW = re.compile(r"^\|\s*\*\*([^*]+)\*\*[^|]*\|")
PWFS = re.compile(r"\d{3}P/\d{2,3}W/\d+F/\d{3}S")

# Commit subjects that constitute a cohort sweep. Override with --sweep-grep. This is the
# convention this repo already writes ("sweep tranche 9g: …", "vanguard: go and python to
# 0.8.2.25, …") and a proxy is all a commit graph can offer — see swept_peers().
SWEEP_SUBJECT = r"^(sweep tranche|vanguard)"


def peer_dir(display):
    key = display.strip().lower()
    return ALIASES.get(key, key.replace(" ", "-"))


def read_roster(text=None):
    """[(lineno, peer, spec_pin)] — blanks preserved so check 1 can see them.

    The column is located BY HEADER NAME, never by index. `spec_pin` was inserted at index 3
    on 2026-09-16 and moved `note` from 3 to 4; `--since <ref>` reads the roster as it stood
    at an arbitrary older commit, where index 3 is the note. A positional read would have
    scored every peer's note as its pin and reported the whole cohort as moved — the
    five-parsers-one-file defect this repo ratified the day before, inside the gate written
    to answer it. A roster with no `spec_pin` header yields "" for every peer, which is the
    honest answer: that revision declared none.
    """
    src = text if text is not None else ROSTER.read_text(encoding="utf-8")
    idx = None
    out = []
    for n, line in enumerate(src.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split("\t")
        if f[0] == "peer":
            idx = f.index("spec_pin") if "spec_pin" in f else None
            continue
        out.append((n, f[0], f[idx] if idx is not None and len(f) > idx else ""))
    return out


def matrix_specs(text=None):
    """peer -> (lineno, spec cell). A §1 row is a bolded name plus a P/W/F/S."""
    src = text if text is not None else MATRIX.read_text(encoding="utf-8")
    out = {}
    for n, line in enumerate(src.splitlines(), 1):
        if line.lstrip().startswith(">"):
            continue  # a dated `>` note block is history, not a live claim
        if not line.startswith("| **") or not PWFS.search(line):
            continue
        m = ROW.match(line)
        if not m:
            continue
        cells = [c.strip() for c in line.split("|")]
        if len(cells) < 4:
            continue
        # Strip a trailing footnote marker (` 13`, superscript) and the backticks.
        cell = re.sub(r"[^\x00-\x7f].*$", "", cells[3]).strip().strip("`").strip()
        out[peer_dir(m.group(1))] = (n, cell)
    return out


def newest(pins):
    """The highest revision present, as a sort key over integer components."""
    vals = [p for p in pins if REVISION.match(p)]
    if not vals:
        return None
    return max(vals, key=lambda v: tuple(int(x) for x in v.split(".")))


def check(roster, specs):
    """Checks 1-3. Returns (errors, reports, n_examined)."""
    errors, reports = [], []

    for lineno, peer, pin in roster:
        if not pin:
            errors.append(
                f"tools/peer-tiers.tsv:{lineno}  {peer}: spec_pin is EMPTY. Write the "
                f"revision or the literal '{UNKNOWN}' — a blank is two different claims."
            )
        elif pin != UNKNOWN and not REVISION.match(pin):
            errors.append(
                f"tools/peer-tiers.tsv:{lineno}  {peer}: spec_pin {pin!r} is neither a "
                f"revision (0.8.2.25) nor '{UNKNOWN}'."
            )

    declared = {p: v for _, p, v in roster}
    for peer, (lineno, cell) in sorted(specs.items()):
        if peer not in declared:
            errors.append(
                f"CONFORMANCE-MATRIX.md:{lineno}  §1 row '{peer}' is not on the roster "
                f"(tools/peer-tiers.tsv). Add it — do not skip the row."
            )
            continue
        if cell != declared[peer]:
            errors.append(
                f"CONFORMANCE-MATRIX.md:{lineno}  {peer}: §1 Spec publishes {cell!r}, the "
                f"roster declares {declared[peer]!r}. Two copies of one fact have drifted."
            )
    for _, peer, _ in roster:
        if peer not in specs:
            errors.append(
                f"tools/peer-tiers.tsv  {peer}: on the roster with no §1 row carrying a "
                f"P/W/F/S. A peer that publishes no number cannot have its pin checked."
            )

    top = newest(declared.values())
    if top:
        behind = sorted(p for p, v in declared.items() if v != top)
        for p in behind:
            reports.append(f"  {p}: {declared[p]}  (cohort is at {top})")
    return errors, reports, len(roster)


def _git(*args):
    r = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        sys.exit(2)
    return r.stdout


def swept_peers(ref, pattern):
    """Peers whose directory the SWEEP'S OWN COMMITS touched, between <ref> and HEAD.

    SCOPING IS THE WHOLE CHECK, and the obvious scoping is wrong. A plain `<ref>..HEAD`
    diff reports all 46 peers as touched, because the range also contains the closing
    re-measurement (which rewrites every peer's committed report) and the previous
    revision's transcription. Measured: `--since b71b940f~1` over the raw range says 46 of
    46 and the truth is 44. The commits that constitute the sweep are selected by SUBJECT.

    That is a convention-keyed proxy and it is stated as one rather than dressed up: it
    answers "did a sweep commit touch this peer", never "was this peer measured". A sweep
    can legitimately produce no diff for a peer that already satisfied the rule — which is
    why the answer is reconciled against the recorded pin and acknowledged out loud, rather
    than being trusted on its own.
    """
    peers = set()
    for line in _git("log", "--format=%H %s", f"{ref}..HEAD").splitlines():
        sha, _, subject = line.partition(" ")
        if not re.search(pattern, subject, re.I):
            continue
        for p in _git("show", "--name-only", "--format=", sha, "--", "protocol-generator").splitlines():
            parts = p.split("/")
            if len(parts) > 2 and parts[1] != "shared":
                peers.add(parts[1])
    return peers


def reconcile_sets(before, after, touched, ack, ref="<ref>"):
    """The pure set difference behind --since, so the self-test can drive it without git."""
    errors = []
    moved = {p for p in after if before.get(p) != after[p]}

    for p in sorted(touched & set(after)):
        if p not in moved:
            errors.append(
                f"  {p}: a sweep commit touched protocol-generator/{p}/ since {ref} and "
                f"spec_pin did not move (still {after[p]!r}). The sweep moved this peer "
                f"and did not record it."
            )
    for p in sorted(moved - touched):
        if p in ack:
            continue
        errors.append(
            f"  {p}: spec_pin advanced to {after[p]!r} since {ref} but NO sweep commit "
            f"touched protocol-generator/{p}/. Either it was never swept — the "
            f"fortran/unison shape — or it was measured and needed nothing. Say which "
            f"with --ack-unchanged {p}."
        )
    return errors


def reconcile(ref, ack, pattern):
    """--since. Returns (errors, rows_reconciled)."""
    touched = swept_peers(ref, pattern)
    before = {p: v for _, p, v in read_roster(_git("show", f"{ref}:tools/peer-tiers.tsv"))}
    after = {p: v for _, p, v in read_roster()}
    return reconcile_sets(before, after, touched, ack, ref), len(after)


def run(quiet=False):
    roster = read_roster()
    specs = matrix_specs()
    errors, reports, n = check(roster, specs)

    if errors:
        print("spec-pin-gate: FAIL")
        for e in errors:
            print(f"  {e}")
        return 1
    if not quiet or reports:
        # Print the COUNT, always. A gate that examined zero things prints the same word
        # as one that examined forty-six.
        print(f"spec-pin-gate: {n} roster row(s) examined, {len(specs)} matrix row(s) matched")
        if reports:
            print(f"  REPORT — {len(reports)} peer(s) behind the cohort spec pin (tracked "
                  f"backlog, not a failure):")
            for r in reports:
                print(r)
        print("PASS — every peer declares a spec pin and the matrix agrees with the roster.")
    return 0


def self_test():
    """Plant each defect this gate exists to catch and require it to be caught."""
    roster_src = ROSTER.read_text(encoding="utf-8")
    matrix_src = MATRIX.read_text(encoding="utf-8")
    ok = True

    def expect(name, errs, want):
        nonlocal ok
        got = bool(errs)
        flag = "ok " if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{flag}] {name}: errors={len(errs)} (wanted {'some' if want else 'none'})")

    base_roster = read_roster(roster_src)
    base_specs = matrix_specs(matrix_src)
    errs, _, n = check(base_roster, base_specs)
    expect("clean tree", errs, False)
    # The examined-zero-things control: assert the population, not just the emptiness.
    if n != len(base_specs) or n == 0:
        ok = False
        print(f"  [FAIL] clean tree examined {n} roster rows vs {len(base_specs)} matrix rows")
    else:
        print(f"  [ok ] population: {n} roster rows == {len(base_specs)} matrix rows")

    # Plant 1 — a blank cell. The defect the `unknown` rule exists for.
    blanked = re.sub(r"^(go\tM1\t[^\t]+)\t[^\t]+\t", r"\1\t\t", roster_src, count=1, flags=re.M)
    assert blanked != roster_src, "plant 1 did not apply"
    errs, _, _ = check(read_roster(blanked), base_specs)
    expect("plant: blank spec_pin", errs, True)

    # Plant 2 — a malformed token.
    bad = re.sub(r"^(go\tM1\t[^\t]+)\t[^\t]+\t", r"\1\tv0.8.0-ish\t", roster_src, count=1, flags=re.M)
    assert bad != roster_src, "plant 2 did not apply"
    errs, _, _ = check(read_roster(bad), base_specs)
    expect("plant: malformed spec_pin", errs, True)

    # Plant 3 — the matrix drifts from the roster. This is the live defect: the column was
    # hand-maintained and published a value the tree did not support.
    drifted = dict(base_specs)
    victim = sorted(drifted)[0]
    drifted[victim] = (drifted[victim][0], "0.0.0")
    errs, _, _ = check(base_roster, drifted)
    expect("plant: matrix Spec drifts from roster", errs, True)

    # Plant 4 — a roster peer with no §1 row. A peer that publishes no number is unchecked.
    thin = {k: v for k, v in base_specs.items() if k != victim}
    errs, _, _ = check(base_roster, thin)
    expect("plant: roster peer missing from the matrix", errs, True)

    # --- the --since set difference, driven directly ------------------------------------
    # Three peers: `a` swept and recorded, `b` swept and NOT recorded, `c` recorded with no
    # sweep commit (the fortran/unison shape). Each arm must fire on its own.
    before = {"a": "0.8.2.21", "b": "0.8.2.21", "c": "0.8.2.21"}
    after = {"a": "0.8.2.25", "b": "0.8.2.21", "c": "0.8.2.25"}

    expect("since: all swept and recorded",
           reconcile_sets(before, {"a": "0.8.2.25"}, {"a"}, set()), False)
    errs = reconcile_sets(before, after, {"a", "b"}, set())
    expect("since: swept but pin not recorded (b)", [e for e in errs if " b:" in e], True)
    expect("since: recorded but never swept (c)", [e for e in errs if " c:" in e], True)
    expect("since: --ack-unchanged silences the never-swept arm",
           reconcile_sets(before, {"c": "0.8.2.25"}, set(), {"c"}), False)
    # A control for the control: the ack must NOT silence the other direction.
    expect("since: --ack-unchanged does not silence the unrecorded arm",
           reconcile_sets(before, {"b": "0.8.2.21"}, {"b"}, {"b"}), True)

    print("spec-pin-gate --self-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main():
    argv = sys.argv[1:]
    if "--self-test" in argv:
        return self_test()
    if "--since" in argv:
        ref = argv[argv.index("--since") + 1]
        ack = set()
        if "--ack-unchanged" in argv:
            ack = {s.strip() for s in argv[argv.index("--ack-unchanged") + 1].split(",") if s.strip()}
        pattern = SWEEP_SUBJECT
        if "--sweep-grep" in argv:
            pattern = argv[argv.index("--sweep-grep") + 1]
        errs, n = reconcile(ref, ack, pattern)
        if errs:
            print(f"spec-pin-gate --since {ref}: FAIL  ({n} roster row(s) reconciled)")
            for e in errs:
                print(e)
            return 1
        print(f"spec-pin-gate --since {ref}: {n} roster row(s) reconciled")
        print("PASS — every peer the sweep touched recorded its pin, and every pin that "
              "moved is backed by a tree change or an explicit acknowledgement.")
        return 0
    return run(quiet="--quiet" in argv)


if __name__ == "__main__":
    sys.exit(main())
