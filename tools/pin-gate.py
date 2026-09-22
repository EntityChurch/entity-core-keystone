#!/usr/bin/env python3
"""pin-gate — is every PUBLISHED conformance number anchored by content, and is
that anchor the one `tools/oracle-pin.env` actually holds?

Run by `make lint`. Read-only, stdlib only, no container.

WHY THIS EXISTS
---------------
[ADR-0027] authors every published commit fresh at the release boundary, so public
`master` is a different history from `dev` — not a rewrite, just two lines that were
never the same line. A `dev` SHA has therefore never resolved for an outside reader
and never will. Measured 2026-08-23: `entity-core-go` public master HEAD is `cc1970f`
and its dev is 514 commits past it, so the oracle this cohort was measured on exists
on no public branch under any name.

This repo already had the durable answer and had had it since 2026-07-10, when go's
mirror rewrote history and killed the pinned `e8524ed`: identify the gate by a digest
of its own content. `oracle-pin.env` carried the proof in one line —
`retired_ref_4 = e8524ed (unreproducible after mirror history rewrite; same
fingerprint)`. The commit died; the fingerprint carried the verdict across its death.
What never happened is that the practice reached the published documents, which kept
leading with the SHA for six more weeks.

So the failure mode this gate exists for is NOT "someone writes a commit hash." It is
the two ways the content anchor stops being trustworthy:

  (A) DRIFT — the matrix publishes a digest that `oracle-pin.env` no longer holds.
      A digest is 64 hex characters that no human proofreads. Hand-copied into prose
      45 times, a wrong one is invisible and is strictly worse than a wrong commit
      hash, because a commit hash at least fails loudly when someone tries to resolve
      it. Every anchor-shaped token in a published doc must match a value this repo
      actually recorded.

  (B) REGRESSION — the §1 pin column goes back to carrying a commit. That column is
      the per-row anchor for 45 published numbers; it is the single highest-value
      place for the old habit to return, and the return would look completely normal.

WHAT IT CHECKS
  1. The §1 table's pin column header says "Oracle pin", not "Oracle commit".
  2. Every cell in that column is a content digest, never a git SHA.
  3. Every anchor-shaped token (>=8 hex followed by U+2026) in the published docs
     resolves to a value recorded in `tools/oracle-pin.env` or a pinned MANIFEST.
  3b. README.md and CHANGELOG.md — the two front-door documents — carry no bare git
     short-SHA at all. Scanned over the whole text rather than per line, because a
     backtick span can WRAP a line: `@ c1b0708` survived in README.md until
     2026-08-23 precisely because its span opened on the previous line and a
     per-line regex could not see it. A false negative in a gate is worse than a
     false positive, and this one hid the number on the front page.
  4. The anchors the matrix publishes for the CURRENT pin are the current values.
  5. `guide_conformance` matches the sibling's GUIDE-CONFORMANCE.md, when the sibling
     is on disk. That line sat in `oracle-pin.env` with NOTHING READING IT, and the
     cost was a cohort-wide drift rather than untidiness: peers derive their entire
     §7a conformance scaffolding from that guide, and when `0.8.2.19` made the
     `reentry_*` carriers PLURAL, 40 of 46 peers silently stayed singular. The
     spec-data snapshots are digest-verified by `make lint`; the guide is
     deliberately not in spec-data (non-normative, arch-owned); so the one input that
     moved was the one input with no gate. Measured 2026-09-16: 17 guide commits since
     the recorded pin, including the plural carriers, a narrow-scaffold-grant
     requirement, and a new `deadline_ms` MUST that 0 of 46 peers implement.
     ⭐ THE DIGEST IS A *READ* MARKER, NOT A CONFORMANCE CLAIM — exactly the
     vendored-versus-consumed split the spec-data snapshots already use. Advancing it
     asserts "this revision has been read and its obligations enumerated," never
     "implemented"; the implementation debt is tracked in the arch tracker and the
     per-peer `spec_pin` column. So the gate fires on an UNREAD revision, which is the
     state that costs, and does not hold itself red against tracked backlog — a gate
     that is permanently red teaches people to skip it.

WHAT IT DELIBERATELY DOES NOT CHECK
  Commit hashes in the dated `>` build-log note blocks and the closed-items ledger.
  Those are internal provenance, are marked historical in the document, and are left
  as written on purpose — a build log that gets back-edited stops being evidence of
  anything. Resolvability of citations across the whole published surface is arch's
  `spec pins` (entity-system-arch-tools), which resolves cross-repo; duplicating it
  here would give two homes for one fact. This gate owns exactly the fact this repo
  owns: our own anchors, and the column that publishes them.
"""

import hashlib
import os
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
PIN = REPO / "tools" / "oracle-pin.env"
MATRIX = REPO / "CONFORMANCE-MATRIX.md"

# Docs whose anchor-shaped tokens must resolve. All of these are declared in
# CANONICAL-DOCS.toml and reach a public reader.
#
# `STATUS.md` moved `docs/status/` → `docs/` on 2026-08-23 and publishes again
# ([ADR-0031]'s correction: the DATED snapshots are working memory, the single rolling
# canonical log is not, and the two are now separable by PATH instead of by remembering a
# filename). It was gated here even during the window it did not publish — it quotes the
# pin, and a digest that has drifted misleads the next session exactly as it would mislead
# an adopter. Internal was never a reason to carry a wrong number; that it is public again
# only removes the need to argue the point.
ANCHORED_DOCS = [
    "CONFORMANCE-MATRIX.md",
    "README.md",
    "CHANGELOG.md",
    "research/diagnostics/oracle-vendoring-policy.md",
    "research/diagnostics/validate-peer-usage.md",
    "docs/STATUS.md",
]

# Docs where a bare git short-SHA is a defect anywhere in the file.
#
# Scoped to the two front-door documents ON PURPOSE, and the exclusions matter more
# than the inclusions:
#
#   * CONFORMANCE-MATRIX.md is NOT here. Its live claims are already covered by
#     checks 1, 2 and 4, and it deliberately retains dev SHAs in the dated `>`
#     build-log blocks and the closed-items ledger under an explicit disclaimer — a
#     build log that gets back-edited stops being evidence of anything. Including it
#     produced ~85 findings that are all intended state, and a gate that is
#     permanently red teaches people to skip it. Same reasoning that keeps
#     check-set-gate's disclosed CAP backlog non-failing.
#   * AGENTS.md is NOT here. It publishes commit-pinned engineering provenance on
#     purpose — METHODOLOGY.md requires the anti-pattern catalog to carry "a source
#     commit" per entry. That requirement and L24 are in genuine tension; routed to
#     arch rather than resolved by quietly stripping citations the methodology asks
#     for.
NO_BARE_SHA_DOCS = ["README.md", "CHANGELOG.md"]

# Hex-looking tokens that are not commits and never will be. `ed25519` is seven hex
# characters; `d9d9f7a0` is CBOR tag 55799 + the empty map, a conformance vector.
NOT_A_COMMIT = {"ed25519", "d9d9f7a0", "ed448"}

# A git short-SHA as we write them: 7-10 bare hex in backticks. A 64-hex content hash
# is never this shape, and neither is a truncated digest (which carries U+2026).
SHA_RE = re.compile(r"`([0-9a-f]{7,10})`")
ANCHOR_RE = re.compile(r"([0-9a-f]{8,64})…")


def pin_values():
    """Every 8+-hex value this repo has committed as an anchor, current or retired.

    Comments count. `oracle-pin.env` records superseded and recomputed digests in
    prose — the old-method `ca0c988f…`/`3e749f37…` pair from the test-fixture
    incident, for instance — and a document citing one of those is citing a value
    this repo did record. Reading only the assignment lines would have called them
    typos.

    Harvest only DIGEST-shaped tokens: a full 64-hex sha256, or a truncated form
    explicitly marked with U+2026. **A bare 40-hex commit must not be harvested**, and
    getting that wrong silently disabled the bare-SHA check: `commit =
    c1b0708c167956765a2641ee2775adbcfe62c65b` is in this file, so a prefix test
    accepted `c1b0708` as "a known anchor" and the gate passed a planted defect. The
    file records both kinds of identifier and only one of them is an anchor.
    """
    vals = {}
    for line in PIN.read_text().splitlines():
        key = line.partition("=")[0].strip().lstrip("#").strip() or "(comment)"
        for tok in re.findall(r"[0-9a-f]{64}", line):
            vals.setdefault(tok, key)
        for tok in re.findall(r"([0-9a-f]{8,63})…", line):
            vals.setdefault(tok, key)
    return vals


def manifest_values():
    """SHA-256 pins from the spec-data and test-vector snapshots.

    Same dual harvest as pin_values(), and for the same reason: these files record
    superseded corpora in prose with the digest truncated — the ECF corpus's
    *"was `71015b72…`"* row is the whole provenance of a value the matrix
    legitimately cites. 64-hex only would have called that citation a typo.

    **A vector corpus's pins live in its `CHANGELOG.md`, not a `MANIFEST.md`.**
    When the corpora were de-versioned (`GUIDE-CONFORMANCE.md` §5.1) the single
    `test-vectors/v0.8.0/MANIFEST.md` was retired in favour of one changelog per
    corpus. A glob left pointing at the old name would match nothing and harvest
    zero anchors — silently, because an empty harvest looks exactly like a clean
    one. Both names are globbed so neither a stale nor a future layout goes blind,
    and `check_manifest_harvest()` asserts the harvest is non-empty.
    """
    vals = {}
    for pat in ("protocol-generator/shared/spec-data/*/MANIFEST.md",
                "protocol-generator/shared/test-vectors/*/MANIFEST.md",
                "protocol-generator/shared/test-vectors/*/CHANGELOG.md",
                "protocol-generator/shared/test-vectors/README.md"):
        for m in sorted(REPO.glob(pat)):
            body = m.read_text()
            for tok in (re.findall(r"[0-9a-f]{64}", body)
                        + re.findall(r"([0-9a-f]{8,63})…", body)):
                vals.setdefault(tok, str(m.relative_to(REPO)))
    return vals


def pin_column(lines):
    """Yield (lineno, cell) for the §1 table's pin column, plus its header text."""
    header_idx = None
    for i, line in enumerate(lines):
        if line.startswith("| Peer |") and "core`" in line:
            header_idx = i
            break
    if header_idx is None:
        return None, []
    cols = [c.strip() for c in lines[header_idx].strip().strip("|").split("|")]
    # The pin column sits between Spec and the --profile core result.
    try:
        idx = next(n for n, c in enumerate(cols) if c.startswith("Oracle"))
    except StopIteration:
        return "<no Oracle column>", []
    cells = []
    for i in range(header_idx + 2, len(lines)):     # +2 skips the |---| separator
        line = lines[i]
        if not line.startswith("|"):
            break
        parts = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(parts) > idx:
            cells.append((i + 1, parts[idx]))
    return cols[idx], cells


def main():
    fails = []
    notes = []

    pins = pin_values()
    manifests = manifest_values()
    known = dict(manifests)
    known.update(pins)

    # A gate that examined ZERO things prints the same word as one that examined
    # forty-six. manifest_values() globs filenames, so a layout change silently
    # empties it — and an empty anchor table makes check 3 pass every published
    # digest by vacuously failing to contradict it... no: it makes check 3 FAIL
    # everything, which at least shouts. The quiet direction is a PARTIAL harvest,
    # so assert the population and print the count either way.
    n_sources = (len(list(REPO.glob("protocol-generator/shared/spec-data/*/MANIFEST.md")))
                 + len(list(REPO.glob("protocol-generator/shared/test-vectors/*/MANIFEST.md")))
                 + len(list(REPO.glob("protocol-generator/shared/test-vectors/*/CHANGELOG.md"))))
    n_corpora = len([p for p in (REPO / "protocol-generator/shared/test-vectors").iterdir()
                     if p.is_dir()]) if (REPO / "protocol-generator/shared/test-vectors").is_dir() else 0
    if n_sources == 0 or not manifests:
        fails.append(
            "pin-gate: harvested 0 digests from the pinned snapshots — the "
            "spec-data/test-vectors glob matches nothing. Check the layout before "
            "trusting any 'OK' from this gate."
        )
    elif n_corpora and n_sources < n_corpora:
        fails.append(
            f"pin-gate: {n_corpora} vector corpora on disk but only {n_sources} pin "
            f"source(s) harvested — a corpus with no MANIFEST.md/CHANGELOG.md "
            f"contributes no anchors, so its digests would read as mistyped."
        )
    else:
        notes.append(f"pin sources: {n_sources} manifest/changelog files → "
                     f"{len(manifests)} digests ({n_corpora} vector corpora)")

    text = MATRIX.read_text()
    lines = text.splitlines()

    # -- 1 & 2: the pin column -------------------------------------------------
    header, cells = pin_column(lines)
    if header is None:
        fails.append("CONFORMANCE-MATRIX.md: could not locate the §1 table header row")
    elif not header.startswith("Oracle pin"):
        fails.append(
            f'CONFORMANCE-MATRIX.md: §1 pin column is headed "{header}" — it must read '
            '"Oracle pin". A column headed "Oracle commit" publishes an identifier no '
            "reader outside this tree can resolve (see this file's docstring)."
        )
    else:
        notes.append(f"§1 pin column: {len(cells)} rows under “{header}”")

    for lineno, cell in cells:
        for sha in SHA_RE.findall(cell):
            fails.append(
                f"CONFORMANCE-MATRIX.md:{lineno}: §1 pin column carries the commit "
                f"`{sha}`. The pin is a content digest — use "
                f"core_executed_check_set_digest from tools/oracle-pin.env."
            )
        if not ANCHOR_RE.search(cell):
            fails.append(
                f"CONFORMANCE-MATRIX.md:{lineno}: §1 pin cell {cell!r} carries no "
                f"content digest."
            )

    # -- 3: every published anchor resolves to something we recorded -----------
    for rel in ANCHORED_DOCS:
        doc = REPO / rel
        if not doc.exists():
            fails.append(f"{rel}: declared as anchor-bearing but missing")
            continue
        for n, line in enumerate(doc.read_text().splitlines(), 1):
            for tok in ANCHOR_RE.findall(line):
                if not any(k.startswith(tok) for k in known):
                    fails.append(
                        f"{rel}:{n}: published anchor `{tok}…` matches no value in "
                        f"tools/oracle-pin.env or any pinned MANIFEST. A mistyped digest "
                        f"is invisible to a reader — verify it against the source."
                    )

    # -- 3b: the three number-publishing docs carry no bare commit at all ------
    # Note the regex is applied per-line but a backtick span can WRAP a line, which
    # is how `@ c1b0708` survived in README.md until 2026-08-23 — invisible to a
    # per-line scan because its span opened on the previous line. Joining the text
    # first is the fix, and it is why this check is not simply a grep.
    for rel in NO_BARE_SHA_DOCS:
        doc = REPO / rel
        if not doc.exists():
            fails.append(f"{rel}: declared number-publishing but missing")
            continue
        body = doc.read_text()
        for span in re.findall(r"`[^`]*`", body, re.S):
            for sha in re.findall(r"\b([0-9a-f]{7,10})\b", span):
                if sha in NOT_A_COMMIT:
                    continue
                if any(k.startswith(sha) for k in known):
                    continue                     # a truncated content anchor
                n = body[:body.index(span)].count("\n") + 1
                fails.append(
                    f"{rel}:~{n}: `{sha}` reads as a git commit in a document that "
                    f"publishes conformance numbers. Anchor on a content digest "
                    f"([ADR-0012] Amendment 1), or describe the pin by check count."
                )

    # -- 4: the CURRENT anchors published are the current values ---------------
    current = {
        "core_executed_check_set_digest": None,
        "core_gate_fingerprint": None,
        "check_set_digest": None,
    }
    for line in PIN.read_text().splitlines():
        s = line.strip()
        for key in current:
            if s.startswith(key + " ") or s.startswith(key + "="):
                current[key] = s.split("=", 1)[1].split()[0]
    for key, val in current.items():
        if val is None:
            fails.append(f"tools/oracle-pin.env: no {key}")
            continue
        if val[:8] + "…" not in text:
            fails.append(
                f"CONFORMANCE-MATRIX.md: does not publish {key} (`{val[:8]}…`). "
                f"Every anchor the pin file holds must be visible to a reader."
            )
        else:
            notes.append(f"published {key} = {val[:8]}…")

    # -- 5: the GUIDE-CONFORMANCE digest ---------------------------------------
    #
    # `guide_conformance` sat in oracle-pin.env with NOTHING READING IT, and that is
    # the mechanism behind a cohort-wide drift rather than a tidiness complaint. Peers
    # derive their whole §7a conformance scaffolding from that guide — the
    # system/validate handlers, their params contracts, the §7b concurrency gate — and
    # when `0.8.2.19` turned `reentry_granter`/`reentry_cap_signature` into PLURAL
    # carriers, 40 of 46 peers silently stayed singular. Nothing could report it: the
    # spec-data snapshots are digest-verified by `make lint` and the guide is
    # deliberately NOT in spec-data (non-normative, arch-owned), so the one input that
    # moved was the one input with no gate. A pin nobody reads is a comment.
    #
    # FAILS ONLY WHEN THE SIBLING IS PRESENT AND DIFFERS. A clean clone of this repo
    # alone has no sibling checkout, and a gate that exits 1 there is a gate people
    # switch off — the `author-extension-host --check` lesson, which was red on every
    # clone for reading gitignored scratch. Absent sibling → say the comparison was not
    # made, and pass. That distinction is the whole design: "could not look" and "looked
    # and it matches" must not print the same word.
    guide_pin = None
    for line in PIN.read_text().splitlines():
        s = line.strip()
        if s.startswith("guide_conformance"):
            guide_pin = s.split("=", 1)[1].split()[0]
    # PIN_GATE_GUIDE exists so the three arms below can be exercised WITHOUT WRITING TO
    # THE SIBLING REPO. Verifying this check the obvious way means making the guide
    # differ, and the obvious way to do that is to edit it in place — which crosses the
    # standing "never write to the architecture repo" boundary for a test. Copy it to a
    # scratch path, mutate the copy, point this at it. Not for production use: it is a
    # way to make the gate agree with you.
    guide = pathlib.Path(os.environ.get("PIN_GATE_GUIDE", "")) if os.environ.get("PIN_GATE_GUIDE") \
        else REPO.parent / "entity-system-architecture" / "guides" / "GUIDE-CONFORMANCE.md"
    if guide_pin is None:
        fails.append(
            "tools/oracle-pin.env: no guide_conformance digest. Peers derive their §7a "
            "conformance scaffolding from GUIDE-CONFORMANCE.md; unpinned, it moves "
            "without anything reporting it (measured: the 0.8.2.19 plural-carrier "
            "rename reached 0 of 46 peers)."
        )
    elif not guide.is_file():
        notes.append(
            f"guide_conformance = {guide_pin[:8]}… — sibling checkout absent, "
            f"STALENESS NOT COMPARED (this is not a pass for that property)"
        )
    else:
        actual = hashlib.sha256(guide.read_bytes()).hexdigest()
        if actual == guide_pin:
            notes.append(f"guide_conformance = {guide_pin[:8]}… matches the sibling")
        else:
            fails.append(
                f"GUIDE-CONFORMANCE.md has MOVED: pinned {guide_pin[:8]}…, actual "
                f"{actual[:8]}…. Peers derive their §7a conformance scaffolding from it, "
                f"so a move is potential cohort work and must be read before the pin is "
                f"advanced. Diff it, act on it, then update guide_conformance in "
                f"tools/oracle-pin.env — do NOT advance the pin to silence this."
            )

    quiet = "--quiet" in sys.argv
    if not quiet or fails:
        print("pin-gate — published conformance anchors are content, and are ours")
        for line in notes:
            print(f"  {line}")
    if fails:
        print()
        for f in fails:
            print(f"  FAIL  {f}")
        print(f"\nFAIL — {len(fails)} problem(s).")
        return 1
    if not quiet:
        print("\nPASS — the pin column is content-anchored and every published "
              "digest matches tools/oracle-pin.env.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
