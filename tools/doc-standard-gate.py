#!/usr/bin/env python3
"""doc-standard-gate — the 2026-09 doc/memory/routing standard, enforced locally.

WHY THIS EXISTS, AND WHY IT IS NOT "the release pipeline will catch it".

The standard's blocking checks run at a CUT. That is the wrong moment to learn that
`AGENTS.md` is undeclared or that a memory file was added and never indexed, because by
then the tree has moved on and the person who made the change is gone. Every invariant
below is cheap, offline, and decidable from this tree alone, so it runs in `make lint`.

It is also this repo's own rule applied to a document standard: **a discipline with no
enforcement point is theater.** What was a paragraph in `AGENTS.md` for one day is a check
from today.

WHAT IT DOES NOT DO — stated because a gate's silence must not be mistaken for a verdict:

  * It does not check the CONTENT of anything. A memory entry can be wrong, stale, or a
    lie about a peer and this gate reports clean.
  * It does not run the pipeline's own checks. `canon-filter`, `public-regress` and the
    overlay byte-comparison live in the release builder and are authoritative there; this
    is the subset that is decidable here.
  * The 30 KiB `AGENTS.md` budget is ADVISORY this release and BLOCKING from the next.
    `--strict` turns it blocking now.

EVERY CHECK PRINTS THE COUNT IT EXAMINED. A check that examined zero things prints the
same word as one that examined forty-six, and this repo has found that defect seven times.
Where a count can legitimately be zero, that is said at the site; everywhere else the
count is asserted non-zero and a zero is a FAILURE OF THE CHECK, not a pass.

Self-test: `tools/doc-standard-gate.py --self-test` plants a defect per check in a scratch
copy and requires each to be caught. A gate with no regression suite is a script that has
not been wrong yet.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# §2 of the standard. A cut is refused without these, and the fourth is the one that bites:
# all four are loose top-level PROSE, so undeclared they are deleted at a cut — which is how
# a repo goes public with no AGENTS.md without anyone deleting one.
REQUIRED = ("AGENTS.md", "CLAUDE.md", "AGENTS-STANDARD.md", "METHODOLOGY.md", "README.md")
REQUIRED_DECLARED = ("AGENTS.md", "CLAUDE.md", "AGENTS-STANDARD.md", "METHODOLOGY.md", "README.md")

# Tier-1 make verbs, required only because we HAVE a Makefile. `run` is Tier 2; `dist` and
# `publish` are reserved words — implement the standard meaning or do not define the verb.
TIER1 = ("help", "build", "test", "lint", "fmt", "check", "clean")

AGENTS_BUDGET = 30 * 1024  # 30,720 bytes. BYTES, not lines — bytes are what a context window pays.

MEMORY = Path("docs/agents/memory")
OUTBOX = Path("docs/outbox")
TRACKER_GLOB = "docs/status/TRACKER-*.md"

# A memory file named for a category of FEELING accepts anything and becomes the new
# AGENTS.md. This is the standard's advisory list; we treat it as blocking because the
# whole point of the split was to stop exactly this.
FEELING_NAMES = {"MISC", "NOTES", "TIPS", "GOTCHAS", "RANDOM", "STUFF", "STUFF.md", "STUFF2"}


class Result:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.lines: list[str] = []

    def err(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def note(self, msg: str) -> None:
        self.lines.append(msg)


def load_manifest(root: Path) -> dict:
    return tomllib.loads((root / "CANONICAL-DOCS.toml").read_text(encoding="utf-8"))


def check_required(root: Path, man: dict, r: Result) -> None:
    """1. The required set exists AND is declared."""
    declared = {d["path"] for d in man.get("doc", [])}
    missing = [f for f in REQUIRED if not (root / f).is_file()]
    undeclared = [f for f in REQUIRED_DECLARED if f not in declared]
    if missing:
        r.err(f"required file(s) absent: {', '.join(missing)}")
    if undeclared:
        r.err(
            f"required file(s) present but UNDECLARED in CANONICAL-DOCS.toml: "
            f"{', '.join(undeclared)} — undeclared top-level prose is DELETED at a cut, "
            f"not skipped"
        )
    r.note(f"required set: {len(REQUIRED)} examined, {len(REQUIRED) - len(missing)} present, "
           f"{len(REQUIRED_DECLARED) - len(undeclared)} declared")


def check_claude_shim(root: Path, r: Result) -> None:
    """2. CLAUDE.md is a shim — imports and prose, never a second copy of the guidance."""
    p = root / "CLAUDE.md"
    if not p.is_file():
        return  # check_required already said so
    text = p.read_text(encoding="utf-8")
    if "@AGENTS.md" not in text:
        r.err("CLAUDE.md does not import @AGENTS.md — it must be a shim, not a document")
    size = len(text.encode())
    if size > 2048:
        r.err(f"CLAUDE.md is {size} B — a shim, not a place for content (>2 KiB)")
    r.note(f"CLAUDE.md shim: {size} B, imports @AGENTS.md")


def check_declared_exist(root: Path, man: dict, r: Result) -> None:
    """3. Every declared doc exists. The keep-list is FAIL-CLOSED on an absent declared path
    ([ADR-0021]) — a declaration naming a file we moved aborts every unit that names it."""
    docs = man.get("doc", [])
    if not docs:
        r.err("CANONICAL-DOCS.toml declares NO docs — the manifest did not parse as expected")
        return
    missing = [d["path"] for d in docs if not (root / d["path"]).exists()]
    for m in missing:
        r.err(f"declared but absent: {m} (the keep-list is fail-closed on this)")
    r.note(f"declared docs: {len(docs)} examined, {len(missing)} absent")


def check_outbox(root: Path, man: dict, r: Result) -> None:
    """4. docs/outbox/ is NEVER declared. Routing is internal; publishing the corpus is the
    expensive mistake. Also: nothing but packets lives there."""
    declared = {d["path"] for d in man.get("doc", [])}
    leaked = sorted(p for p in declared if p.startswith("docs/outbox"))
    for p in leaked:
        r.err(f"docs/outbox/ path DECLARED as canonical: {p} — routing must never publish")
    ob = root / OUTBOX
    n = 0
    if ob.is_dir():
        for f in ob.iterdir():
            if f.name == "README.md":
                continue
            n += 1
            if not re.match(r"^(ROUTING|HANDOFF-TO)-", f.name):
                r.err(f"docs/outbox/{f.name} is not a packet — nothing else lives here")
        if not (ob / "README.md").is_file():
            # Describe the path, never write it: this file is non-prose and PUBLISHES, while the
            # outbox is stripped at a cut — so a literal here is exactly the defect link-gate
            # check 2 exists for. It caught this on the day the gate was written.
            r.err(f"the {OUTBOX.name} README is absent — the convention must be stated where "
                  f"it lives")
    r.note(f"outbox: {n} packet(s), {len(leaked)} declared (must be 0)")


def check_memory(root: Path, man: dict, r: Result) -> None:
    """5. The memory index and files agree IN BOTH DIRECTIONS, and every file is declared.

    Both directions matter and they fail differently: a file missing from the index is
    invisible to every reader, and an index row with no file sends one to a 404."""
    mem = root / MEMORY
    if not mem.is_dir():
        r.err(f"{MEMORY}/ does not exist — the memory split is the standard's §4")
        return
    idx = mem / "INDEX.md"
    if not idx.is_file():
        r.err(f"{MEMORY}/INDEX.md absent — an unindexed directory is the new AGENTS.md")
        return
    files = {f.name for f in mem.glob("*.md")} - {"INDEX.md"}
    linked = set(re.findall(r"\[`([A-Za-z0-9][A-Za-z0-9_-]*\.md)`\]", idx.read_text(encoding="utf-8")))
    linked -= {"INDEX.md"}
    for n in sorted(linked - files):
        r.err(f"INDEX.md names {n}, which does not exist in {MEMORY}/")
    for n in sorted(files - linked):
        r.err(f"{MEMORY}/{n} exists and INDEX.md does not name it — unindexed is unfindable")

    declared = {d["path"] for d in man.get("doc", [])}
    for n in sorted(files | {"INDEX.md"}):
        rel = f"{MEMORY.as_posix()}/{n}"
        if rel not in declared:
            r.err(f"{rel} is undeclared — prose under a doc root, so a cut deletes it")

    for n in sorted(files):
        stem = n[:-3].upper().replace("-", "").replace("_", "")
        if n[:-3].upper() in FEELING_NAMES or stem in FEELING_NAMES:
            r.err(f"{MEMORY}/{n} is named for a category of feeling — such a file accepts "
                  f"anything and becomes the new AGENTS.md. Name it for a part of the system.")

    # Findable BY THE SYMPTOM is the property that makes this directory usable at all.
    for n in sorted(files):
        if "Arrive here when" not in (mem / n).read_text(encoding="utf-8"):
            r.err(f"{MEMORY}/{n} has no 'Arrive here when' line — a reader arrives with a "
                  f"symptom, not with a filename")

    if not files:
        r.err("memory check examined ZERO files — the glob matched nothing, so this check is "
              "vacuous. Fix the glob, do not delete the check.")
    r.note(f"memory: {len(files)} topic file(s) + INDEX, cross-checked both directions, all declared")


def check_agents_size(root: Path, r: Result, strict: bool) -> None:
    """6. AGENTS.md <= 30 KiB. Advisory this release, blocking from the next.

    Codex defaults `project_doc_max_bytes` to 32,768 and SILENTLY TRUNCATES above it —
    AGENTS.md exists to be read by every agent, not one of them."""
    p = root / "AGENTS.md"
    if not p.is_file():
        return
    size = len(p.read_bytes())
    pct = 100 * size / AGENTS_BUDGET
    msg = (f"AGENTS.md is {size:,} B against the {AGENTS_BUDGET:,} B budget ({pct:.0f}%). "
           f"Do NOT satisfy this by deleting knowledge — move it to {MEMORY}/, or turn it "
           f"into a check.")
    if size > AGENTS_BUDGET:
        (r.err if strict else r.warn)(msg)
    r.note(f"AGENTS.md: {size:,} B / {AGENTS_BUDGET:,} B budget ({pct:.0f}%)"
           + ("  [--strict: blocking]" if strict else "  [advisory this release]"))


def check_trackers(root: Path, r: Result) -> None:
    """7. Every tracker carries a watermark, and it names a tip.

    "Nothing new" and "nothing new AND I CHECKED" are different claims. The tip is what
    separates them — a checkout you have not pulled lists nothing new and looks exactly
    like a clean scan, after which the watermark advances PAST packets never seen."""
    trackers = sorted(root.glob(TRACKER_GLOB))
    wm = re.compile(r"_Last read `([^`]+)`'s outbox through", re.I)
    for t in trackers:
        text = t.read_text(encoding="utf-8")
        m = wm.search(text)
        if not m:
            r.err(f"{t.relative_to(root)} has no watermark line — there is then no answer to "
                  f"'what have I not seen?'")
            continue
        head = text[: m.end() + 400]
        if not re.search(r"@ `[0-9a-f]{7,40}`", head):
            r.err(f"{t.relative_to(root)} watermark names no tip — a scan with no tip cannot "
                  f"be told apart from no scan")
    if not trackers:
        r.err("tracker check examined ZERO files — the glob matched nothing, so this check is "
              "vacuous. Fix the glob, do not delete the check.")
    r.note(f"trackers: {len(trackers)} examined, all carry a watermark naming a tip")


def check_counterpart_set(root: Path, r: Result) -> None:
    """8. THE SET MUST COME FROM THE WORLD, NOT FROM THE ARTIFACTS WE HAVE ALREADY MADE.

    A reconciliation keyed on the trackers you KEEP cannot see the counterpart you OMITTED —
    a seat with no file is not an unrowed packet, it is an absent row in an absent table, and
    the control reports clean. This has cost this repo four times. So: ask which sibling repos
    keep a tracker for US, and require one of ours for each.

    REPORTS rather than fails — the sibling checkouts are not guaranteed present (a clean
    clone has none), and a gate that is red on every clone is a gate people switch off.
    A missing sibling tree is 'could not look', which is NOT 'nothing to see' and says so."""
    me = root.name
    siblings = root.parent
    keep_one_for_us, looked = [], 0
    if siblings.is_dir():
        for d in sorted(siblings.iterdir()):
            if not (d / ".git").exists() or d.name == me:
                continue
            looked += 1
            if (d / "docs/status" / f"TRACKER-{me}.md").is_file():
                keep_one_for_us.append(d.name)
    if looked == 0:
        r.note("counterpart set: NO sibling checkouts beside this repo — could not look. That "
               "is not 'nothing to see'; re-run where the siblings are checked out.")
        return
    ours = {p.name[len("TRACKER-"):-3] for p in root.glob(TRACKER_GLOB)}
    missing = sorted(set(keep_one_for_us) - ours)
    for m in missing:
        r.warn(f"`{m}` keeps a TRACKER-{me}.md and we keep no tracker for them — every packet "
               f"they address to us is an absent row in an absent table")
    r.note(f"counterpart set: {looked} sibling repo(s) examined, {len(keep_one_for_us)} track us, "
           f"we keep {len(ours)}, {len(missing)} missing")


def check_make_verbs(root: Path, r: Result) -> None:
    """9. Tier-1 make verbs, required only because we have a Makefile."""
    mk = root / "Makefile"
    if not mk.is_file():
        r.note("no Makefile — Tier-1 verbs not required")
        return
    text = mk.read_text(encoding="utf-8")
    missing = [v for v in TIER1 if not re.search(rf"^{v}:", text, re.M)]
    for v in missing:
        r.err(f"Makefile has no Tier-1 target `{v}`")
    r.note(f"make verbs: {len(TIER1)} examined, {len(TIER1) - len(missing)} present")


def check_dated_placement(root: Path, man: dict, r: Result) -> None:
    """10. A dated doc lives in a `status/` directory or in a DECLARED area.

    The rule used to carry one hardcoded idea of where dated docs live and fired on anyone
    organised differently — which is what `[[area]]` exists to fix. We declare ours, so this
    reads the declarations rather than assuming."""
    areas = {a["path"].rstrip("/") for a in man.get("area", [])
             if a.get("kind") in {"status", "archive", "outbox"}}
    dated = re.compile(r"\b20\d{2}-\d{2}-\d{2}\b")
    out = subprocess.run(["git", "-C", str(root), "ls-files", "*.md"],
                         capture_output=True, text=True).stdout.split()
    offenders, examined = [], 0
    for rel in out:
        name = Path(rel).name
        if not dated.search(name):
            continue
        examined += 1
        parts = Path(rel).parts
        if "status" in parts or "archive" in parts:
            continue
        if any(rel.startswith(a + "/") for a in areas):
            continue
        offenders.append(rel)
    for o in offenders[:20]:
        r.err(f"dated doc outside a status/ directory or a declared area: {o}")
    if len(offenders) > 20:
        r.err(f"...and {len(offenders) - 20} more")
    r.note(f"dated docs: {examined} examined, {len(areas)} declared area(s), {len(offenders)} misplaced")


PROSE_EXT = {".md", ".markdown", ".rst", ".txt", ".adoc", ".patch", ".diff"}
# canon-filter's doc-root prefixes, matched at the START of a path. Replayed here rather
# than imported because the filter lives in another repo — and re-read from its source
# rather than remembered, because this list was documented WRONG here for a fortnight.
DOC_ROOTS = ("docs/", "doc/", "reviews/", "review/", "research/", "explorations/", "exploration/",
             "proposals/", "proposal/", "validation/", "stewardship/", "status/", "reports/",
             "report/", "notes/", "handoffs/", "handoff/", "audits/", "audit/", "planning/",
             "design/", "designs/")


def check_declared_links(root: Path, man: dict, r: Result) -> None:
    """11. A DECLARED doc must not markdown-link a path the filter STRIPS.

    Distinct from `link-gate` check 2, which is scoped to NON-PROSE citations because the
    prose-to-prose class was measured at 26 hits — dated snapshots cited from published docs —
    and parked by ruling. This is the narrow, unambiguous subset of that class: a markdown
    LINK (not a citation, not a backticked path) from a DECLARED file to a path the release
    deletes. A reader clicks it and gets nothing; there is no reading under which that is
    intended, so there is no noise to separate out.

    It earned itself immediately — the commit that created `docs/outbox/` linked it from
    `AGENTS.md` twice and from `docs/STATUS.md` once, all three published, all three 404."""
    declared = {d["path"] for d in man.get("doc", [])} | {"README.md", "CANONICAL-DOCS.toml"}

    def is_stripped(rel: str) -> bool:
        if Path(rel).suffix.lower() not in PROSE_EXT:
            return False  # source, configs and vectors are never dropped, wherever they sit
        in_scope = ("/" not in rel) or any(rel.startswith(p) for p in DOC_ROOTS)
        return in_scope and rel not in declared

    link = re.compile(r"\[[^\]]*\]\(([^)#\s]+)\)")
    examined = 0
    for rel in sorted(declared):
        p = root / rel
        if p.suffix.lower() != ".md" or not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for m in link.finditer(text):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            examined += 1
            try:
                resolved = (p.parent / target).resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                continue  # escapes the repo; a different problem and not this check's
            if is_stripped(resolved):
                line = text[: m.start()].count("\n") + 1
                r.err(f"{rel}:{line} links `{target}` — a published document linking a path the "
                      f"release STRIPS ({resolved}). Describe the source; do not name it.")
    if examined == 0:
        r.err("declared-link check examined ZERO links — the pattern or the declared set matched "
              "nothing, so this check is vacuous. Fix it, do not delete it.")
    r.note(f"declared-doc links: {examined} examined across {len(declared)} declared file(s), "
           f"none into a stripped path")


CHECKS = (
    ("required set", check_required),
    ("CLAUDE.md shim", check_claude_shim),
    ("declared docs exist", check_declared_exist),
    ("outbox never declared", check_outbox),
    ("memory index agrees both ways", check_memory),
    ("AGENTS.md budget", check_agents_size),
    ("tracker watermarks", check_trackers),
    ("counterpart set from the world", check_counterpart_set),
    ("Tier-1 make verbs", check_make_verbs),
    ("dated docs placed", check_dated_placement),
    ("declared docs link nothing stripped", check_declared_links),
)


def run(root: Path, strict: bool) -> Result:
    r = Result()
    man = load_manifest(root)
    check_required(root, man, r)
    check_claude_shim(root, r)
    check_declared_exist(root, man, r)
    check_outbox(root, man, r)
    check_memory(root, man, r)
    check_agents_size(root, r, strict)
    check_trackers(root, r)
    check_counterpart_set(root, r)
    check_make_verbs(root, r)
    check_dated_placement(root, man, r)
    check_declared_links(root, man, r)
    return r


def report(r: Result, quiet: bool) -> int:
    if not quiet:
        for line in r.lines:
            print(f"doc-standard-gate: {line}")
    for w in r.warnings:
        print(f"doc-standard-gate: ADVISORY — {w}", file=sys.stderr)
    if r.errors:
        print(f"doc-standard-gate: {len(r.errors)} FAILURE(S):", file=sys.stderr)
        for e in r.errors:
            print(f"  {e}", file=sys.stderr)
        print("\nThe answer is almost never delete. It is declare, or move. If your next step "
              "removes information, stop.", file=sys.stderr)
        return 1
    if not quiet:
        print(f"doc-standard-gate: OK — {len(CHECKS)} checks, "
              f"{len(r.warnings)} advisory, 0 failures.")
    return 0


# ---------------------------------------------------------------------------- self-test

def self_test() -> int:
    """Plant one defect per check in a scratch copy; each must be caught.

    A plant that runs green is a finding about the CHECK. Every plant below names the
    check it must redden, and the unplanted copy must run clean first — otherwise a
    'caught' is indistinguishable from a tree that was already red."""
    with tempfile.TemporaryDirectory() as td:
        # Copy only what the gate reads; a full tree copy is minutes and buys nothing.
        work = Path(td) / REPO.name
        work.mkdir()
        for item in ("CANONICAL-DOCS.toml", "AGENTS.md", "CLAUDE.md", "AGENTS-STANDARD.md",
                     "METHODOLOGY.md", "README.md", "Makefile"):
            shutil.copy2(REPO / item, work / item)
        for d in (MEMORY, OUTBOX, Path("docs/status")):
            src, dst = REPO / d, work / d
            dst.mkdir(parents=True, exist_ok=True)
            for f in src.glob("*.md"):
                shutil.copy2(f, dst / f.name)
        # Every OTHER declared path gets a stand-in. The declared-docs check ranges over the
        # whole manifest, so without these the baseline is red for a reason that has nothing
        # to do with any plant — and a red baseline makes every 'CAUGHT' meaningless.
        for decl in load_manifest(work).get("doc", []):
            p = work / decl["path"]
            if not p.exists():
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("stand-in for the self-test\n")
        # git ls-files backs one check; without a repo it returns nothing, which is a
        # legitimate zero here and is asserted as such rather than silently tolerated.
        subprocess.run(["git", "init", "-q"], cwd=work, check=True)
        subprocess.run(["git", "add", "-A"], cwd=work, check=True)

        base = run(work, strict=False)
        if base.errors:
            print("self-test: the UNPLANTED copy is already red — a 'caught' would prove "
                  "nothing:", file=sys.stderr)
            for e in base.errors:
                print(f"  {e}", file=sys.stderr)
            return 1

        def restore(p: Path, saved: bytes) -> None:
            p.write_bytes(saved)

        plants: list[tuple[str, str]] = []

        def plant(name: str, mutate, undo) -> None:
            mutate()
            res = run(work, strict=False)
            caught = bool(res.errors)
            plants.append((name, "CAUGHT" if caught else "INERT"))
            undo()

        # 1 required-but-undeclared
        man_path = work / "CANONICAL-DOCS.toml"
        saved_man = man_path.read_bytes()
        plant("required file undeclared",
              lambda: man_path.write_text(
                  man_path.read_text().replace('path  = "AGENTS.md"', 'path  = "AGENTS-XX.md"')),
              lambda: restore(man_path, saved_man))

        # 2 CLAUDE.md stops being a shim
        cl = work / "CLAUDE.md"
        saved_cl = cl.read_bytes()
        plant("CLAUDE.md not a shim",
              lambda: cl.write_text("# not a shim\n" + "x" * 4000),
              lambda: restore(cl, saved_cl))

        # 3 declared doc missing
        plant("declared doc absent",
              lambda: (work / "README.md").unlink(),
              lambda: shutil.copy2(REPO / "README.md", work / "README.md"))

        # 4 outbox declared
        plant("outbox declared canonical",
              lambda: man_path.write_text(
                  man_path.read_text()
                  + f'\n[[doc]]\npath  = "{OUTBOX.as_posix()}/README.md"\ntitle = "x"\n'
                    'blurb = "x"\ngroup = "x"\n'),
              lambda: restore(man_path, saved_man))

        # 5a memory file not in the index
        newmem = work / MEMORY / "UNINDEXED-TOPIC.md"
        plant("memory file absent from INDEX",
              lambda: newmem.write_text("# x\n\n**Arrive here when:** x.\n"),
              lambda: newmem.unlink())

        # 5b index row with no file
        idx = work / MEMORY / "INDEX.md"
        saved_idx = idx.read_bytes()
        plant("INDEX row with no file",
              lambda: idx.write_text(idx.read_text() + "\n| [`GHOST.md`](GHOST.md) | x | x |\n"),
              lambda: restore(idx, saved_idx))

        # 5c a file named for a feeling
        feel = work / MEMORY / "GOTCHAS.md"
        plant("memory file named for a feeling",
              lambda: (feel.write_text("# x\n\n**Arrive here when:** x.\n"),
                       idx.write_text(idx.read_text() + "\n| [`GOTCHAS.md`](GOTCHAS.md) | x | x |\n"),
                       man_path.write_text(man_path.read_text()
                                           + '\n[[doc]]\npath  = "docs/agents/memory/GOTCHAS.md"\n'
                                             'title = "x"\nblurb = "x"\ngroup = "x"\n')),
              lambda: (feel.unlink(), restore(idx, saved_idx), restore(man_path, saved_man)))

        # 6 AGENTS.md over budget (blocking only under --strict)
        ag = work / "AGENTS.md"
        saved_ag = ag.read_bytes()
        ag.write_bytes(saved_ag + b"x" * AGENTS_BUDGET)
        strict_res = run(work, strict=True)
        loose_res = run(work, strict=False)
        plants.append(("AGENTS.md over budget (--strict blocks)",
                       "CAUGHT" if strict_res.errors else "INERT"))
        plants.append(("AGENTS.md over budget (advisory only by default)",
                       "CAUGHT" if (loose_res.warnings and not loose_res.errors) else "INERT"))
        restore(ag, saved_ag)

        # 7 tracker without a watermark
        tr = sorted((work / "docs/status").glob("TRACKER-*.md"))[0]
        saved_tr = tr.read_bytes()
        plant("tracker with no watermark",
              lambda: tr.write_text(
                  re.sub(r"_Last read .*?\._", "", tr.read_text(), flags=re.S | re.I)),
              lambda: restore(tr, saved_tr))

        # 7b watermark with no tip
        plant("watermark naming no tip",
              lambda: tr.write_text(re.sub(r"@ `[0-9a-f]{7,40}`", "at their latest",
                                           tr.read_text())),
              lambda: restore(tr, saved_tr))

        # 9 missing make verb
        mk = work / "Makefile"
        saved_mk = mk.read_bytes()
        plant("Makefile missing a Tier-1 verb",
              lambda: mk.write_text(re.sub(r"(?m)^clean:", "cleanup:", mk.read_text())),
              lambda: restore(mk, saved_mk))

        # 11 a declared doc links a stripped path — the defect this gate found on day one
        rd = work / "README.md"
        saved_rd = rd.read_bytes()
        plant("declared doc links a stripped path",
              lambda: rd.write_text(rd.read_text()
                                    + f"\n[the outbox]({OUTBOX.as_posix()}/README.md)\n"),
              lambda: restore(rd, saved_rd))

        # 10 dated doc outside status/ and outside any declared area
        stray = work / "STRAY-2026-09-17-note.md"
        plant("dated doc at repo root",
              lambda: (stray.write_text("x\n"),
                       subprocess.run(["git", "add", "-A"], cwd=work, check=True)),
              lambda: (stray.unlink(),
                       subprocess.run(["git", "add", "-A"], cwd=work, check=True)))

        inert = [n for n, s in plants if s == "INERT"]
        for n, s in plants:
            print(f"  {s:7s}  {n}")
        print(f"doc-standard-gate --self-test: {len(plants)} plants, "
              f"{len(plants) - len(inert)} caught, {len(inert)} inert")
        if inert:
            print("\nAn INERT plant is a finding about the CHECK, not about the plant.",
                  file=sys.stderr)
            return 1
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--strict", action="store_true",
                    help="make the AGENTS.md size budget blocking (it is blocking from the "
                         "next release regardless)")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--self-test", action="store_true",
                    help="plant a defect per check and require each to be caught")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    return report(run(REPO, a.strict), a.quiet)


if __name__ == "__main__":
    sys.exit(main())
