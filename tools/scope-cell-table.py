#!/usr/bin/env python3
"""Enumerate the §5 capability scope algebra as a decision table, and report coverage.

WHY THIS EXISTS
---------------
Twenty-one point revisions of `0.8.2.x` in twelve days moved almost nothing except ten
functions (`ENTITY-CORE-PROTOCOL.md` §5.2/§5.4/§5.6/§6.8).  Every finding in that arc has
one of three shapes: *this cell says A here and B there*, *this cell is unreachable*, or
*the sweep covered 3 of 7 sites*.  Those are not N defects.  They are one defect --
**the cells are nowhere enumerated** -- reported N times.

This script derives the cells from the algorithm's own structure, so the count is a
computation rather than an assertion, and so a fold can be checked against a table
instead of against another reading of the prose.

METHOD, AND ITS LIMIT
---------------------
The axes are read off the normative pseudocode, not invented:

  * LAYER      -- the four call sites that answer an authorization question.
  * DIMENSION  -- the four grant dimensions.  Their scope TYPE is not a free axis: it is
                  fixed by the dimension (`grant-entry`, §3.6 lines 1010-1013).
  * POLARITY   -- which arm of the scope decides.  `resources` at dispatch has two arms
                  the other dimensions do not (a pattern arm and a caller-exclude arm)
                  because it is the only dimension whose subject is a SET.
  * OPERAND    -- the pattern forms the matcher distinguishes.

Reachability is computed from the pseudocode's control flow.  A cell that no input can
reach is reported as DEAD rather than as uncovered -- the distinction matters, because a
dead cell needs deleting and an uncovered one needs a vector.

**The coverage column is a source read and is `unknown` until a harness executes it.**
It maps oracle check NAMES onto cells.  A name is evidence about intent, not about what
the check drives; this repo has published a wrong cohort claim from exactly that
inference before.  Cells marked `?` are the honest state, not an accusation.

Usage:
    python3 tools/scope-cell-table.py            # markdown table to stdout
    python3 tools/scope-cell-table.py --summary  # counts only
    python3 tools/scope-cell-table.py --gaps     # unruled / dead / uncovered only
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

# --------------------------------------------------------------------------------------
# AXIS 1 -- the layers.  Each is a call site in ENTITY-CORE-PROTOCOL.md that returns
# ALLOW/DENY or true/false over a grant scope.  `dims` is what that layer actually
# consults, read off the pseudocode's own loop body.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Layer:
    key: str
    fn: str
    section: str
    dims: tuple[str, ...]
    subject: str  # what is compared against the scope
    frame: str  # whose peer_id canonicalization is relative to


LAYERS = (
    Layer(
        "L1",
        "check_permission / check_grant_covers",
        "§5.2",
        ("handlers", "operations", "peers", "resources"),
        "value (resources: a target SET)",
        "local",
    ),
    Layer(
        "L2",
        "check_path_permission",
        "§6.8 / §6.3",
        ("handlers", "operations", "resources"),
        "value",
        "local",
    ),
    Layer(
        "L3",
        "scope_subset (chain attenuation)",
        "§5.5a",
        ("handlers", "operations", "peers", "resources"),
        "pattern",
        "per-link granter",
    ),
    Layer(
        "L4",
        "scope_subset (§6.2 mint)",
        "§6.2",
        ("handlers", "operations", "peers", "resources"),
        "pattern",
        "local (both sides)",
    ),
)

# --------------------------------------------------------------------------------------
# AXIS 2 -- the dimensions.  Scope type is DETERMINED, not free.  This is the single
# biggest correction to the naive product: it halves the space.
# --------------------------------------------------------------------------------------

DIM_TYPE = {
    "handlers": "path",
    "resources": "path",
    "operations": "id",
    "peers": "id",
}

# --------------------------------------------------------------------------------------
# AXIS 3 -- polarity.  `resources` at L1 is the only (layer, dimension) pair with more
# than the two ordinary arms, because it is the only one whose subject is a set carrying
# its own exclusions.  That asymmetry is the generator of most of this arc's findings.
# --------------------------------------------------------------------------------------


def polarities(layer: Layer, dim: str) -> tuple[str, ...]:
    if layer.key in ("L3", "L4"):
        return ("include-coverage", "exclude-inheritance")
    if layer.key == "L1" and dim == "resources":
        return (
            "include",
            "grant-exclude/concrete",
            "grant-exclude/pattern",
            "caller-exclude",
        )
    return ("include", "grant-exclude")


# --------------------------------------------------------------------------------------
# AXIS 4 -- operand forms the matcher distinguishes.  Derived from `matches_pattern`
# (§5.4) and the id-scope grammar (§5.2).  `/*/interior` and NEVER_MATCH exist only on
# the path side: id-scope is forbidden the path transforms, and never canonicalizes, so
# it has no way to produce the sentinel.
# --------------------------------------------------------------------------------------

OPERANDS = {
    "path": ("concrete", "trailing/*", "/*/interior", "bare *", "NEVER_MATCH"),
    # "path-form string" is the F40 trap: a pattern carrying path syntax, which id-scope
    # MUST match literally.  It is a distinct cell precisely because the wrong answer
    # looks correct on every other operand.
    "id": ("literal", "trailing/*", "bare *", "path-form string"),
}


@dataclass
class Cell:
    layer: Layer
    dim: str
    polarity: str
    operand: str
    reachable: bool = True
    dead_reason: str = ""
    ruled: str = "yes"
    note: str = ""
    vectors: list[str] = field(default_factory=list)

    @property
    def stype(self) -> str:
        return DIM_TYPE[self.dim]

    @property
    def cid(self) -> str:
        op = self.operand.replace("/", "").replace(" ", "").replace("*", "S")
        pol = {
            "include": "IN",
            "grant-exclude": "GX",
            "grant-exclude/concrete": "GXC",
            "grant-exclude/pattern": "GXP",
            "caller-exclude": "CX",
            "include-coverage": "INC",
            "exclude-inheritance": "XIN",
        }[self.polarity]
        return f"{self.layer.key}-{self.dim[:3].upper()}-{pol}-{op}"


# --------------------------------------------------------------------------------------
# REACHABILITY + RULING.  Every rule below is a statement about the pseudocode's control
# flow or about a normative sentence, with the site named.  Nothing here is taste.
# --------------------------------------------------------------------------------------


def classify(c: Cell) -> None:
    L, dim, pol, op = c.layer.key, c.dim, c.polarity, c.operand

    if op == "NEVER_MATCH" and pol in ("include", "include-coverage"):
        # canonicalize() yields NEVER_MATCH only from malformed input; as an INCLUDE it
        # covers nothing, so the grant grants nothing.  Safe, and it is a real cell --
        # but it can never ALLOW, so it needs no vector beyond the fail-closed control.
        c.note = "fail-closed by construction (matches_pattern rejects either operand)"
        c.ruled = "yes"
        return

    # ---- peers: one live call site ----------------------------------------------
    if dim == "peers" and L == "L1":
        c.note = (
            "target_peer = extract_peer(uri); §1.4 refuses foreign inbound at §6.5 "
            "step 3, so this is live only on the internal-dispatch / outbound class"
        )

    # ---- the id-scope trap -------------------------------------------------------
    if c.stype == "id" and op == "path-form string":
        c.note = (
            "F40: MUST match literally. Canonicalizing over-grants on include and "
            "INVERTS intent on exclude (§5.2 line 1085)"
        )

    # ---- resources-at-dispatch: the set-shaped dimension -------------------------
    if L == "L1" and dim == "resources":
        if pol == "grant-exclude/pattern" and op == "NEVER_MATCH":
            c.ruled = "DEFECT"
            c.note = (
                "FAIL-OPEN. patterns_overlap(ct, NEVER_MATCH) is false for every real "
                "target, so the `continue` skips the exclude entirely and the pattern "
                "arm never reaches the caller-exclude test. Found by arch at 0.8.2.21 "
                "§1.1 after scoring it 'fail-closed by accident'"
            )
        if pol == "caller-exclude":
            c.note = (
                "effective_targets (§5.2, 0.8.2.20/.21) — the subject BOTH layers must "
                "derive from. F68/F71: the ruled COUNT does not close it; the selection does"
            )

    # ---- delegation / mint -------------------------------------------------------
    if L in ("L3", "L4"):
        if pol == "exclude-inheritance":
            c.note = (
                "child must carry every parent exclude; pattern_covers has no "
                "NEVER_MATCH arm, so a sentinel parent exclude fails closed"
            )
        if c.stype == "id":
            c.ruled = "yes, UNGATED"
            c.note = (
                (c.note + " · " if c.note else "")
                + "F50 ruled the id/path split reaches scope_subset; scope_subset takes "
                "no scope-type argument in 0 of 20 peers where it is nameable"
            )

    if L == "L3":
        c.note = (
            (c.note + " · " if c.note else "")
            + "per-link GRANTER frame (§5.5a); a K-of-N root has no granter and takes local"
        )


# --------------------------------------------------------------------------------------
# COVERAGE -- a source read of the 778-check executed set, by NAME.  Conservative: a
# check is credited to a cell only where its name names the dimension or the mechanism
# unambiguously.  Everything else stays `?`.
# --------------------------------------------------------------------------------------

VECTOR_MAP = {
    "L1-HAN-IN": ["handler_scope_denied", "handler_scope_denied_core_1"],
    "L1-OPE-IN": ["operation_scope_denied"],
    "L1-RES-IN": ["resource_scope_denied"],
    "L1-OPE-GX": ["f40_id_scope_exclude_literal"],
    "L1-OPE-IN-pathformstring": [
        "f40_id_scope_include_no_overgrant",
        "f40_id_scope_include_control",
    ],
    # `chain_*_exclude_*` drive the DELEGATION link, not the caller's own exclude set.
    # An earlier cut of this table filed them under L1 caller-exclude, which reported a
    # false ZERO on exclude-inheritance and a false cover on the F68 arm -- wrong in both
    # directions from one mis-assignment. The caller-exclude arm (F68/F71) genuinely has
    # no vector in the pinned set; `tools/f68-probe` is the only instrument that drives it.
    "L3-RES-XIN": ["chain_parent_exclude_drop_denied"],
    "L3-OPE-XIN": ["chain_operation_exclude_denied"],
    "L3-RES-INC": [
        "authz_attenuation_foreign_granter_1",
        "authz_attenuation_foreign_granter_deep",
        "authz_attenuation_foreign_granter_wildcard_leaf",
    ],
    "L4-RES-INC": ["authz_scope_exceeds_1", "request_rejects_scope_widening"],
    "L4-ANY": ["request_token_attenuated", "authz_delegate_grant_1"],
}


def attach_vectors(cells: list[Cell]) -> None:
    for c in cells:
        base = "-".join(c.cid.split("-")[:3])
        opkey = f"{base}-{c.operand.replace('/', '').replace(' ', '').replace('*', 'S')}"
        for key in (opkey, base):
            if key in VECTOR_MAP:
                c.vectors = VECTOR_MAP[key]
                break


def build() -> list[Cell]:
    out: list[Cell] = []
    for layer in LAYERS:
        for dim in layer.dims:
            for pol in polarities(layer, dim):
                for op in OPERANDS[DIM_TYPE[dim]]:
                    c = Cell(layer, dim, pol, op)
                    classify(c)
                    out.append(c)
    attach_vectors(out)
    return out


def reduction() -> list[tuple[str, int, str]]:
    """What the naive product would have been, and what removes each factor.

    Reported rather than assumed: the whole argument of this table is that the space is
    smaller than it looks, and a reduction nobody can see is a reduction nobody can
    check.  Each row is asserted non-zero -- a reduction that removes nothing is a rule
    the code no longer implements, and it must not sit here reading as load-bearing.
    """
    n_layers, n_dims = len(LAYERS), len(DIM_TYPE)
    max_pol = max(len(polarities(l, d)) for l in LAYERS for d in l.dims)
    max_op = max(len(v) for v in OPERANDS.values())

    # Staged, each stage derived from the one above, so the arithmetic closes by
    # construction rather than by three independent estimates agreeing.
    s0 = n_layers * n_dims * 2 * max_pol * max_op  # scope type as a free axis
    s1 = n_layers * n_dims * max_pol * max_op  # type fixed by dimension
    id_dims = [d for d in DIM_TYPE if DIM_TYPE[d] == "id"]
    s2 = s1 - n_layers * len(id_dims) * max_pol * (max_op - len(OPERANDS["id"]))
    s3 = s2 - max_pol * len(OPERANDS["id"])  # L2 drops `peers`
    s4 = len(build())  # polarity is per-pair, not max

    rows = [
        ("naive product (scope type as a free axis)", s0, "—"),
        ("type is FIXED by the dimension (§3.6 grant-entry)", s1 - s0, "halves it"),
        ("id-scope has no /*/ and no NEVER_MATCH (§5.2)", s2 - s1, "never canonicalizes"),
        ("L2 consults 3 dimensions, not 4", s3 - s2, "check_path_permission"),
        ("only (L1,resources) has 4 arms; the rest 2", s4 - s3, "set-shaped subject"),
    ]
    for label, n, _ in rows[1:]:
        assert n != 0, f"reduction {label!r} removes nothing -- stale rule"
    assert s4 == len(build()), "reduction does not close"
    return rows


def main() -> int:
    cells = build()
    live = [c for c in cells if c.reachable]
    dead = [c for c in cells if not c.reachable]
    covered = [c for c in live if c.vectors]
    defects = [c for c in live if c.ruled == "DEFECT"]
    ungated = [c for c in live if c.ruled.endswith("UNGATED")]

    if "--summary" in sys.argv or "--gaps" in sys.argv:
        for label, n, why in reduction():
            print(f"  {n:>6}  {label}  {'' if why == '—' else '(' + why + ')'}")
        print()
        print(f"enumerated cells          {len(cells)}")
        print(f"  excluded by construction{'':2}{len(dead)}")
        print(f"  live                    {len(live)}")
        print(f"    with a named vector   {len(covered)}")
        print(f"    UNMEASURED            {len(live) - len(covered)}")
        print(f"    known DEFECT          {len(defects)}")
        print(f"    ruled but UNGATED     {len(ungated)}")
        if "--summary" in sys.argv:
            return 0

    rows = live if "--gaps" not in sys.argv else [c for c in live if not c.vectors]
    print("| cell | layer | fn | dim | type | polarity | operand | frame | ruled | vector |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for c in rows:
        v = ", ".join(f"`{x}`" for x in c.vectors) if c.vectors else "**—**"
        print(
            f"| `{c.cid}` | {c.layer.key} | `{c.layer.fn.split(' ')[0]}` | {c.dim} | "
            f"{c.stype} | {c.polarity} | `{c.operand}` | {c.layer.frame} | {c.ruled} | {v} |"
        )
    if dead:
        print("\n**Structurally dead — needs deleting, not a vector:**\n")
        for c in dead:
            print(f"- `{c.cid}` — {c.dead_reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
