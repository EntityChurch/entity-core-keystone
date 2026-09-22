# entity-core-keystone — toolchain images (make + podman).
#
# Keystone is the multi-language peer generator: there is no single build
# artifact. All build/test/conformance work for a given language profile runs
# inside that language's pinned toolchain image (see containers/README.md).
# This Makefile is the discoverable `make` wrapper over the per-toolchain
# `podman build` commands the README documents. Host needs only make + podman.
#
# Build context is the repo root (.) — Containerfiles reference paths into
# ../protocol-generator/, ../ffi-generator/, etc.
REG := entity-core-keystone

# Toolchain list is auto-derived from containers/*/Containerfile so it can never
# drift behind the on-disk container dirs (it had — 13 toolchains were missing
# from a hand-maintained list). `make <name>` works for every dir that has a
# Containerfile; `make images` builds them all.
TOOLCHAINS := $(sort $(notdir $(patsubst %/Containerfile,%,$(wildcard containers/*/Containerfile))))

# ============================================================================
# Podman resource caps — entity-systems standard ([internal]/docs/
# release-readiness/RESOURCE-CAPS.md). Per-container ceilings so a build can't
# take the host down. Tune the COMMITTED defaults for THIS project; override
# per-machine WITHOUT editing this file via env vars or an untracked
# caps.local.mk.
#
#   Precedence (highest first):  env var  >  caps.local.mk  >  defaults below
#   CAP_SWAP == CAP_MEM  =>  zero swap: container is OOM-killed cleanly at the
#   cap instead of thrashing the host into a freeze.
#
# Sizing: the release gate `make build` (the base image, a dnf transaction)
# measured a ~1.0 GB cgroup peak (513 MB process RSS + page cache) on
# 2026-06-19. The committed default is sized to ALSO cover the heavier
# per-language toolchain image builds that share this cap — the JVM/Gradle
# (kotlin/java) and large-SDK (swift/ghc/lean) builds run well above the base
# gate — so `make <any-toolchain>` doesn't false-OOM out of the box. A base-
# only cloner can lower CAP_MEM; a heavy multi-toolchain build can raise it.
# Both via caps.local.mk (§4a of RESOURCE-CAPS.md) — no edit to this file.
# ============================================================================
-include caps.local.mk          # untracked per-machine overrides (gitignored)

CAP_MEM           ?= 4g         # hard memory ceiling per container
CAP_SWAP          ?= $(CAP_MEM) # keep == CAP_MEM (no swap); raise only deliberately
CAP_PIDS          ?= 2048       # max procs/threads (RUN only) — stops fork bombs
CAP_CPUS          ?= 4          # CPU cores at runtime (RUN only; fractional ok)
CAP_CGROUP_PARENT ?=            # optional host slice to nest under, e.g. dev-heavy.slice

_cap_cgp := $(if $(strip $(CAP_CGROUP_PARENT)),--cgroup-parent=$(CAP_CGROUP_PARENT),)

# $(strip ...) defends against trailing whitespace from the aligned comments above.
_cap_mem  := $(strip $(CAP_MEM))
_cap_swap := $(strip $(CAP_SWAP))
_cap_pids := $(strip $(CAP_PIDS))
_cap_cpus := $(strip $(CAP_CPUS))

# podman BUILD accepts --memory/--memory-swap/--cgroup-parent (NOT --cpus/--pids-limit)
PODMAN_BUILD_CAPS := --memory=$(_cap_mem) --memory-swap=$(_cap_swap) $(_cap_cgp)
# podman RUN accepts the full set (for any future `make` run target; the per-
# language conformance run-scripts under protocol-generator/<lang>/ invoke
# `podman run` directly and can source these via the same env vars).
PODMAN_RUN_CAPS   := --memory=$(_cap_mem) --memory-swap=$(_cap_swap) \
                     --pids-limit=$(_cap_pids) --cpus=$(_cap_cpus) $(_cap_cgp)

.PHONY: build images images-cold images-audit caps test lint fmt check clean help $(TOOLCHAINS)

.DEFAULT_GOAL := help

# ADR-0019 Tier-1 verbs. keystone is a multi-language *generator*: there is no
# single root artifact, and all real build/test/format work happens per-toolchain
# INSIDE each container (driven by /entity-rosetta + the wire-conformance /
# validate-peer oracles, see AGENTS.md). The root verbs below are therefore thin
# and honest: `build` is the base substrate image, `test` is the substrate smoke,
# `lint` is the one cheap read-only check the root genuinely owns (it verifies the
# SHA-256-pinned spec-data snapshot — every peer's normative source of truth), and
# `fmt` is a deliberate no-op (generated source is formatted by its own toolchain,
# and a blind root autoformat would corrupt that same byte-pinned spec-data).
help:
	@echo "entity-core-keystone — make + podman (host needs only make + podman)"
	@echo
	@echo "  build    build the shared base toolchain image (the release gate)"
	@echo "  images   build every per-toolchain image"
	@echo "  images-cold   rebuild EVERY image with --no-cache (what a clean pull does)"
	@echo "  images-audit  network audit: every pinned RPM still resolves, digests match,"
	@echo "                and each pin group carries its version-locked siblings"
	@echo "  <name>   build one toolchain image, e.g. 'make go' / 'make lean-toolchain'"
	@echo "  test     substrate smoke (base image builds); per-language conformance"
	@echo "           runs per-toolchain via /entity-rosetta + the oracles"
	@echo "  lint     read-only integrity gate: verify the SHA-256-pinned spec-data"
	@echo "           snapshot(s); generated peers are linted per-toolchain, in-container"
	@echo "  fmt      no-op at root — generated src is formatted by its own toolchain;"
	@echo "           spec-data is byte-pinned and MUST NOT be reformatted"
	@echo "  check    lint + test — STATIC ONLY; verifies no peer behaviour"
	@echo "  gate     THE gate: lint + S2 + S3 + the S4 census,"
	@echo "           one command, one verdict (~2-4 h, census-dominated)"
	@echo "  gate-sweeps   the fast three axes, no census — reports INCOMPLETE"
	@echo "  clean    remove every built keystone toolchain image"
	@echo "  caps     print the resolved resource caps + toolchain list"

# Default = the shared base image everything else layers on (the release gate).
build: base

# Build every toolchain image.
images: $(TOOLCHAINS)

# Build every image FROM SCRATCH. This is the only target that asks the question an
# adopter asks, because the layer cache and the already-present local images hide a
# broken recipe from the machine that authored it. Run before a release and whenever
# containers/ changes. Slow by design (~35 min; source-building images dominate).
images-cold:
	@tools/cold-build-gate.sh

# Network audit of the pins themselves, without building anything: every recorded RPM
# still resolves from Koji's permanent archive, still hashes to the recorded digest,
# and every pin group carries its version-locked siblings. That last one is not
# pedantry -- pinning `rust` without `rust-std-static` at the same NVR builds fine
# until the rolling repo moves past it, then fails in a way indistinguishable from rot.
images-audit:
	@python3 tools/koji-pin.py verify
	@python3 tools/koji-pin.py closure

# Per-toolchain image, e.g. `make go`, `make dotnet9`, `make zig-toolchain`.
$(TOOLCHAINS):
	podman build $(PODMAN_BUILD_CAPS) -t $(REG)/$@:latest -f containers/$@/Containerfile .

# Show the resolved caps + toolchain list (debug aid).
caps:
	@echo "TOOLCHAINS       = $(TOOLCHAINS)"
	@echo "CAP_MEM          = $(CAP_MEM)"
	@echo "CAP_SWAP         = $(CAP_SWAP)"
	@echo "CAP_PIDS         = $(CAP_PIDS)"
	@echo "CAP_CPUS         = $(CAP_CPUS)"
	@echo "PODMAN_BUILD_CAPS= $(PODMAN_BUILD_CAPS)"
	@echo "PODMAN_RUN_CAPS  = $(PODMAN_RUN_CAPS)"

# --- ADR-0019 Tier-1 verbs (thin/honest for a generator — see help) ---------
# test = the base substrate builds; real conformance is per-language (oracles).
test: build
	@echo "--- base substrate built (root 'test' smoke) ---"
	@echo "Per-language conformance is per-toolchain: build one with 'make <lang>',"
	@echo "then run its peer against wire-conformance + validate-peer via the"
	@echo "/entity-rosetta --phase verify pipeline (see protocol-generator/<lang>/)."

# lint = read-only static check. keystone has no host-lintable *sources* (every
# generated peer is linted inside its own toolchain image), but the one root-level
# invariant that IS cheaply checkable read-only is the SHA-256-pinned spec-data
# snapshot — the immutable normative inputs every peer derives from. We re-hash the
# files and check them against the per-snapshot MANIFEST.md pin table. This never
# writes (it *enforces* the spec-data immutability boundary rather than risking it)
# and uses only stock tools (awk + sha256sum). A drifted/edited spec file fails here.
lint:
	@echo "lint: verifying SHA-256-pinned spec-data snapshot(s) (read-only)…"
	@set -e; any=; \
	for m in protocol-generator/shared/spec-data/*/MANIFEST.md; do \
	  [ -e "$$m" ] || continue; any=1; d=$$(dirname "$$m"); \
	  sums=$$(awk '{ fn=""; sha=""; \
	    if (match($$0, /[A-Za-z0-9._-]+\.md/)) fn=substr($$0,RSTART,RLENGTH); \
	    if (match($$0, /[0-9a-f]{64}/))        sha=substr($$0,RSTART,RLENGTH); \
	    if (fn!="" && sha!="") print sha"  "fn }' "$$m"); \
	  [ -n "$$sums" ] || { echo "  ERROR: no SHA-256 pins parsed from $$m" >&2; exit 1; }; \
	  ( cd "$$d" && printf '%s\n' "$$sums" | sha256sum -c - ) || exit 1; \
	done; \
	[ -n "$$any" ] || { echo "  ERROR: no spec-data MANIFEST found" >&2; exit 1; }; \
	echo "lint: spec-data integrity OK (peers are linted per-toolchain, in-container)"
	@echo "lint: gating COMMITTED per-peer conformance reports (read-only)…"
	@# The second root-level invariant that is cheaply checkable read-only: a peer we
	@# publish as 0-FAIL must have a COMMITTED status/CONFORMANCE-REPORT.json measured
	@# on the pinned check set. Until 2026-08-22 nothing looked at these files and all
	@# 45 had drifted a full oracle pin behind CONFORMANCE-MATRIX.md §1 — a clone showed
	@# each peer contradicting its own published row. Peers still owing the CAP fix are
	@# reported but do not fail the gate (disclosed debt, matrix §3); the gated set is
	@# the publishable one, so this can only ratchet tighter.
	@python3 tools/check-set-gate.py --tracked --quiet
	@echo "lint: gating PUBLISHED conformance anchors (read-only)…"
	@# Third root-level invariant. A published number must be anchored by a digest of
	@# the oracle's content, not by a commit: [ADR-0027] authors published commits fresh
	@# at the release boundary, so a dev SHA resolves for no outside reader. We learned
	@# this on 2026-07-10 when go's mirror rewrote history and killed the pinned e8524ed,
	@# built core_gate_fingerprint in response, and then left the documents citing the
	@# commit for six more weeks. This gate watches the two ways the content anchor stops
	@# being trustworthy: the §1 pin column reverting to a commit, and a hand-copied
	@# 64-hex digest drifting from tools/oracle-pin.env (which no human proofreads).
	@python3 tools/pin-gate.py --quiet
	@echo "lint: gating relative link integrity (read-only)…"
	@# Fourth root-level invariant, and the first one about the tree rather than about a
	@# number. Nine gates run across this repo and the release pipeline; not one of them
	@# asked whether a published document points at something a reader can open. Measured
	@# 2026-08-23: protocol-generator/fortran/status/ had cited two findings at paths that
	@# had not existed since those findings were archived weeks earlier, dangling out of a
	@# published file past every gate. This is the cheap floor only — it sees markdown
	@# links, not backticked paths, wrapped fragments, or a path a tool prints at runtime.
	@# The hand-walk of the published tree stays mandatory (AGENTS.md).
	@python3 tools/link-gate.py --quiet
	@echo "lint: gating internal coherence of published numbers (read-only)…"
	@# Sixth root-level invariant, and the one the other five structurally cannot see.
	@# check-set-gate asks whether numbers are COMPARABLE, pin-gate whether anchors
	@# RESOLVE, link-gate whether links reach real FILES — all three pass a tree in which
	@# CONFORMANCE-MATRIX.md §1 publishes 595P/54W for a peer whose own committed report
	@# says 313P/336W. Every documentation defect found in the two weeks before this gate
	@# existed was found by walking the tree BY HAND with `make lint` green throughout.
	@# Gates the 46 §1 rows and the 46 per-peer prose banners against the committed
	@# reports; reports (does not gate) superseded figures quoted elsewhere in prose,
	@# because this repo keeps those deliberately as evidence. Regression suite:
	@# `python3 tools/coherence-gate.py --self-test`. The hand-walk stays mandatory.
	@python3 tools/coherence-gate.py --quiet
	@echo "lint: gating container recipe reproducibility (read-only, offline)…"
	@# Fifth root-level invariant. Every image in containers/ is a recipe an adopter has
	@# to be able to run, and until 2026-08-27 nothing asked whether they still could:
	@# 36 of 46 images pinned RPMs against rolling dnf repos (which drop an NVR the moment
	@# it is superseded — eleven images died at once on 2026-07-27, `clang` twice in one
	@# day), 45 of 46 floated on an unpinned base tag that had already moved, and three
	@# fetched and ran remote artifacts with no digest check at all. The old policy was
	@# explicitly reactive — convert a package to Koji only after it breaks — which is a
	@# policy of waiting to be broken. These three properties are checkable offline, so
	@# they run every lint; whether the pins still RESOLVE and whether the images still
	@# BUILD need the network and live in `make images-audit` / `make images-cold`.
	@python3 tools/containers-gate.py --quiet
	@echo "lint: gating peer-harness structure (read-only)…"
	@# Seventh root-level invariant, and the first about the HARNESS rather than about a
	@# number or a document. Two properties of every run-s4.sh, both cohort-wide defects
	@# found 2026-09-02, both invisible to the six gates above, and both failing in the
	@# direction where the harness still reports success.
	@#   TEARDOWN WAITS. 45 of 46 tore the peer down with a fire-and-forget
	@#   `trap 'kill "$$HOST_PID" ...'`: kill(1) delivers the signal and returns, so the
	@#   script exited while the peer still owned the listening socket. Measured, port
	@#   still ACCEPTING after the harness had exited — rexx never released it, elixir
	@#   >400ms (and the next run in that container exited 1), julia ~88ms, smalltalk
	@#   ~4ms, zig and go 0ms. The two peers anyone reaches for first are the two that do
	@#   not show it, which is exactly why this is a gate and not a fix.
	@#   CALLER ARGS REACH THE ORACLE. python/ruby/prolog hardcoded their argument list,
	@#   so `run-s4.sh -category connectivity` ran the whole 756-check suite AND rewrote
	@#   the tracked, signed-off report it was meant to be diagnosed against.
	@# Regression suite: `python3 tools/harness-gate.py --self-test`.
	@python3 tools/harness-gate.py --quiet
	@echo "lint: gating the B-role reference peer in every harness (read-only)…"
	@# The ninth gate. `--profile core` alone executes 756 checks; with -reference-peer
	@# it executes 758, and the three it adds are the WHOLE origination axis. The census
	@# never passed the flag, which is the only reason a separate run-origination-core.sh
	@# existed on 31 peers and was ABSENT on 15 — an axis that was a workaround for an
	@# unpassed flag, and 15 peers with no coverage of it at all.
	@# This gates the property rather than the edit: each harness must source the shared
	@# helper, bring the reference up, pass $$REFPEER_FLAG to the oracle, and reap it from
	@# its existing teardown. A peer that regresses any of the four drops back to 756 and
	@# its number stops being comparable — silently, which is the failure mode this whole
	@# fold exists to end.
	@python3 tools/fold-reference-peer.py --check
	@echo "lint: gating skip provenance — every SKIP explained (read-only)…"
	@python3 tools/skip-provenance-gate.py

# fmt = autoformat (writes). Intentionally a no-op: generated source is formatted
# by its own toolchain, and spec-data/<version>/ is a SHA-256-pinned immutable
# snapshot that MUST NOT be reformatted. Running a formatter here would be unsafe.
fmt:
	@echo "no root autoformat — generated src is formatted per-toolchain, and"
	@echo "spec-data is byte-pinned (reformatting it would break the SHA-256 pins)."

# check = the green gate (lint + test).
check: lint test

# gate = THE gate. Every verification axis, one command, one verdict.
#
# There is no "re-run S2" or "re-run S3" as a separate act. `check` above is a
# static gate only -- `test` prints a paragraph and verifies nothing -- and until
# 2026-09-03 there was no target at all that ran the verification. That is how a
# tree publishing 46 of 46 at `756 · 0F` was simultaneously carrying 21 failures
# on two axes nobody swept.
#
# Runs: lint, S2 (arch's vendored fixture corpora), S3 (our loopback smoke),
# and the S4 conformance census -- which since 2026-09-03 passes -reference-peer
# and therefore carries the three origination checks that used to need their own
# harness. Sequentially -- concurrent containers relabel each other's :Z mount
# and manufacture false REDs.
#
# ~2-4 h, dominated by the census. `make gate-sweeps` is the fast three and
# announces itself as INCOMPLETE, because it is not the gate.
gate:
	@tools/run-gate.sh

gate-sweeps:
	@tools/run-gate.sh --sweeps-only

# clean = remove every built keystone toolchain image (base + per-language).
clean:
	-@for t in $(TOOLCHAINS); do podman rmi $(REG)/$$t:latest 2>/dev/null || true; done
	@echo "--- removed keystone toolchain images (any that were built) ---"
