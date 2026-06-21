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

.PHONY: build images caps test lint fmt check clean help $(TOOLCHAINS)

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
	@echo "  <name>   build one toolchain image, e.g. 'make go' / 'make lean-toolchain'"
	@echo "  test     substrate smoke (base image builds); per-language conformance"
	@echo "           runs per-toolchain via /entity-rosetta + the oracles"
	@echo "  lint     read-only integrity gate: verify the SHA-256-pinned spec-data"
	@echo "           snapshot(s); generated peers are linted per-toolchain, in-container"
	@echo "  fmt      no-op at root — generated src is formatted by its own toolchain;"
	@echo "           spec-data is byte-pinned and MUST NOT be reformatted"
	@echo "  check    lint + test (the green gate)"
	@echo "  clean    remove every built keystone toolchain image"
	@echo "  caps     print the resolved resource caps + toolchain list"

# Default = the shared base image everything else layers on (the release gate).
build: base

# Build every toolchain image.
images: $(TOOLCHAINS)

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

# fmt = autoformat (writes). Intentionally a no-op: generated source is formatted
# by its own toolchain, and spec-data/<version>/ is a SHA-256-pinned immutable
# snapshot that MUST NOT be reformatted. Running a formatter here would be unsafe.
fmt:
	@echo "no root autoformat — generated src is formatted per-toolchain, and"
	@echo "spec-data is byte-pinned (reformatting it would break the SHA-256 pins)."

# check = the green gate (lint + test).
check: lint test

# clean = remove every built keystone toolchain image (base + per-language).
clean:
	-@for t in $(TOOLCHAINS); do podman rmi $(REG)/$$t:latest 2>/dev/null || true; done
	@echo "--- removed keystone toolchain images (any that were built) ---"
