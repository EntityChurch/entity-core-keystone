# entity-core-protocol-odin — build / test / dist (container-bound; sealed-offline).
# The `odin` compiler IS the build system (no external build tool). A package is a directory
# of .odin files. Every build/test runs inside the pinned odin-toolchain Podman image; the
# core peer pulls ZERO third-party packages, so every run is --network=none.
#
#   make build   # compile the peer host  → bin/entity-core-peer
#   make test    # odin test test (71-vector codec + head-form + Ed25519 KATs + peer units)
#   make smoke   # two Odin peers over loopback TCP — the only driver of this peer's dialer
#   make dist    # source tarball (no compiled binaries) → dist/entity-core-protocol-odin-<V>.tar.gz
#   make clean   # remove build artifacts (bin/*, dist/)

# Container plumbing (profile [container].dev_loop). Overridable for a native run.
IMAGE     ?= entity-core-keystone/odin-toolchain:latest
REPO_ROOT := $(abspath ../..)
WORKDIR   := /work/protocol-generator/odin
PODMAN    ?= podman
# Cap every podman run per RESOURCE-CAPS.md — source PODMAN_RUN_CAPS if present, else empty.
RUN_CAPS  ?= $(shell . $(REPO_ROOT)/tools/podman-caps.sh 2>/dev/null && echo $$PODMAN_RUN_CAPS)
RUN        = $(PODMAN) run $(RUN_CAPS) --rm --network=none -v "$(REPO_ROOT)":/work:Z -w $(WORKDIR) $(IMAGE) sh -c

.PHONY: all build test check smoke clean dist

all: test

# ── Build: compile the peer host (odin build; a package is a directory of .odin files). ──
build:
	$(RUN) 'odin build host -out:bin/entity-core-peer -o:speed'

# ── Test: the S2 codec gate + head-form + Ed25519 KATs + the S3 peer accept-path units, ──
# all leak-checked under mem.Tracking_Allocator (odin test = core:testing in-language runner).
test:
	$(RUN) 'odin test test'

# ── Check: type-check without codegen (odin check; no separate ecosystem linter at core). ──
check:
	$(RUN) 'odin check src'

# ── Smoke: two Odin peers over real loopback TCP (§4.1 handshake both directions, §6.5 ──
# dispatch, §6.11 request_id demux), leak-checked. This is the ONLY thing in the tree that
# drives this peer's own DIALER — `initiate()` in src/transport.odin — because the
# conformance oracle is always the client and its origination check reuses the inbound
# connection rather than making us dial. `smoke/` was already copied into the source
# tarball by `make dist` and had no build or run target, so it had never been executed by
# anything: a §4.5 defect in the hello we SEND was invisible to every gate. Verified to
# have teeth by planting one (empty hello params → SMOKE: FAIL).
smoke:
	$(RUN) 'odin build smoke -out:bin/smoke -o:none && ./bin/smoke'

# ── S5 packaging ──
# Odin has NO package manager and NO module system — a peer is a directory of .odin files a
# consumer vendors (git subtree / tag pin). So "the package" is a source tarball of the .odin
# tree + host/ + smoke/ + test/ + status/ + arch/ + the run scripts + README/CHANGELOG/LICENSE.
# NO compiled binaries ship — the consumer builds with their pinned Odin toolchain. A source
# distribution (mirrors the Forth/COBOL/Rexx `make dist` convention).
VERSION  ?= 0.1.0-pre
DISTNAME := entity-core-protocol-odin-$(VERSION)
DISTDIR  := dist/$(DISTNAME)
dist:
	rm -rf $(DISTDIR) dist/$(DISTNAME).tar.gz
	mkdir -p $(DISTDIR)/src $(DISTDIR)/host $(DISTDIR)/smoke $(DISTDIR)/test $(DISTDIR)/status $(DISTDIR)/arch
	cp src/*.odin $(DISTDIR)/src/
	cp host/*.odin $(DISTDIR)/host/
	cp smoke/*.odin $(DISTDIR)/smoke/
	cp test/*.odin $(DISTDIR)/test/
	cp status/PHASE-S*.md status/CONFORMANCE-REPORT.md status/CONFORMANCE-REPORT-S2.md status/SPEC-AMBIGUITY-LOG.md $(DISTDIR)/status/ 2>/dev/null || true
	cp arch/*.md $(DISTDIR)/arch/ 2>/dev/null || true
	cp Makefile profile.toml run-s2.sh run-s4.sh $(DISTDIR)/
	cp README.md CHANGELOG.md LICENSE $(DISTDIR)/
	tar czf dist/$(DISTNAME).tar.gz -C dist $(DISTNAME)
	rm -rf $(DISTDIR)
	@echo "dist: dist/$(DISTNAME).tar.gz  (source .odin tree; no binaries; VERSION=$(VERSION))"

clean:
	rm -rf dist bin/entity-core-peer bin/smoke
