# entity-core-protocol-smalltalk — S2 codec build + conformance (container-bound; run-s2.sh).
# Pure-Smalltalk canonical CBOR (the PURE-OBJECT / MESSAGE-PASSING probe: a value is a tagged
# EcValue object, the codec is a polymorphic encodeOn: double-dispatch) + base58/varint/
# peer_id; crypto via the codec C-ABI (libentitycore_codec) bound with Pharo's in-process
# UFFI (ffiCall:module:). SUnit (bundled) is the test framework.
#
# LIVE-IMAGE MODEL: "build" = load the Tonel-ish src/*.st doits into a fresh base image and
# snapshot a peer .image (there is no AOT binary). The test drivers then eval against that
# saved peer image, where the classes are compile-time visible. These recipes run INSIDE the
# pharo-toolchain container (run-s2.sh drives podman); on the host `pharo` is not present.

PHARO       ?= pharo --headless
BASEIMG     := /opt/pharo/image
CODEC_SRC   := ../../ffi-generator/c-abi/entity-core-codec-ffi-c
CODEC_BUILD := $(CODEC_SRC)/build
CODEC_SO    := $(CODEC_BUILD)/libentitycore_codec.so
CORPUS      := ../shared/test-vectors/ecf-conformance/conformance-vectors.cbor
PEERIMG     := entity-core.image

# UFFI dlopen's the codec .so by soname → it must be on LD_LIBRARY_PATH at run time.
FFI_ENV = LD_LIBRARY_PATH=$(abspath $(CODEC_BUILD)):$$LD_LIBRARY_PATH EC_CORPUS=$(CORPUS)

.PHONY: all gate test int-boundary crypto-accept sunit ffi image clean dist s3 selftest smoke multisig-accept

all: gate

# The full S2 gate: corpus conformance (69) + int boundary + crypto accept-path.
gate: test int-boundary crypto-accept

# ── S3 peer machinery gate ──
# The peer-layer foundation self-test (units the loopback + a rejection-only oracle can't
# cover: identity, store, N5 envelope, §4.10(a)/(b) floor, §6.11 demux) + the two-peer
# loopback smoke (handshake both ways + 404 + request_id demux). Both run against the
# snapshotted peer image (A-ST-010). Loopback 127.0.0.1 works under --network=none.
s3: selftest smoke

selftest: image
	$(FFI_ENV) $(PHARO) ./$(PEERIMG) eval "$$(cat tests/s3-selftest.st)"

smoke: image
	$(FFI_ENV) bash tests/smoke.sh

# Build the codec C-ABI (libentitycore_codec) if absent — its CMake, offline (libsodium is
# in the toolchain image). Provenance via ec_impl_info().
ffi: $(CODEC_SO)
$(CODEC_SO):
	cd $(CODEC_SRC) && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build >/dev/null

# Load the src/*.st doits into a fresh base image + the SUnit test class; snapshot a peer
# .image. Depends on the codec .so (UFFI warms on first crypto call). Deliberately does NOT
# bake EcCapAuthzTest into this snapshot: this is the SAME image run-s4.sh boots the
# conformance peer from (bin/peer.st), so keeping it byte-for-byte what it was before the
# 2026-08-13 peers-dimension fix means zero risk of a test-only class perturbing peer boot.
# `sunit` below loads EcCapAuthzTest JIT, on top of this same snapshot, at test-run time.
image: ffi $(PEERIMG)
$(PEERIMG): load.st $(wildcard src/*/*.st) tests/EntityCore-Tests/EcCodecTest.st
	rm -f $(PEERIMG) entity-core.changes *.sources
	cp $(BASEIMG)/*.image ./$(PEERIMG)
	cp $(BASEIMG)/*.changes ./entity-core.changes
	cp $(BASEIMG)/*.sources . 2>/dev/null || true
	$(FFI_ENV) $(PHARO) ./$(PEERIMG) eval "Smalltalk compiler evaluate: (FileLocator workingDirectory / 'load.st') contents. Smalltalk compiler evaluate: (FileLocator workingDirectory / 'tests/EntityCore-Tests/EcCodecTest.st') contents. Smalltalk snapshot: true andQuit: false. 'built'"
	@$(MAKE) --no-print-directory load-verify

# Assert the load POSTCONDITION rather than reading the loader's diagnostics.
# The recipe above used to pipe through `grep -vi 'undeclared\|warning' || true`.
# That was unsound in both halves: the `||true` swallowed a failing load, and the
# filter hid the one diagnostic that matters. Pharo emits benign forward-reference
# `NewUndeclaredWarning`s during a dependency-ordered file-in (EcMapEntry,
# EcConnection — defined later in load order), and a class that genuinely failed
# to compile produces a warning that looks EXACTLY the same. There is no way to
# tell them apart by reading the text, so this asks the tree instead: every class
# the sources install must be present in the snapshotted image. A typo'd or
# uncompilable class is caught by ABSENCE, which is unambiguous.
ST_CLASSES := $(shell grep -ho '<< *#[A-Za-z0-9_]*' src/*/*.st | sed 's/.*#//' | sort -u)
load-verify:
	@$(FFI_ENV) $(PHARO) ./$(PEERIMG) eval "| want missing | \
	  want := #($(ST_CLASSES)). \
	  missing := want reject: [ :n | Smalltalk includesKey: n asSymbol ]. \
	  missing isEmpty \
	    ifTrue: [ 'load-verify: OK — ', want size printString, ' classes present' ] \
	    ifFalse: [ 'load-verify: MISSING ', missing printString ]" \
	  | tee /dev/stderr | grep -q 'load-verify: OK' \
	  || { echo "make: *** load-verify failed — a src/*.st class did not install" >&2; exit 1; }

# Full pinned-corpus conformance gate (69 vectors, byte-identical encode+decode+hash).
test: image
	$(FFI_ENV) $(PHARO) ./$(PEERIMG) eval "$$(cat tests/conformance.st)"

# BIGNUM uint64 boundary self-test [2^63, 2^64-1] + mt1 floor (A-ST-001) — pure codec, no FFI.
int-boundary: image
	$(FFI_ENV) $(PHARO) ./$(PEERIMG) eval "$$(cat tests/int-boundary.st)"

# Crypto accept-path unit test (the direction the rejection-heavy oracle can't cover).
crypto-accept: image
	$(FFI_ENV) $(PHARO) ./$(PEERIMG) eval "$$(cat tests/crypto-accept.st)"

# S4 MULTISIG accept-path unit test (the keystone payoff): a GENUINE 2-of-3 K-of-N cap the
# rejection-only `multisig` oracle category can't cover — asserts M3/M4/M6 ACCEPT + each reject.
multisig-accept: image
	$(FFI_ENV) $(PHARO) ./$(PEERIMG) eval "$$(cat tests/multisig-accept.st)"

# SUnit suite (bundled xUnit) — the first-class TestCase mirror of the drivers, PLUS the
# EcCapAuthz §5.2 `peers`-dimension regression suite (2026-08-13 fix; the oracle has zero
# coverage of this dimension, see the class comment on EcCapAuthzTest). EcCapAuthzTest is
# loaded JIT here, not baked into $(PEERIMG) (see the comment on that recipe above).
#
# Two things this target got wrong for as long as it existed, both of which made
# it report success without measuring anything:
#
#  (a) The second eval both LOADED EcCapAuthzTest and referenced it by global
#      name in ONE doit. Pharo compiles the whole doit before executing any of
#      it, so the reference is undeclared at compile time even though the
#      statement before it would have defined the class — `OCUndeclaredVariable
#      Notice ... Undeclared variable->EcCapAuthzTest`, and the suite never ran.
#      The class must be reached LATE-BOUND (`Smalltalk at: #EcCapAuthzTest`),
#      which compiles to a runtime lookup and therefore sees the just-loaded class.
#  (b) `pharo eval` exits 0 whatever the suite reports, so a red suite printed
#      `failures=3` and the target passed. The counts are now ASSERTED.
sunit: image
	@$(call st_suite,EcCodecTest,)
	@$(call st_suite,EcCapAuthzTest,Smalltalk compiler evaluate: (FileLocator workingDirectory / 'tests/EntityCore-Tests/EcCapAuthzTest.st') contents.)

# $(call st_suite,<TestCase class>,<setup statements>) — run an SUnit suite and
# FAIL unless it reports zero failures and zero errors AND actually ran something.
#
# The `runs=[1-9]` half is not decoration. `buildSuite` on a class whose test
# methods failed to compile — or were renamed out of the `test*` convention —
# answers an EMPTY suite, which reports `runs=0 passes=0 failures=0 errors=0` and
# satisfies a failures/errors-only check perfectly. That is the
# gate-that-examined-zero-things shape: an empty error list is the expected output
# of both a passing check and an absent one, so the COUNT is what has to be
# asserted. Same one-line fix as the XCTest floor in swift/run-s2.sh.
define st_suite
$(FFI_ENV) $(PHARO) ./$(PEERIMG) eval "| r | $(2) \
  r := (Smalltalk at: #$(1)) buildSuite run. \
  '$(1): runs=', r runCount printString, \
  ' passes=', r passedCount printString, \
  ' failures=', r failureCount printString, \
  ' errors=', r errorCount printString" \
  | tee /dev/stderr | grep -qE 'runs=[1-9][0-9]* .*failures=0 errors=0' \
  || { echo "make: *** $(1) SUnit suite is not green, or ran no tests at all" >&2; exit 1; }
endef

# ── S5 packaging (deferred like the cohort; source distribution + Metacello baseline) ──
# Pharo has NO binary package registry — distribution is a git repo + a Metacello baseline. The
# "package" is a source tarball of the Tonel src/ tree + bin + tests + the run/conformance
# scripts + the libentitycore_codec build recipe (a runtime dep, documented, not bundled) + the
# load stub. The saved .image/.changes/.sources are BUILD artifacts (make image regenerates
# them), gitignored + NOT shipped. A source distribution (mirrors COBOL/Rexx/Forth `make dist`).
VERSION  ?= 0.1.0-pre
DISTNAME := entity-core-protocol-smalltalk-$(VERSION)
DISTDIR  := dist/$(DISTNAME)
dist:
	rm -rf $(DISTDIR) dist/$(DISTNAME).tar.gz
	mkdir -p $(DISTDIR)/src $(DISTDIR)/tests $(DISTDIR)/bin $(DISTDIR)/status $(DISTDIR)/arch $(DISTDIR)/.github/workflows
	cp -r src/* $(DISTDIR)/src/
	cp -r tests/* $(DISTDIR)/tests/
	cp bin/*.st $(DISTDIR)/bin/
	cp status/PHASE-S*.md status/CONFORMANCE-REPORT.md status/SPEC-AMBIGUITY-LOG.md $(DISTDIR)/status/ 2>/dev/null || true
	cp arch/*.md $(DISTDIR)/arch/ 2>/dev/null || true
	cp .github/workflows/*.yml $(DISTDIR)/.github/workflows/ 2>/dev/null || true
	cp Makefile profile.toml load.st run-s2.sh run-s3.sh run-s4.sh run-origination-core.sh $(DISTDIR)/
	cp README.md CHANGELOG.md LOAD.md $(DISTDIR)/
	cp LICENSE $(DISTDIR)/ 2>/dev/null || cp ../../LICENSE $(DISTDIR)/ 2>/dev/null || true
	tar czf dist/$(DISTNAME).tar.gz -C dist $(DISTNAME)
	rm -rf $(DISTDIR)
	@echo "dist: dist/$(DISTNAME).tar.gz  (Tonel src tree + libentitycore_codec recipe; VERSION=$(VERSION))"

clean:
	rm -f $(PEERIMG) entity-core.changes *.sources
	rm -rf dist
