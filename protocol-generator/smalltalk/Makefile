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
CORPUS      := ../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor
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
# .image. Depends on the codec .so (UFFI warms on first crypto call).
image: ffi $(PEERIMG)
$(PEERIMG): load.st $(wildcard src/*/*.st) tests/EntityCore-Tests/EcCodecTest.st
	rm -f $(PEERIMG) entity-core.changes *.sources
	cp $(BASEIMG)/*.image ./$(PEERIMG)
	cp $(BASEIMG)/*.changes ./entity-core.changes
	cp $(BASEIMG)/*.sources . 2>/dev/null || true
	$(FFI_ENV) $(PHARO) ./$(PEERIMG) eval "Smalltalk compiler evaluate: (FileLocator workingDirectory / 'load.st') contents. Smalltalk compiler evaluate: (FileLocator workingDirectory / 'tests/EntityCore-Tests/EcCodecTest.st') contents. Smalltalk snapshot: true andQuit: false. 'built'" | grep -vi 'undeclared\|warning' || true

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

# SUnit suite (bundled xUnit) — the first-class TestCase mirror of the drivers.
sunit: image
	$(FFI_ENV) $(PHARO) ./$(PEERIMG) eval "| r | r := EcCodecTest buildSuite run. 'SUnit runs=', r runCount printString, ' passes=', r passedCount printString, ' failures=', r failureCount printString, ' errors=', r errorCount printString"

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
