# entity-core-protocol-apl — build (container-bound; run-s2.sh).
#
# The ALIEN-SUBSTRATE (array/value-model) probe. The canonical CBOR VALUE codec is
# hand-rolled PURE APL (src/*.apl — interpreted, no compile step); the ONLY compiled
# artifact is the GNU APL NATIVE-FUNCTION C++ shim (src/ext/ec_native.cc ->
# ec_native.so) that binds libentitycore_codec's ec_* crypto/base58 symbols. This
# Makefile: (1) builds libentitycore_codec from the vendored C-ABI (CMake, links the
# image libsodium) if absent; (2) compiles the native-fn shim; (3) runs the tests.
# The tests LOAD the .apl modules into one GNU APL workspace (multiple -f share the
# workspace) and run the corpus gate + unit suites.

APL         := apl
APL_ROOT    ?= /opt/apl-1.9
APL_SRC     ?= $(APL_ROOT)/src
CXX         := g++
# native-fn shims need BOTH the build root (configure-generated config.h) and the
# src dir (Value.hh/Cell.hh/...), plus the verbatim C-ABI header (A-APL-009).
CABI_SPEC   := ../../ffi-generator/c-abi/spec
CXXFLAGS    := -shared -fPIC -std=gnu++17 -Wall -I$(APL_ROOT) -I$(APL_SRC) -I$(CABI_SPEC)

CODEC_SRC   := ../../ffi-generator/c-abi/entity-core-codec-ffi-c
CODEC_BUILD := $(CODEC_SRC)/build
CODEC_LIB   := $(CODEC_BUILD)/libentitycore_codec.so

SHIM_SRC    := src/ext/ec_native.cc
SHIM_SO     := src/ext/ec_native.so

# APL module load order (dependencies first): status -> varint/cbor -> ffi -> entity.
MODS        := src/status.apl src/varint.apl src/cbor.apl src/ffi.apl src/entity.apl
LOAD        := $(patsubst %,-f %,$(MODS))

# S3 peer machinery load order (on the S2 codec): value/entity helpers -> L1 identity/
# keystore -> foundation store -> L2 wire -> L3 capability -> L4 net/transport -> core
# types -> the peer brain.
S3MODS      := $(MODS) src/val.apl src/ent.apl src/identity.apl src/keystore.apl \
               src/store.apl src/wire.apl src/capability.apl src/net.apl \
               src/transport.apl src/coretypes.apl src/peer.apl
S3LOAD      := $(patsubst %,-f %,$(S3MODS))

CORPUS      := ../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor

.PHONY: all test conf unit codec shim clean dist s3 selftest smoke
all: test

# ── S2 codec gate ──
test: conf unit

codec: $(CODEC_LIB)
$(CODEC_LIB):
	cd $(CODEC_SRC) && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build >/dev/null

# native-function shim (the only compiled artifact); links libentitycore_codec.
shim: $(SHIM_SO)
$(SHIM_SO): $(SHIM_SRC) $(CODEC_LIB)
	$(CXX) $(CXXFLAGS) -o $@ $(SHIM_SRC) -L$(CODEC_BUILD) -lentitycore_codec -Wl,-rpath,$(CODEC_BUILD)

# ── S2 conformance corpus driver (the gate) ──
# Load modules + the driver into one workspace; the driver prints a greppable
# CONFORMANCE: ALL PASS marker on 69/69. The grep IS the gate (fails make on any FAIL).
# NB: apl output is REDIRECTED to a file, not piped — GNU APL does not exit cleanly
# when its stdout is a pipe (it hangs after )OFF); a file redirect exits fine.
conf: $(SHIM_SO)
	@$(APL) --script $(LOAD) -f test/conformance.apl </dev/null >build-conf.log 2>&1 || true
	@cat build-conf.log
	@grep -q 'CONFORMANCE: ALL PASS' build-conf.log

unit: $(SHIM_SO)
	@$(APL) --script $(LOAD) -f test/unit_tests.apl </dev/null >build-unit.log 2>&1 || true
	@cat build-unit.log
	@grep -q 'UNIT: ALL PASS' build-unit.log

# ── S3 peer machinery gate: offline foundation self-test + two-peer loopback smoke ──
# Container-bound, sealed-offline (--network=none); loopback is intra-container 127.0.0.1.
s3: selftest smoke

# offline foundation self-test (file-redirect run, then grep the marker — A-APL-013).
selftest: $(SHIM_SO)
	@$(APL) --script $(S3LOAD) -f test/s3_selftest.apl </dev/null >build-selftest.log 2>&1 || true
	@cat build-selftest.log
	@grep -q 'SELFTEST: PASS' build-selftest.log

# two-peer loopback smoke (the driver launches responder + initiator, greps SMOKE: PASS).
smoke: $(SHIM_SO)
	@bash test/smoke.sh

# ── S5 packaging (source distribution: the .apl workspace + shim source + recipe) ──
# APL is INTERPRETED, so the "package" is a SOURCE distribution: the .apl workspace tree
# (src/ modules + bin/peer.apl loader) + the native-fn shim SOURCE (src/ext/ec_native.cc —
# NOT the gitignored .so) + the tests + the Makefile (the actual container build) + README +
# CHANGELOG + run scripts + status + arch + the repo-root Apache-2.0 LICENSE. The consumer
# rebuilds only the shim (`make shim`, g++ + the retained apl headers) and loads the workspace
# into apl. libentitycore_codec is a documented runtime dep (README), rebuilt from the FFI repo
# — NOT bundled. Mirrors the COBOL / Rexx / Fortran `make dist` source-tarball model (no binary
# registry — APL has none; a git tag is the deliverable). LICENSE bundled, never duplicated
# (one canonical license — the Fortran/Rexx/Tcl convention).
VERSION  ?= 0.1.0-pre
DISTNAME := entity-core-protocol-apl-$(VERSION)
DISTDIR  := dist/$(DISTNAME)
dist:
	rm -rf $(DISTDIR) dist/$(DISTNAME).tar.gz
	mkdir -p $(DISTDIR)/src/ext $(DISTDIR)/bin $(DISTDIR)/test $(DISTDIR)/status $(DISTDIR)/arch
	cp src/*.apl $(DISTDIR)/src/
	cp src/ext/*.cc $(DISTDIR)/src/ext/
	cp bin/peer.apl $(DISTDIR)/bin/
	cp test/*.apl test/*.sh $(DISTDIR)/test/
	cp status/PHASE-S*.md status/CONFORMANCE-REPORT.md status/CONFORMANCE-REPORT.json \
	   status/SPEC-AMBIGUITY-LOG.md $(DISTDIR)/status/
	cp arch/*.md $(DISTDIR)/arch/ 2>/dev/null || true
	cp Makefile profile.toml README.md CHANGELOG.md .gitignore \
	   run-s2.sh run-s3.sh run-s4.sh $(DISTDIR)/
	cp ../../LICENSE $(DISTDIR)/
	tar czf dist/$(DISTNAME).tar.gz -C dist $(DISTNAME)
	rm -rf $(DISTDIR)
	@echo "dist: dist/$(DISTNAME).tar.gz (source distribution: .apl workspace + bin/peer.apl + ec_native.cc recipe + make build; VERSION=$(VERSION))"

clean:
	rm -f $(SHIM_SO) build-conf.log build-unit.log build-selftest.log
	rm -rf dist
