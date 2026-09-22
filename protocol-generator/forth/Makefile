# entity-core-protocol-forth — S2 codec build + conformance (container-bound; run-s2.sh).
# Pure-Forth canonical CBOR (the STACK-MACHINE probe) + base58/varint/peer_id; crypto via
# the codec C-ABI (libentitycore_codec) bound with gforth's in-process libcc c-function.
# gforth ships no unit-test framework — the harness is hand-rolled Forth.

GFORTH      ?= gforth
CODEC_SRC   := ../../ffi-generator/c-abi/entity-core-codec-ffi-c
CODEC_BUILD := $(CODEC_SRC)/build
SPEC        := ../../ffi-generator/c-abi/spec
CORPUS      := ../shared/test-vectors/ecf-conformance/conformance-vectors.cbor

# libcc needs the codec lib on LIBRARY_PATH (link the wrapper) + LD_LIBRARY_PATH (dlopen),
# and the C-ABI header on the include path (the c-library \c #include "entitycore_codec.h").
# GOTCHA A-FT-005: clear the libcc wrapper cache (keyed by c-library NAME) before each run,
# or a stale .so silently binds old symbols.
FFI_ENV = LIBRARY_PATH=$(CODEC_BUILD) LD_LIBRARY_PATH=$(CODEC_BUILD) \
          C_INCLUDE_PATH=$(SPEC) CPATH=$(SPEC)
CLEAR_CACHE = rm -rf $$HOME/.gforth/libcc-named $$HOME/.gforth/libcc-tmp

.PHONY: all test codec ffi crypto-accept int-boundary clean dist s3 smoke selftest

all: test

# ── S3 peer machinery gate ──
# The peer-layer foundation self-test (units the loopback + a rejection-only oracle can't
# cover: identity, store, N5 envelope, §4.10(a)/(b) floor) + the two-peer loopback smoke.
s3: selftest smoke

selftest: codec
	$(CLEAR_CACHE)
	$(FFI_ENV) $(GFORTH) -e "warnings off" test/s3-selftest.fs

smoke: codec
	$(CLEAR_CACHE)
	$(FFI_ENV) bash test/smoke.sh

# The full S2 gate: corpus conformance + crypto accept-path + the uint64 boundary self-test.
gate: test int-boundary crypto-accept

# Build the codec C-ABI (libentitycore_codec) if absent — its CMake, offline (libsodium is
# in the toolchain image). Provenance queried via ec_impl_info().
codec: $(CODEC_BUILD)/libentitycore_codec.so
$(CODEC_BUILD)/libentitycore_codec.so:
	cd $(CODEC_SRC) && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build >/dev/null

# `ffi` is the profile's declared build_command + the verb LOAD.md/README document — an alias
# for `codec` (builds libentitycore_codec.so; the libcc crypto wrapper warms on first load).
ffi: codec

# Full pinned-corpus conformance gate (69 vectors, byte-identical encode+decode+hash).
test: codec
	$(CLEAR_CACHE)
	$(FFI_ENV) $(GFORTH) -e "warnings off" test/conformance.fs $(CORPUS)

# Crypto accept-path unit test (the direction the rejection-only oracle can't cover).
crypto-accept: codec
	$(CLEAR_CACHE)
	$(FFI_ENV) $(GFORTH) test/crypto-accept.fs

# Fixed-width uint64 boundary self-test [2^63, 2^64-1] (A-FT-001) — pure codec, no FFI.
int-boundary:
	$(GFORTH) test/int-boundary.fs

# ── S5 packaging ──
# Forth has NO package registry and no module system — the "package" is a source tarball of
# the .fs tree + the libentitycore_codec build recipe (a runtime dep, documented, not
# bundled) + a load stub. A source distribution (mirrors COBOL/Rexx `make dist`).
VERSION  ?= 0.1.0-pre
DISTNAME := entity-core-protocol-forth-$(VERSION)
DISTDIR  := dist/$(DISTNAME)
dist:
	rm -rf $(DISTDIR) dist/$(DISTNAME).tar.gz
	mkdir -p $(DISTDIR)/src/ffi $(DISTDIR)/bin $(DISTDIR)/test $(DISTDIR)/status $(DISTDIR)/arch
	cp src/*.fs $(DISTDIR)/src/
	cp src/ffi/*.fs $(DISTDIR)/src/ffi/
	cp bin/*.fs $(DISTDIR)/bin/
	cp test/*.fs test/*.sh $(DISTDIR)/test/
	cp status/PHASE-S*.md status/CONFORMANCE-REPORT.md status/SPEC-AMBIGUITY-LOG.md $(DISTDIR)/status/ 2>/dev/null || true
	cp arch/*.md $(DISTDIR)/arch/ 2>/dev/null || true
	cp Makefile profile.toml run-s2.sh run-s3.sh run-s4.sh run-origination-core.sh $(DISTDIR)/
	cp README.md CHANGELOG.md LOAD.md $(DISTDIR)/
	cp LICENSE $(DISTDIR)/ 2>/dev/null || cp ../../LICENSE $(DISTDIR)/ 2>/dev/null || true
	tar czf dist/$(DISTNAME).tar.gz -C dist $(DISTNAME)
	rm -rf $(DISTDIR)
	@echo "dist: dist/$(DISTNAME).tar.gz  (source .fs tree + libentitycore_codec recipe; VERSION=$(VERSION))"

clean:
	rm -rf dist
