# entity-core-protocol-oz — build + conformance (container-bound; run-s2.sh etc.).
# Hand-rolled canonical CBOR in pure Oz (the dataflow-concurrency peer's native
# codec); crypto via the entity-codec-daemon co-process over libentitycore_codec.
# Mozart has no test framework — harnesses are hand-rolled Oz functors + sh.

OZC         ?= ozc
CODEC_SRC   := ../../ffi-generator/c-abi/entity-core-codec-ffi-c
CODEC_BUILD := $(CODEC_SRC)/build

# Every file the codec compiles from -- DERIVED with `find`, never a hand-listed
# set, because a second copy of a dependency list is a second thing that can
# drift.  Without these prerequisites the rule below is a BARE file target, so
# make runs it only when the .so is ABSENT and a codec source change never
# reaches this peer: that is how two ISA peers shipped a 2026-07-15 codec.
CODEC_DEPS := $(shell find $(CODEC_SRC)/src $(CODEC_SRC)/include \
                          $(CODEC_SRC)/CMakeLists.txt -type f 2>/dev/null)

SPEC        := ../../ffi-generator/c-abi/spec
CORPUS      := ../shared/test-vectors/ecf-conformance/conformance-vectors.cbor
DAEMON      := build/eccodecd

# S2 codec modules; S3 adds the peer machinery. Order matters (ozc resolves
# imports from already-built .ozf pickles).
S2MODS := util varint base58 val cbor peerid crypto
S3MODS := $(S2MODS) hexpath entity envelope identity store capability wire \
          conn typestore peer transport
OZFS   := $(addprefix build/,$(addsuffix .ozf,$(S3MODS)))

.PHONY: all build s2 clean codec daemon dist host multisig-accept

all: s2

build/%.ozf: src/%.oz
	@mkdir -p build
	$(OZC) -c $< -o $@

build/conformance.ozf: test/conformance.oz $(addprefix build/,$(addsuffix .ozf,$(S2MODS)))
	@mkdir -p build
	$(OZC) -c $< -o $@

build/host.ozf: src/host.oz $(OZFS)
	@mkdir -p build
	$(OZC) -c $< -o $@

build/multisig_accept.ozf: test/multisig_accept.oz $(OZFS)
	@mkdir -p build
	$(OZC) -c $< -o $@

# the standalone S4 host binary (peer on a port)
host: build/host.ozf daemon

# genuine multisig K-of-N ACCEPT-path unit test (the oracle can't cover accept)
multisig-accept: build/multisig_accept.ozf daemon
	ozengine build/multisig_accept.ozf $(DAEMON)

# Build the codec C-ABI (libentitycore_codec) if absent — its CMake, offline
# (libsodium is in the toolchain image). Provenance queried via ec_impl_info().
codec: $(CODEC_BUILD)/libentitycore_codec.so
$(CODEC_BUILD)/libentitycore_codec.so: $(CODEC_DEPS)
	cd $(CODEC_SRC) && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build >/dev/null

# The entity-codec-daemon co-process (crypto/clock/entropy seam; A-OZ-004,
# DAEMON-PROTOCOL.md). rpath'd to the codec build dir — no LD_LIBRARY_PATH.
daemon: $(DAEMON)
$(DAEMON): src/daemon/eccodecd.c | codec
	@mkdir -p build
	gcc -O2 -I$(SPEC) -o $@ $< -L$(CODEC_BUILD) -Wl,--no-as-needed -lentitycore_codec \
	    -Wl,-rpath,$(abspath $(CODEC_BUILD))

build: $(OZFS) daemon

# S2 gate: the 71-vector pinned corpus, byte-identical.
s2: $(addprefix build/,$(addsuffix .ozf,$(S2MODS))) build/conformance.ozf daemon
	ozengine build/conformance.ozf $(CORPUS) $(DAEMON)

clean:
	rm -rf build

# ── S5 packaging ── source distribution (no Oz registry exists; MOGUL defunct):
# the .oz tree + daemon recipe + run scripts. libentitycore_codec is a documented
# runtime dep, not bundled.
VERSION  ?= 0.1.0-pre
DISTNAME := entity-core-protocol-oz-$(VERSION)
DISTDIR  := dist/$(DISTNAME)
dist:
	rm -rf $(DISTDIR) dist/$(DISTNAME).tar.gz
	mkdir -p $(DISTDIR)/src/daemon $(DISTDIR)/test $(DISTDIR)/status $(DISTDIR)/arch
	cp src/*.oz $(DISTDIR)/src/
	cp src/daemon/eccodecd.c src/daemon/DAEMON-PROTOCOL.md $(DISTDIR)/src/daemon/
	cp test/*.oz test/*.sh $(DISTDIR)/test/ 2>/dev/null || true
	cp status/PHASE-S*.md status/CONFORMANCE-REPORT.md status/CONFORMANCE-REPORT.json \
	   status/SPEC-AMBIGUITY-LOG.md $(DISTDIR)/status/ 2>/dev/null || true
	cp arch/*.md $(DISTDIR)/arch/ 2>/dev/null || true
	cp Makefile profile.toml README.md run-s2.sh run-s4.sh run-origination-core.sh $(DISTDIR)/ 2>/dev/null || true
	cp ../../LICENSE $(DISTDIR)/ 2>/dev/null || true
	tar czf dist/$(DISTNAME).tar.gz -C dist $(DISTNAME)
	rm -rf $(DISTDIR)
	@echo "dist: dist/$(DISTNAME).tar.gz (VERSION=$(VERSION))"
