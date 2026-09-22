# entity-core-protocol-fortran — build (container-bound; run-s2.sh / run-s3.sh).
#
# Hand-rolled canonical CBOR (ECF) VALUE codec in PURE FORTRAN (the fixed-width SIGNED-ONLY
# numeric probe) + crypto/entity-framing/base58 over the C-ABI (libentitycore_codec) bound
# DIRECTLY via iso_c_binding (no C wrapper). The ONLY C wrapper is the socket net-shim
# (src/ext/net_shim.c). Build is gfortran + make (fpm not in fedora dnf — A-FTN-008); the
# module dependency order is handled here (one module per file, profile [naming]).

FC          := gfortran
CC          := gcc
FFLAGS      := -std=f2018 -ffree-form -ffree-line-length-none -O2 -Wall -fimplicit-none -fcheck=bounds
CFLAGS      := -O2 -Wall
BUILD       := build

CODEC_SRC   := ../../ffi-generator/c-abi/entity-core-codec-ffi-c
CODEC_BUILD := $(CODEC_SRC)/build
CODEC_LIB   := $(CODEC_BUILD)/libentitycore_codec.so
CORPUS      := ../shared/test-vectors/ecf-conformance/conformance-vectors.cbor

# S2 codec module compile order (dependencies first).
CODEC_MODS  := src/status.f90 src/varint.f90 src/entity_core_ffi.f90 src/cbor.f90 src/entity.f90
# S3 peer module compile order (on top of the codec).
PEER_MODS   := src/net.f90 src/val.f90 src/ent.f90 src/identity.f90 src/store.f90 \
               src/wire.f90 src/keystore.f90 src/coretypes.f90 src/capability.f90 \
               src/transport.f90 src/peer.f90

CODEC_OBJ   := $(patsubst src/%.f90,$(BUILD)/%.o,$(CODEC_MODS))
PEER_OBJ    := $(patsubst src/%.f90,$(BUILD)/%.o,$(PEER_MODS))
ALL_OBJ     := $(CODEC_OBJ) $(PEER_OBJ) $(BUILD)/net_shim.o

LDFLAGS     := -L$(CODEC_BUILD) -Wl,--no-as-needed -lentitycore_codec -Wl,-rpath,$(CODEC_BUILD)

.PHONY: all test unit conf s3 smoke selftest clean codec peer dist
all: test

# ── S2 codec gate (unchanged) ──
test: conf unit

codec: $(CODEC_LIB)
$(CODEC_LIB):
	cd $(CODEC_SRC) && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build >/dev/null

$(BUILD):
	mkdir -p $(BUILD)

# ── module objects (compiled in dependency order into $(BUILD)) ──
$(BUILD)/status.o: src/status.f90 | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/varint.o: src/varint.f90 $(BUILD)/status.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/entity_core_ffi.o: src/entity_core_ffi.f90 $(BUILD)/status.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/cbor.o: src/cbor.f90 $(BUILD)/status.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/entity.o: src/entity.f90 $(BUILD)/cbor.o $(BUILD)/varint.o $(BUILD)/entity_core_ffi.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@

# S3 peer modules (dependency order enforced via prior-object prerequisites)
$(BUILD)/net.o: src/net.f90 | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/val.o: src/val.f90 $(BUILD)/cbor.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/ent.o: src/ent.f90 $(BUILD)/val.o $(BUILD)/entity_core_ffi.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/identity.o: src/identity.f90 $(BUILD)/ent.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/store.o: src/store.f90 $(BUILD)/ent.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/wire.o: src/wire.f90 $(BUILD)/ent.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/keystore.o: src/keystore.f90 $(BUILD)/net.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/coretypes.o: src/coretypes.f90 $(BUILD)/store.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/capability.o: src/capability.f90 $(BUILD)/store.o $(BUILD)/identity.o $(BUILD)/wire.o $(BUILD)/net.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/transport.o: src/transport.f90 $(BUILD)/net.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@
$(BUILD)/peer.o: src/peer.f90 $(BUILD)/capability.o $(BUILD)/coretypes.o $(BUILD)/transport.o $(BUILD)/keystore.o | $(BUILD)
	$(FC) $(FFLAGS) -J$(BUILD) -c $< -o $@

# C net-shim (the ONLY C wrapper)
$(BUILD)/net_shim.o: src/ext/net_shim.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# ── S2 conformance corpus driver (the gate) ──
$(BUILD)/conformance: test/conformance.f90 $(CODEC_OBJ) codec
	$(FC) $(FFLAGS) -I$(BUILD) -o $@ test/conformance.f90 $(CODEC_OBJ) $(LDFLAGS)
conf: $(BUILD)/conformance
	$(BUILD)/conformance $(CORPUS)

$(BUILD)/unit_tests: test/unit_tests.f90 $(CODEC_OBJ) codec
	$(FC) $(FFLAGS) -I$(BUILD) -o $@ test/unit_tests.f90 $(CODEC_OBJ) $(LDFLAGS)
unit: $(BUILD)/unit_tests
	$(BUILD)/unit_tests

# ── S3 peer host + tests ──
peer: $(BUILD)/peer
$(BUILD)/peer: bin/peer.f90 $(ALL_OBJ) codec
	$(FC) $(FFLAGS) -I$(BUILD) -o $@ bin/peer.f90 $(ALL_OBJ) $(LDFLAGS)

$(BUILD)/s3_initiator: test/s3_initiator.f90 $(ALL_OBJ) codec
	$(FC) $(FFLAGS) -I$(BUILD) -o $@ test/s3_initiator.f90 $(ALL_OBJ) $(LDFLAGS)

$(BUILD)/s3_selftest: test/s3_selftest.f90 $(ALL_OBJ) codec
	$(FC) $(FFLAGS) -I$(BUILD) -o $@ test/s3_selftest.f90 $(ALL_OBJ) $(LDFLAGS)

# the full S3 gate: offline self-test + two-peer loopback smoke.
s3: selftest smoke

selftest: $(BUILD)/s3_selftest
	LD_LIBRARY_PATH=$(CODEC_BUILD) $(BUILD)/s3_selftest

smoke: $(BUILD)/peer $(BUILD)/s3_initiator
	CODEC_BUILD=$(CODEC_BUILD) PEER=$(BUILD)/peer INIT=$(BUILD)/s3_initiator bash test/smoke.sh

# ── S5 packaging ──
# Fortran is COMPILED, so the "package" is a SOURCE distribution: the .f90 module tree +
# the C net-shim recipe + fpm.toml (idiomatic, for fpm users) + the Makefile (the actual
# container build) + run scripts + status + arch + LICENSE. The consumer rebuilds with
# `make peer` (gfortran + the image gcc) or `fpm build`. libentitycore_codec is a documented
# runtime dep (README), rebuilt from the FFI repo — NOT bundled (its own build tree). The
# net-shim is shipped as SOURCE (net_shim.c), rebuilt by the consumer. Mirrors the
# COBOL / Rexx `make dist` source-tarball model (no fpm/binary registry step here).
VERSION  ?= 0.1.0-pre
DISTNAME := entity-core-protocol-fortran-$(VERSION)
DISTDIR  := dist/$(DISTNAME)
dist:
	rm -rf $(DISTDIR) dist/$(DISTNAME).tar.gz
	mkdir -p $(DISTDIR)/src/ext $(DISTDIR)/bin $(DISTDIR)/test $(DISTDIR)/status $(DISTDIR)/arch
	cp src/*.f90 $(DISTDIR)/src/
	cp src/ext/*.c $(DISTDIR)/src/ext/
	cp bin/peer.f90 $(DISTDIR)/bin/
	cp test/*.f90 test/*.sh $(DISTDIR)/test/
	cp status/PHASE-S*.md status/CONFORMANCE-REPORT.md status/CONFORMANCE-REPORT.json \
	   status/SPEC-AMBIGUITY-LOG.md $(DISTDIR)/status/
	cp arch/*.md $(DISTDIR)/arch/ 2>/dev/null || true
	cp Makefile profile.toml fpm.toml README.md CHANGELOG.md .gitignore \
	   run-s2.sh run-s3.sh run-s4.sh $(DISTDIR)/
	cp ../../LICENSE $(DISTDIR)/
	tar czf dist/$(DISTNAME).tar.gz -C dist $(DISTNAME)
	rm -rf $(DISTDIR)
	@echo "dist: dist/$(DISTNAME).tar.gz  (source distribution: .f90 tree + net_shim.c recipe + fpm.toml + make build; VERSION=$(VERSION))"

clean:
	rm -rf $(BUILD)
