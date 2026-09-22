# entity-core-protocol-tcl — S2 codec build + conformance (container-bound; see run-s2.sh).
# Pure-Tcl canonical CBOR + base58/varint; crypto via the C-extension shim over
# libentitycore_codec (A-TCL-005). tcltest ships in base Tcl.

TCLSH       ?= tclsh
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
STUB        := $(shell find /usr/lib64 /usr/lib -name 'libtclstub*.a' 2>/dev/null | head -1)
SHIM        := src/ffi/libentitycorecrypto.so
CORPUS      := ../shared/test-vectors/ecf-conformance/conformance-vectors.cbor

.PHONY: all test sweep spike codec shim s3 smoke selftest clean
all: test

# Build the codec C-ABI (libentitycore_codec) if absent — its CMake, offline (libsodium
# is in the toolchain image). Provenance queried at runtime via ec_impl_info().
codec: $(CODEC_BUILD)/libentitycore_codec.so
$(CODEC_BUILD)/libentitycore_codec.so: $(CODEC_DEPS)
	cd $(CODEC_SRC) && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build >/dev/null

# The crypto shim: a Tcl stubs C-extension binding the codec's Ed25519 + SHA entry points.
shim: $(SHIM)
$(SHIM): src/ffi/entitycore_tcl.c | codec
	gcc -fPIC -shared -DUSE_TCL_STUBS -I/usr/include -I$(SPEC) \
	    -o $@ $< -L$(CODEC_BUILD) -lentitycore_codec $(STUB) -Wl,-rpath,$(CODEC_BUILD)

# Full pinned-corpus conformance gate (69 vectors, byte-identical) + the 0.8.2.25
# sweep unit gate (the 3.3 ladder, 6.3's path check + listing filter, 5.4's sentinel
# scoping, 5.5a's scope typing, and 4.11's code-belongs-to-the-cause table).
test: shim sweep
	LD_LIBRARY_PATH=$(CODEC_BUILD) $(TCLSH) test/conformance.tcl $(CORPUS) $(SHIM)

# The 0.8.2.25 sweep unit gate. A separate target so it can be driven alone while
# diagnosing, and a PREREQUISITE of `test` so it cannot rot unrun -- an axis's per-peer
# gates rot exactly where no cohort runner reaches.
sweep: shim
	LD_LIBRARY_PATH=$(CODEC_BUILD) $(TCLSH) test/sweep_0_8_2_25.tcl $(SHIM)

# The high-risk-legs spike (pure Tcl, no crypto/shim needed).
spike:
	$(TCLSH) test/spike.tcl

# ── S3 peer machinery ──
# The S3 gate: the peer-layer foundation self-test + the two-peer loopback smoke
# (handshake + 404 + authority-gated tree get + 8-way request_id demux + the §6.13
# extensibility scenario). Loopback is intra-container 127.0.0.1 — works under
# --network=none, so the whole S3 gate stays dependency-sealed and offline.
s3: selftest smoke

selftest: shim
	LD_LIBRARY_PATH=$(CODEC_BUILD) $(TCLSH) test/s3_selftest.tcl $(SHIM)

smoke: shim
	LD_LIBRARY_PATH=$(CODEC_BUILD) $(TCLSH) test/smoke.tcl $(SHIM)

clean:
	rm -f $(SHIM)
