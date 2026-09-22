# entity-core-protocol-asm-x86_64 — build interface (thin make over as + cc-driver).
#
# Runs inside containers/asm-x86_64-toolchain (fedora:43 + binutils + gcc). The C-ABI
# HEADER is committed; the FFI target libentitycore_codec.{so,a} is BUILT here by the
# `codec` target from committed source under ffi-generator/ — reached through the
# mounted /work tree, NOT baked into the image (see the Containerfile). All builds are
# offline (--network=none).
#
# Verbs:
#   make ffi-smoke   — de-risk the asm→C-ABI bridge (ec_sha256 KAT). S1/S2 seam.
#   make codec       — build libentitycore_codec.so (everything below links it).
#   make host        — the live peer executable.                                   [S3]
#   make diff        — L2 native-codec differential: ec_encode_bare_value (codec.s)
#                      vs the pinned corpus golden bytes (tools/diff-harness.c).    [L2]
#   make parse-test  — ec_peerid_parse accept/reject unit (corpus has no parse vector). [L2]
#   make clean

AS      := as
CC      := cc
ASFLAGS := --64 -g -Isrc
# cc is the LINK DRIVER only (crt0 + __libc_start_main + dynamic-linker path). No C compiled.
# -no-pie: hand-authored asm uses absolute/RIP-relative addressing (A-ASM-001).
LDFLAGS := -no-pie

# The codec C-ABI. Its SOURCE is committed under ffi-generator/; its BUILD OUTPUT is
# NOT -- ffi-generator/c-abi/entity-core-codec-ffi-c/.gitignore ignores `build/`. This
# comment used to call the .so a "committed repo output", which is how the `codec`
# target below came to be missing while both ISA siblings have one: the link worked on
# any machine where something else had already built it, and would fail on a clean
# clone. Overridable; defaults are relative to this peer dir.
CODEC_SRC ?= $(abspath ../../ffi-generator/c-abi/entity-core-codec-ffi-c)
CODEC_DIR ?= $(CODEC_SRC)/build

# Every file the codec compiles from -- DERIVED with `find`, never a hand-listed
# set, because a second copy of a dependency list is a second thing that can
# drift.  Without these prerequisites the rule below is a BARE file target, so
# make runs it only when the .so is ABSENT and a codec source change never
# reaches this peer: that is how two ISA peers shipped a 2026-07-15 codec.
CODEC_DEPS := $(shell find $(CODEC_SRC)/src $(CODEC_SRC)/include \
                          $(CODEC_SRC)/CMakeLists.txt -type f 2>/dev/null)

INC_DIR   ?= $(abspath ../../ffi-generator/c-abi/spec)
CODEC_LDFLAGS := -L$(CODEC_DIR) -lentitycore_codec -Wl,-rpath,$(CODEC_DIR)

SRC := src
OBJ := build
BIN := bin

$(OBJ) $(BIN):
	mkdir -p $@

# -- assemble rule ------------------------------------------------------------
$(OBJ)/%.o: $(SRC)/%.s | $(OBJ)
	$(AS) $(ASFLAGS) -o $@ $<

# -- codec (build the native .so this peer links against) ---------------------
# Mirrors asm-arm64 / riscv64, which have always had this; x86_64 did not, because
# its header wrongly described the .so as committed. Everything that links
# $(CODEC_LDFLAGS) depends on it, so a clean clone builds.
.PHONY: codec
codec: $(CODEC_DIR)/libentitycore_codec.so
$(CODEC_DIR)/libentitycore_codec.so: $(CODEC_DEPS)
	cmake -S $(CODEC_SRC) -B $(CODEC_DIR) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(CODEC_DIR) --target entitycore_codec -j4

# -- ffi-smoke (de-risk) ------------------------------------------------------
.PHONY: ffi-smoke
ffi-smoke: $(BIN)/ffi-smoke codec
	@LD_LIBRARY_PATH=$(CODEC_DIR) $(BIN)/ffi-smoke

$(BIN)/ffi-smoke: $(OBJ)/ffi_smoke.o | codec $(BIN)
	$(CC) $(LDFLAGS) -o $@ $< $(CODEC_LDFLAGS)

# -- host (live peer) ---------------------------------------------------------
# codec.o is the L2 native canonical codec (ec_content_hash / ec_peerid_{format,parse}).
# It precedes -lentitycore_codec in the link line, so our native symbols win over the .so;
# the .so still supplies the crypto floor (ec_sha256, ec_ed25519_*), which codec.o calls.
HOST_OBJS := $(OBJ)/codec.o $(OBJ)/host.o $(OBJ)/dispatch.o $(OBJ)/cbor.o $(OBJ)/typestore.o
# macros.s is an .include (not a translation unit); changing it must rebuild all objs.
$(OBJ)/host.o $(OBJ)/dispatch.o $(OBJ)/cbor.o: $(SRC)/macros.s

.PHONY: host
host: $(BIN)/host
$(BIN)/host: $(HOST_OBJS) | codec $(BIN)
	$(CC) $(LDFLAGS) -o $@ $(HOST_OBJS) $(CODEC_LDFLAGS)

# -- diff (L2 native-codec differential) --------------------------------------
# codec.s is a standalone native codec (no libc, no FFI): assemble + link the C
# harness against it directly. corpus_vectors.h is generated host-side from the
# pinned .diag (container has no python3); regenerate with tools/gen-corpus-header.py.
.PHONY: diff
diff: $(OBJ)/codec.o | codec $(BIN)
	$(CC) $(LDFLAGS) -O0 -I tools -o $(BIN)/diff tools/diff-harness.c $(OBJ)/codec.o $(CODEC_LDFLAGS)
	$(BIN)/diff

# -- parse-test (ec_peerid_parse accept + reject paths) -----------------------
# The corpus has no peer-id PARSE vector (peer_id.N are encode_equal only), so this
# unit drives the base58/LEB128 DECODE accept-path + reject paths. codec.o's
# ec_content_hash references ec_sha256, so link the .so too.
.PHONY: parse-test
parse-test: $(OBJ)/codec.o | codec $(BIN)
	$(CC) $(LDFLAGS) -O0 -o $(BIN)/parse-test tools/peerid-parse-test.c $(OBJ)/codec.o $(CODEC_LDFLAGS)
	LD_LIBRARY_PATH=$(CODEC_DIR) $(BIN)/parse-test

# -- peers-scope-test (§5.2 `peers` grant dimension accept + reject paths) ----------------
# The conformance oracle has zero vectors for the `peers` dimension (see
# protocol-generator/shared/findings/peers-grant-dimension-oracle-gap.md), so
# this drives derive_handler/grant_scope_ok directly against hand-encoded CBOR fixtures — no
# FFI/.so link needed (dispatch.o's unrelated externs are stubbed in the test file itself).
.PHONY: peers-scope-test
peers-scope-test: $(OBJ)/dispatch.o $(OBJ)/cbor.o | $(BIN)
	$(CC) $(LDFLAGS) -O0 -o $(BIN)/peers-scope-test tools/peers-scope-test.c $(OBJ)/dispatch.o $(OBJ)/cbor.o
	$(BIN)/peers-scope-test

.PHONY: clean
clean:
	rm -rf $(OBJ) $(BIN)
