# entity-core-protocol-asm-x86_64 — build interface (thin make over as + cc-driver).
#
# Runs inside containers/asm-x86_64-toolchain (fedora:43 + binutils + gcc). The FFI target
# libentitycore_codec.{so,a} + the C-ABI header are committed repo outputs reached through
# the mounted /work tree — NOT baked into the image (see the Containerfile). All builds are
# offline (--network=none).
#
# Verbs:
#   make ffi-smoke   — de-risk the asm→C-ABI bridge (ec_sha256 KAT). S1/S2 seam.
#   make s2          — codec conformance self-check (71-vector corpus via FFI).   [S2]
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

# The codec C-ABI: committed build outputs under ffi-generator/, reached via the repo tree.
# Overridable; defaults are relative to this peer dir (../../ = protocol-generator/..= repo root).
CODEC_DIR ?= $(abspath ../../ffi-generator/c-abi/entity-core-codec-ffi-c/build)
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

# -- ffi-smoke (de-risk) ------------------------------------------------------
.PHONY: ffi-smoke
ffi-smoke: $(BIN)/ffi-smoke
	@LD_LIBRARY_PATH=$(CODEC_DIR) $(BIN)/ffi-smoke

$(BIN)/ffi-smoke: $(OBJ)/ffi_smoke.o | $(BIN)
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
$(BIN)/host: $(HOST_OBJS) | $(BIN)
	$(CC) $(LDFLAGS) -o $@ $(HOST_OBJS) $(CODEC_LDFLAGS)

# -- diff (L2 native-codec differential) --------------------------------------
# codec.s is a standalone native codec (no libc, no FFI): assemble + link the C
# harness against it directly. corpus_vectors.h is generated host-side from the
# pinned .diag (container has no python3); regenerate with tools/gen-corpus-header.py.
.PHONY: diff
diff: $(OBJ)/codec.o | $(BIN)
	$(CC) $(LDFLAGS) -O0 -I tools -o $(BIN)/diff tools/diff-harness.c $(OBJ)/codec.o $(CODEC_LDFLAGS)
	$(BIN)/diff

# -- parse-test (ec_peerid_parse accept + reject paths) -----------------------
# The corpus has no peer-id PARSE vector (peer_id.N are encode_equal only), so this
# unit drives the base58/LEB128 DECODE accept-path + reject paths. codec.o's
# ec_content_hash references ec_sha256, so link the .so too.
.PHONY: parse-test
parse-test: $(OBJ)/codec.o | $(BIN)
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
