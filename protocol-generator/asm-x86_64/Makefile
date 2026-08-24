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
HOST_OBJS := $(OBJ)/host.o $(OBJ)/dispatch.o $(OBJ)/cbor.o $(OBJ)/typestore.o
# macros.s is an .include (not a translation unit); changing it must rebuild all objs.
$(OBJ)/host.o $(OBJ)/dispatch.o $(OBJ)/cbor.o: $(SRC)/macros.s

.PHONY: host
host: $(BIN)/host
$(BIN)/host: $(HOST_OBJS) | $(BIN)
	$(CC) $(LDFLAGS) -o $@ $(HOST_OBJS) $(CODEC_LDFLAGS)

.PHONY: clean
clean:
	rm -rf $(OBJ) $(BIN)
