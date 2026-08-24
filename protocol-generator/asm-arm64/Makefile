# entity-core-protocol-asm-arm64 — build interface (thin make over the aarch64 cross `as` +
# cc-driver, run under qemu-user). First ISA port off protocol-generator/asm-x86_64.
#
# Runs inside containers/asm-arm64-toolchain (fedora:43 + aarch64 cross binutils/gcc + the
# aarch64 glibc sysroot + qemu-user-static-aarch64). The FFI target libentitycore_codec.so is
# CROSS-BUILT for aarch64 into build-aarch64/ (see the `codec` target) and reached through the
# mounted /work tree — NOT baked into the image. All builds are offline (--network=none).
#
# Verbs:
#   make codec       — cross-build the aarch64 libentitycore_codec.so (the FFI×ISA cost).  [S1]
#   make ffi-smoke   — de-risk the aarch64 asm→C-ABI bridge (ec_sha256 KAT) under qemu.  S1/S2 seam.
#   make host        — the live peer executable (aarch64 ELF, run under qemu).             [S3]
#   make clean

AS      := aarch64-linux-gnu-as
CC      := aarch64-linux-gnu-gcc          # LINK DRIVER only (crt0 + __libc_start_main). No C compiled.
QEMU    := qemu-aarch64-static
SYSROOT := /usr/aarch64-redhat-linux/sys-root/fc43
ASFLAGS := -g -Isrc
# -no-pie: hand-authored asm uses absolute/PC-relative addressing (A-ASM-001, adrp/:lo12:).
LDFLAGS := --sysroot=$(SYSROOT) -no-pie

# The codec C-ABI, cross-built for aarch64. Overridable; defaults relative to this peer dir.
CODEC_SRC ?= $(abspath ../../ffi-generator/c-abi/entity-core-codec-ffi-c)
CODEC_DIR ?= $(CODEC_SRC)/build-aarch64
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

# -- codec (cross-build the aarch64 .so) --------------------------------------
.PHONY: codec
codec: $(CODEC_DIR)/libentitycore_codec.so
$(CODEC_DIR)/libentitycore_codec.so:
	cmake -S $(CODEC_SRC) -B $(CODEC_DIR) \
	  -DCMAKE_TOOLCHAIN_FILE=$(CODEC_SRC)/aarch64-cross-toolchain.cmake \
	  -DCMAKE_BUILD_TYPE=Release
	cmake --build $(CODEC_DIR) --target entitycore_codec -j4

# -- ffi-smoke (de-risk) ------------------------------------------------------
.PHONY: ffi-smoke
ffi-smoke: $(BIN)/ffi-smoke codec
	@QEMU_LD_PREFIX=$(SYSROOT) LD_LIBRARY_PATH=$(CODEC_DIR) $(QEMU) $(BIN)/ffi-smoke

$(BIN)/ffi-smoke: $(OBJ)/ffi_smoke.o | $(BIN)
	$(CC) $(LDFLAGS) -o $@ $< $(CODEC_LDFLAGS)

# -- host (live peer) ---------------------------------------------------------
HOST_OBJS := $(OBJ)/host.o $(OBJ)/dispatch.o $(OBJ)/cbor.o $(OBJ)/typestore.o
# macros.s is an .include (not a translation unit); changing it must rebuild all objs.
$(OBJ)/host.o $(OBJ)/dispatch.o $(OBJ)/cbor.o: $(SRC)/macros.s

.PHONY: host
host: $(BIN)/host
$(BIN)/host: $(HOST_OBJS) codec | $(BIN)
	$(CC) $(LDFLAGS) -o $@ $(HOST_OBJS) $(CODEC_LDFLAGS)

# -- peers-scope-test (§5.2 `peers` grant dimension accept + reject paths) ----------------
# The conformance oracle has zero vectors for the `peers` dimension (see
# research/stewardship/HANDOFF-TO-ARCH-2026-08-13-peers-grant-dimension-oracle-gap.md), so
# this drives derive_handler/grant_scope_ok directly against hand-encoded CBOR fixtures — no
# FFI/.so link needed (dispatch.o's unrelated externs are stubbed in the test file itself).
.PHONY: peers-scope-test
peers-scope-test: $(OBJ)/dispatch.o $(OBJ)/cbor.o | $(BIN)
	$(CC) $(LDFLAGS) -O0 -o $(BIN)/peers-scope-test tools/peers-scope-test.c $(OBJ)/dispatch.o $(OBJ)/cbor.o
	QEMU_LD_PREFIX=$(SYSROOT) $(QEMU) $(BIN)/peers-scope-test

.PHONY: clean
clean:
	rm -rf $(OBJ) $(BIN)
