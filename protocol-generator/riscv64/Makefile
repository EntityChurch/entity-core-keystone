# entity-core-protocol-riscv64 — build interface (thin make over the riscv64 cross `as` +
# cc-driver, run under qemu-user). THIRD ISA port; off protocol-generator/asm-arm64 (the
# generic-syscall-table sibling), NOT asm-x86_64.
#
# Runs inside containers/riscv64-toolchain (fedora:43 + riscv64 cross binutils/gcc + a Debian
# trixie riscv64 glibc+libsodium sysroot + qemu-user-static-riscv). The FFI target
# libentitycore_codec.so is CROSS-BUILT for riscv64 into build-riscv64/ (see the `codec` target)
# and reached through the mounted /work tree — NOT baked into the image. All builds are offline.
#
# Verbs:
#   make codec       — cross-build the riscv64 libentitycore_codec.so (the FFI×ISA cost).  [S1]
#   make ffi-smoke   — de-risk the riscv64 asm→C-ABI bridge (ec_sha256 KAT) under qemu.  S1/S2 seam.
#   make host        — the live peer executable (riscv64 ELF, run under qemu).             [S3]
#   make clean

AS      := riscv64-linux-gnu-as
CC      := riscv64-linux-gnu-gcc          # LINK DRIVER only (crt0 + __libc_start_main). No C compiled.
QEMU    := qemu-riscv64-static
SYSROOT := $(if $(RISCV_SYSROOT),$(RISCV_SYSROOT),/opt/riscv64-sysroot)
# -march=rv64gc: base ISA (no Zbb — byte-swap is hand-rolled in macros.s, A-RISCV-001).
ASFLAGS := -g -Isrc -march=rv64gc
# Debian is multiarch + merged-usr: -B points the link driver at the arch subdir for startfiles
# (crt1.o/crti.o/crtn.o) + the -L that resolves -lc/-lgcc_s; --dynamic-linker names the guest
# loader (resolved under QEMU_LD_PREFIX at run time). -no-pie: hand-authored absolute/PC-rel asm.
LDFLAGS := --sysroot=$(SYSROOT) \
           -B$(SYSROOT)/usr/lib/riscv64-linux-gnu \
           -L$(SYSROOT)/usr/lib/riscv64-linux-gnu \
           -Wl,--dynamic-linker,/lib/ld-linux-riscv64-lp64d.so.1 \
           -no-pie

# The codec C-ABI, cross-built for riscv64. Overridable; defaults relative to this peer dir.
CODEC_SRC ?= $(abspath ../../ffi-generator/c-abi/entity-core-codec-ffi-c)
CODEC_DIR ?= $(CODEC_SRC)/build-riscv64
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

# -- codec (cross-build the riscv64 .so) --------------------------------------
.PHONY: codec
codec: $(CODEC_DIR)/libentitycore_codec.so
$(CODEC_DIR)/libentitycore_codec.so:
	cmake -S $(CODEC_SRC) -B $(CODEC_DIR) \
	  -DCMAKE_TOOLCHAIN_FILE=$(CODEC_SRC)/riscv64-cross-toolchain.cmake \
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

.PHONY: clean
clean:
	rm -rf $(OBJ) $(BIN)
