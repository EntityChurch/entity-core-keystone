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

# -- peers-scope-test (§5.2 `peers` grant dimension accept + reject paths) ----------------
# The conformance oracle has zero vectors for the `peers` dimension (see
# protocol-generator/shared/findings/peers-grant-dimension-oracle-gap.md), so
# this drives derive_handler/grant_scope_ok directly against hand-encoded CBOR fixtures — no
# FFI/.so link needed (dispatch.o's unrelated externs are stubbed in the test file itself).
#
# THIS TARGET IS THE ONE PLACE THIS PEER ACTUALLY COMPILES C, which is why it needs an
# include flag nothing else here does. $(CC) is described above as a LINK DRIVER only, and
# for the peer itself that is true. The Debian riscv64 sysroot is MULTIARCH (headers under
# usr/include/riscv64-linux-gnu) while the Fedora cross-gcc is not multiarch-aware, so a bare
# compile dies on `bits/libc-header-start.h: No such file or directory` -- which reads like a
# broken image and is not. The codec's riscv64-cross-toolchain.cmake has carried exactly this
# flag, with exactly this explanation, since the sysroot was built; it was simply never needed
# here until something tried to run this unit.
CROSS_INC := -I$(SYSROOT)/usr/include/riscv64-linux-gnu

.PHONY: peers-scope-test
peers-scope-test: $(OBJ)/dispatch.o $(OBJ)/cbor.o | $(BIN)
	$(CC) $(LDFLAGS) $(CROSS_INC) -O0 -o $(BIN)/peers-scope-test tools/peers-scope-test.c $(OBJ)/dispatch.o $(OBJ)/cbor.o
	QEMU_LD_PREFIX=$(SYSROOT) $(QEMU) $(BIN)/peers-scope-test

.PHONY: clean
clean:
	rm -rf $(OBJ) $(BIN)
