# entity-core-protocol-wasm-wat — build interface (thin make over wat2wasm + wasmedge).
#
# Runs inside containers/wasm-wat-toolchain (fedora:43 + wabt + wasmedge). The peer is
# hand-authored WebAssembly TEXT (.wat); the runtime (WasmEdge) supplies the flat
# wasi_snapshot_preview1 socket imports — the WASM analog of the asm peer's syscalls.
# All builds are offline (--network=none); loopback still works in the container netns.
#
# Verbs (converging on the ecosystem standard vocabulary):
#   make build   — assemble every src/*.wat -> build/*.wasm (+ wasm-validate).   [S2/S3]
#   make echo     — S1 SPIKE increment 1: run the echo module, prove sockets from raw WAT.
#   make clean

WAT2WASM  := wat2wasm
VALIDATE  := wasm-validate
WASMEDGE  := wasmedge
WASMMERGE := wasm-merge

SRC := src
OUT := out

# The codec SEAM artifact: the Rust C-ABI codec (entity-core-codec-ffi-rust) compiled to
# wasm32-wasip1, exporting the ec_* symbols + its memory. The WASM analog of the asm peer's
# libentitycore_codec.so. Overridable; defaults to the cargo build output in-repo.
CODEC_WASM ?= $(abspath ../../ffi-generator/c-abi/entity-core-codec-ffi-rust/target/wasm32-wasip1/release/entitycore_codec.wasm)

SOURCES := $(wildcard $(SRC)/*.wat)
WASMS   := $(patsubst $(SRC)/%.wat,$(OUT)/%.wasm,$(SOURCES))

$(OUT):
	mkdir -p $@

$(OUT)/%.wasm: $(SRC)/%.wat | $(OUT)
	$(WAT2WASM) $< -o $@
	$(VALIDATE) $@

.PHONY: build
build: $(WASMS)

# -- S1 spike (increment 1): the echo foundation -------------------------------
# Runs the module, waits for its LISTENING line, then drives a loopback echo round-trip
# entirely inside the container (bash /dev/tcp). Prints PASS/FAIL.
.PHONY: echo
echo: $(OUT)/echo.wasm
	@sh spike-echo.sh

.PHONY: echo

# -- S1 spike (increment 2): the codec seam ------------------------------------
# Assemble the interior (imports codec.memory + ec_sha256), fuse the compiled codec.wasm
# into it over one shared memory with wasm-merge (the "linker"), run the KAT under WasmEdge.
$(OUT)/ffismoke.wasm: $(SRC)/ffi-smoke.wat | $(OUT)
	$(WAT2WASM) $< -o $@

$(OUT)/ffismoke.combined.wasm: $(OUT)/ffismoke.wasm $(CODEC_WASM) | $(OUT)
	$(WASMMERGE) -all \
	  $(OUT)/ffismoke.wasm ffismoke \
	  $(CODEC_WASM) codec \
	  --rename-export-conflicts -o $@

.PHONY: ffi-smoke
ffi-smoke: $(OUT)/ffismoke.combined.wasm
	@sh spike-ffi.sh $(OUT)/ffismoke.combined.wasm

# -- increment 3: wire layer unit test (hand-rolled canonical-CBOR primitives) ---
# wire.wat (primitives, imports codec.memory) + wire-test.wat (harness) + codec.wasm
# (memory provider), fused with wasm-merge, run under WasmEdge; exit code = PASS/assert-id.
$(OUT)/wire.wasm: $(SRC)/wire.wat | $(OUT)
	$(WAT2WASM) $< -o $@
$(OUT)/wire-test.wasm: $(SRC)/wire-test.wat | $(OUT)
	$(WAT2WASM) $< -o $@

$(OUT)/wire-test.combined.wasm: $(OUT)/wire.wasm $(OUT)/wire-test.wasm $(CODEC_WASM) | $(OUT)
	$(WASMMERGE) -all \
	  $(OUT)/wire.wasm wire \
	  $(OUT)/wire-test.wasm wiretest \
	  $(CODEC_WASM) codec \
	  --rename-export-conflicts -o $@

.PHONY: wire-test
wire-test: $(OUT)/wire-test.combined.wasm
	@$(WASMEDGE) $< && echo "wire-test: PASS (canonical-CBOR reader/writer round-trip)" \
	  || { echo "wire-test: FAIL (assert id = exit code above)"; exit 1; }

# -- increment 3: identity KAT (peer_id + identity_hash over the seam) -----------
$(OUT)/identity.wasm: $(SRC)/identity.wat | $(OUT)
	$(WAT2WASM) $< -o $@
$(OUT)/identity-test.wasm: $(SRC)/identity-test.wat | $(OUT)
	$(WAT2WASM) $< -o $@

$(OUT)/identity-test.combined.wasm: $(OUT)/wire.wasm $(OUT)/identity.wasm $(OUT)/identity-test.wasm $(CODEC_WASM) | $(OUT)
	$(WASMMERGE) -all \
	  $(OUT)/wire.wasm wire \
	  $(OUT)/identity.wasm identity \
	  $(OUT)/identity-test.wasm idtest \
	  $(CODEC_WASM) codec \
	  --rename-export-conflicts -o $@

.PHONY: identity-test
identity-test: $(OUT)/identity-test.combined.wasm
	@$(WASMEDGE) $< && echo "identity-test: PASS (peer_id KAT + identity_hash over the seam)" \
	  || { echo "identity-test: FAIL (assert id = exit code above)"; exit 1; }

# -- the live peer: merge wire + identity + host + codec into one module ---------
$(OUT)/host.wasm: $(SRC)/host.wat | $(OUT)
	$(WAT2WASM) $< -o $@

$(OUT)/dispatch.wasm: $(SRC)/dispatch.wat | $(OUT)
	$(WAT2WASM) $< -o $@

$(OUT)/peer.wasm: $(OUT)/wire.wasm $(OUT)/identity.wasm $(OUT)/dispatch.wasm $(OUT)/host.wasm $(CODEC_WASM) | $(OUT)
	$(WASMMERGE) -all \
	  $(OUT)/wire.wasm wire \
	  $(OUT)/identity.wasm identity \
	  $(OUT)/dispatch.wasm dispatch \
	  $(OUT)/host.wasm host \
	  $(CODEC_WASM) codec \
	  --rename-export-conflicts -o $@

.PHONY: peer
peer: $(OUT)/peer.wasm

# stage-1 transport check: launch the peer, send a [len]-framed frame, verify the echo.
.PHONY: run-frame
run-frame: $(OUT)/peer.wasm
	@sh spike-frame.sh $(OUT)/peer.wasm

.PHONY: clean
clean:
	rm -rf $(OUT)
