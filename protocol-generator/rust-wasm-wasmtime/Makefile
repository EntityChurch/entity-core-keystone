# entity-core-protocol-rust-wasm-wasmtime — build the Rust peer as a wasm32-wasip1
# module AND precompile it to a wasmtime `.cwasm` (Cranelift AOT — the whole point).
#
# Runs inside containers/rust-wasm-wasmtime-toolchain (rust + cargo + wasm std + a
# pinned wasmtime). The protocol payload is the sibling ../rust crate (path dep), the
# SAME interior as ../rust-wasm; this Makefile cross-builds it, stages out/peer.wasm,
# then `wasmtime compile`s out/peer.cwasm — native code, compiled once.
#
# Dev loop (cargo cache mounted so crate fetch is one-time):
#   podman run --memory=6g --memory-swap=6g --pids-limit=2048 --cpus=4 --rm \
#     -v "$PWD":/work:Z -v <cargo-cache>:/cargo:Z \
#     -w /work/protocol-generator/rust-wasm-wasmtime \
#     localhost/entity-core-keystone/rust-wasm-wasmtime-toolchain:latest make aot

TARGET   := wasm32-wasip1
BIN      := entity-peer-wasm-wasmtime
ARTIFACT := target/$(TARGET)/release/$(BIN).wasm
WASMTIME ?= wasmtime
CARGOFLAGS ?=

.PHONY: peer aot clean size

peer: out/peer.wasm

out/peer.wasm: $(shell find src ../rust/src -name '*.rs') Cargo.toml ../rust/Cargo.toml
	cargo build --release --target $(TARGET) --bin $(BIN) $(CARGOFLAGS)
	mkdir -p out
	cp $(ARTIFACT) out/peer.wasm
	@echo "staged out/peer.wasm ($$(wc -c < out/peer.wasm) bytes)"

# AOT: precompile the module to native Cranelift code — this is the compile-once-run-
# native artifact the whole phase is about. `.cwasm` is wasmtime-version-specific (a
# deploy-time recompile artifact, NOT portable across wasmtime versions — pinned runtime).
aot: out/peer.cwasm

out/peer.cwasm: out/peer.wasm
	$(WASMTIME) compile out/peer.wasm -o out/peer.cwasm
	@echo "staged out/peer.cwasm ($$(wc -c < out/peer.cwasm) bytes) — AOT native code"

# Size comparison: .wasm (portable) vs .cwasm (native) vs ../rust-wasm's WasmEdge module.
size: out/peer.wasm
	@echo "rust-wasm-wasmtime peer.wasm : $$(wc -c < out/peer.wasm) bytes"
	@[ -f out/peer.cwasm ] && echo "rust-wasm-wasmtime peer.cwasm: $$(wc -c < out/peer.cwasm) bytes (AOT)" || true

clean:
	cargo clean
	rm -rf out
