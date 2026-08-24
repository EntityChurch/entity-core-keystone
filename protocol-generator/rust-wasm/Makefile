# entity-core-protocol-rust-wasm — build the Rust peer as a wasm32-wasip1 module.
#
# Runs inside containers/rust-wasm-toolchain (rust + cargo + wasm std + wasmedge). The
# whole protocol payload is the sibling ../rust crate (path dep), compiled to wasm; this
# Makefile only orchestrates the cross-build + stages out/peer.wasm for run-s4.sh.
#
# Dev loop (assemble, cargo cache mounted so crate fetch is one-time):
#   podman run --memory=6g --memory-swap=6g --pids-limit=2048 --cpus=4 --rm \
#     -v "$PWD":/work:Z -v <cargo-cache>:/cargo:Z -w /work/protocol-generator/rust-wasm \
#     localhost/entity-core-keystone/rust-wasm-toolchain:latest make peer

TARGET   := wasm32-wasip1
BIN      := entity-peer-wasm
ARTIFACT := target/$(TARGET)/release/$(BIN).wasm
CARGOFLAGS ?=

.PHONY: peer clean size wat

peer: out/peer.wasm

out/peer.wasm: $(shell find src ../rust/src -name '*.rs') Cargo.toml ../rust/Cargo.toml
	cargo build --release --target $(TARGET) --bin $(BIN) $(CARGOFLAGS)
	mkdir -p out
	cp $(ARTIFACT) out/peer.wasm
	@echo "staged out/peer.wasm ($$(wc -c < out/peer.wasm) bytes)"

# Report module size (the Rust-wasm ⟷ hand-WAT code-size comparison; §5 of the eval).
size: out/peer.wasm
	@echo "rust-wasm peer.wasm: $$(wc -c < out/peer.wasm) bytes"
	@which wasm-opt >/dev/null 2>&1 && wasm-opt --version || true

# Disassemble for inspection (wabt).
wat: out/peer.wasm
	wasm2wat out/peer.wasm -o out/peer.wat
	@echo "wrote out/peer.wat"

clean:
	cargo clean
	rm -rf out
