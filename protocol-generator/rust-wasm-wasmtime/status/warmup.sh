#!/bin/sh
# Cold-warmup probe: wall time from `wasmtime run` launch to the peer printing LISTENING.
# AOT (.cwasm, precompiled Cranelift-native) vs JIT (.wasm, Cranelift-compiled at load),
# SAME runtime — the AOT column the WasmEdge/JIT peers could not produce. Run inside the
# rust-wasm-wasmtime-toolchain container (needs out/peer.{wasm,cwasm} built via `make aot`).
set -eu
PROJ=/work/protocol-generator/rust-wasm-wasmtime
cd "$PROJ"
now() { date +%s.%N; }
measure() {
  MODULE="$1"; PRE="$2"; LABEL="$3"; PORT="$4"
  start=$(now)
  wasmtime run -S preview2=n -S tcplisten="127.0.0.1:$PORT" $PRE "$MODULE" \
    --debug-open-grants >/tmp/w.out 2>/tmp/w.err &
  pid=$!
  while ! grep -q '^LISTENING' /tmp/w.out 2>/dev/null; do
    kill -0 "$pid" 2>/dev/null || { echo "$LABEL: EXITED EARLY"; cat /tmp/w.err; return; }
  done
  end=$(now)
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  awk -v s="$start" -v e="$end" -v l="$LABEL" 'BEGIN{ printf "%s warmup: %.4fs\n", l, e - s }'
}
for i in 1 2 3; do
  measure out/peer.cwasm --allow-precompiled "AOT(.cwasm)" 7801
  measure out/peer.wasm  ""                  "JIT(.wasm) " 7802
done
echo "--- sizes ---"
echo "peer.wasm  : $(wc -c < out/peer.wasm) bytes  (portable module)"
echo "peer.cwasm : $(wc -c < out/peer.cwasm) bytes  (AOT native, wasmtime-46-specific)"
