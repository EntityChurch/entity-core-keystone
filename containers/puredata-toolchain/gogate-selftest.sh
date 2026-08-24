#!/usr/bin/env bash
# GO-gate self-test — baked into the puredata-toolchain image build (and runnable
# standalone). Asserts the S1 feasibility gate for the reactive-patch peer:
#   1. `pd -nogui -noaudio` boots headless (no X) and runs a .pd patch.
#   2. `[netreceive -b]` accepts a raw TCP connection and delivers bytes byte-clean.
#   3. A list sent back to [netreceive]'s inlet is written to the SAME connection
#      (stock Pd bidirectional TCP — no iemnet/mrpeach external needed).
# FATAL (exit 1) on any mismatch: the image is only valid if native binary TCP
# round-trips clean, incl. 0x00 / 0xFF.
set -u

PORT="${1:-15007}"
PATCH="$(mktemp --suffix=.pd)"
LOG="$(mktemp)"

cat > "$PATCH" <<EOF
#N canvas 0 0 500 400 12;
#X obj 40 40 netreceive -b ${PORT};
#X obj 40 110 list;
#X obj 260 110 print GOT;
#X connect 0 0 1 0;
#X connect 0 0 2 0;
#X connect 1 0 0 0;
EOF

pd -nogui -noaudio -stderr -open "$PATCH" > "$LOG" 2>&1 &
PDPID=$!
sleep 2

if ! kill -0 "$PDPID" 2>/dev/null; then
    echo "FATAL: pd did not stay alive"; cat "$LOG"; exit 1
fi

python3 - "$PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
payload = bytes([10, 20, 255, 0, 42, 200, 1])
s = socket.socket(); s.settimeout(4)
s.connect(("127.0.0.1", port))
s.sendall(payload); time.sleep(0.6)
back = s.recv(64); s.close()
print("GO-GATE sent:", list(payload), " echo:", list(back))
sys.exit(0 if back == payload else 1)
PY
RC=$?

kill "$PDPID" 2>/dev/null
rm -f "$PATCH" "$LOG"

if [ "$RC" -eq 0 ]; then
    echo "GO-GATE OK: headless pd + native binary TCP round-trip clean"
    exit 0
else
    echo "FATAL: GO-GATE binary TCP round-trip failed (rc=$RC)"
    exit 1
fi
