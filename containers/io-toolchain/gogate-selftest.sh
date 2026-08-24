#!/usr/bin/env bash
# GO-gate self-test — baked into the io-toolchain image build (and runnable
# standalone). Asserts the S1 feasibility gate for the Io prototype-OO peer
# (protocol-generator/shared/evaluations/oz-io-viability.md §S1, 2026-07-15):
#   1. `io -e` boots headless (no X) and evaluates code.
#   2. The hand-built Socket addon loads (Server/Socket coroutine protos live).
#   3. A Server echo round-trips a raw TCP payload byte-identically,
#      including 0x00 / 0xFF (coroutine accept + read + write).
# FATAL (exit 1) on any mismatch: the image is only valid if headless Io +
# the coroutine TCP server are byte-clean.
set -u

PORT="${1:-15008}"
SCRIPT="$(mktemp --suffix=.io)"
LOG="$(mktemp)"

# Headless eval sanity first (cheap, fails fast).
if ! io -e '(6*7) print' 2>/dev/null | grep -q '^42'; then
    echo "FATAL: io -e headless eval failed"; io --version 2>&1 | head -2; exit 1
fi

cat > "$SCRIPT" <<EOF
Echo := Object clone
Echo handleSocketFromServer := method(aSocket, aServer,
    while(aSocket isOpen,
        if(aSocket read, aSocket write(aSocket readBuffer asString))
        aSocket readBuffer empty
    )
)
server := Server clone setPort(${PORT})
server handleSocket := method(aSocket,
    Echo clone @handleSocketFromServer(aSocket, self)
)
"LISTENING" println
File standardOutput flush
server start
EOF

io "$SCRIPT" > "$LOG" 2>&1 &
IOPID=$!
for i in $(seq 1 50); do
    grep -q LISTENING "$LOG" 2>/dev/null && break
    kill -0 "$IOPID" 2>/dev/null || { echo "FATAL: io server exited early"; cat "$LOG"; exit 1; }
    sleep 0.2
done

python3 - "$PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
payload = bytes([10, 20, 255, 0, 42, 200, 1])
deadline = time.time() + 15
last = None
while time.time() < deadline:
    try:
        s = socket.socket(); s.settimeout(4)
        s.connect(("127.0.0.1", port))
        break
    except OSError as e:
        last = e; time.sleep(0.3)
else:
    print("GO-GATE connect failed:", last); sys.exit(1)
s.sendall(payload)
back = b""
try:
    while len(back) < len(payload):
        chunk = s.recv(64)
        if not chunk: break
        back += chunk
except socket.timeout:
    pass
s.close()
print("GO-GATE sent:", list(payload), " echo:", list(back))
sys.exit(0 if back == payload else 1)
PY
RC=$?

kill "$IOPID" 2>/dev/null
[ "$RC" -ne 0 ] && cat "$LOG"
rm -f "$SCRIPT" "$LOG"

if [ "$RC" -eq 0 ]; then
    echo "GO-GATE OK: headless io + Socket-addon coroutine TCP round-trip clean (incl 0x00/0xFF)"
    exit 0
else
    echo "FATAL: GO-GATE binary TCP round-trip failed (rc=$RC)"
    exit 1
fi
