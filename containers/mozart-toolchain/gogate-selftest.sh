#!/usr/bin/env bash
# GO-gate self-test — baked into the mozart-toolchain image build (and runnable
# standalone). Asserts the S1 feasibility gate for the dataflow-variable peer:
#   1. `ozc -c` compiles and `ozengine` runs a functor headless (no display).
#   2. Dataflow threads work: `thread Y = X + 1 end` blocks on unbound X and
#      resumes on bind (the §7b paradigm axis, live under ozengine).
#   3. Oz integers are bignum: the [2^63, 2^64-1] head-form boundary carries
#      exactly (no fixed-width trap; profile's "no head-form self-test tax" claim).
#   4. `Open.socket` bind/listen/accept/read/write round-trips a TCP payload
#      byte-identically, incl. 0x00 / 0xFF.
#   5. `Open.pipe` to a spawned co-process round-trips bytes incl. 0x00 / 0xFF —
#      the entity-codec-daemon seam transport.
# FATAL (exit 1) on any mismatch.
set -u

PORT="${1:-47901}"
DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

cat > "$DIR/gogate.oz" <<EOF
functor
import
   System Application Open
define
   %% (2) dataflow threads
   local X Y in
      thread Y = X + 1 end
      thread X = 41 end
      {Wait Y}
      if Y \\= 42 then {System.showInfo 'FATAL: dataflow'} {Application.exit 1} end
   end
   %% (3) bignum integers across the uint64 head-form boundary
   local A B in
      A = 9223372036854775808      % 2^63
      B = 18446744073709551615     % 2^64-1
      if A + B \\= 27670116110564327423 orelse B + 1 \\= 18446744073709551616
      then {System.showInfo 'FATAL: bignum'} {Application.exit 1} end
   end
   %% (5) Open.pipe co-process byte-cleanliness (through /bin/cat)
   local P Xs in
      P = {New Open.pipe init(cmd:"/bin/cat" args:nil)}
      {P write(vs:[0 255 65 10 66 1 128])}
      {P read(list:?Xs size:7 len:_)}
      if Xs \\= [0 255 65 10 66 1 128]
      then {System.showInfo 'FATAL: pipe'} {Application.exit 1} end
      {P close}
   end
   %% (4) Open.socket echo server — one connection, echo 7 bytes, exit
   local Server Port A Xs in
      Server = {New Open.socket init}
      {Server bind(takePort:${PORT} port:Port)}
      {Server listen}
      {System.showInfo 'LISTENING '#Port}
      {Server accept(acceptClass:Open.socket accepted:?A)}
      {A read(list:?Xs size:7 len:_)}
      {A write(vs:Xs)}
      {A close}
   end
   {Application.exit 0}
end
EOF

cd "$DIR"
if ! ozc -c gogate.oz -o gogate.ozf > compile.log 2>&1; then
    echo "FATAL: ozc failed"; cat compile.log; exit 1
fi

ozengine gogate.ozf > run.log 2>&1 &
OZPID=$!
for i in $(seq 1 50); do
    grep -q '^LISTENING' run.log 2>/dev/null && break
    kill -0 "$OZPID" 2>/dev/null || { echo "FATAL: ozengine died"; cat run.log; exit 1; }
    sleep 0.1
done
grep -q '^LISTENING' run.log || { echo "FATAL: no LISTENING line"; cat run.log; exit 1; }

python3 - "$PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
payload = bytes([10, 20, 255, 0, 42, 200, 1])
s = socket.socket(); s.settimeout(5)
s.connect(("127.0.0.1", port))
s.sendall(payload); time.sleep(0.4)
back = s.recv(64); s.close()
print("GO-GATE sent:", list(payload), " echo:", list(back))
sys.exit(0 if back == payload else 1)
PY
RC=$?

wait "$OZPID" 2>/dev/null
OZRC=$?

if [ "$RC" -eq 0 ] && [ "$OZRC" -eq 0 ]; then
    echo "GO-GATE OK: headless ozc/ozengine + dataflow threads + bignum ints + byte-clean Open.socket echo + byte-clean Open.pipe"
    exit 0
else
    echo "FATAL: GO-GATE failed (client rc=$RC, ozengine rc=$OZRC)"; cat run.log
    exit 1
fi
