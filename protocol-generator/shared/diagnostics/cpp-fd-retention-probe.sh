#!/bin/sh
# Does the cpp peer accumulate a file descriptor per connection?
#
# `Listener::Impl::conns` is push_back-only — nothing ever erases it — and `~Io`
# (which is what calls ::close on the socket) therefore cannot run until the
# listener is destroyed. `close_io()` only shutdown()s. Reading says one fd per
# connection is retained for the process lifetime; this asks the running peer.
#
# Sampled at three points so the answer is a CURVE, not a number: idle, after one
# full suite, after two. A leak grows; a high-water mark does not.
set -u
PORT=7821
KPDIR="${HOME:-/root}/.entity/peers/conformance"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"
cd /work/protocol-generator/cpp || exit 1
"${BUILD:-build-s4}/host" --port "$PORT" --name conformance --debug-open-grants --validate \
  >/tmp/c.out 2>/tmp/c.err &
hp=$!
w=0
while [ "$w" -lt 100 ]; do
  grep -q '^LISTENING' /tmp/c.out 2>/dev/null && break
  w=$((w + 1)); sleep 0.1
done
echo "fds idle:            $(ls /proc/$hp/fd 2>/dev/null | wc -l)"
/work/output/s4-oracles/validate-peer -addr "127.0.0.1:$PORT" -profile core \
  -json-out /tmp/c1.json 2>&1 | grep -m1 '^Summary:'
echo "fds after 1 suite:   $(ls /proc/$hp/fd 2>/dev/null | wc -l)"
/work/output/s4-oracles/validate-peer -addr "127.0.0.1:$PORT" -profile core \
  -json-out /tmp/c2.json 2>&1 | grep -m1 '^Summary:'
echo "fds after 2 suites:  $(ls /proc/$hp/fd 2>/dev/null | wc -l)"
echo "soft limit:          $(ulimit -n)"
kill "$hp" 2>/dev/null
