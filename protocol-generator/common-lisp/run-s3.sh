#!/usr/bin/env bash
# S3 peer machinery — the two-peer loopback smoke test, container-bound and
# sealed-offline (--network=none, loopback only). Boots a RESPONDER Common Lisp
# peer on a localhost port and drives the §4.1 handshake + core ops from a second
# CL peer acting as INITIATOR over real TCP, proving transport + handshake +
# register/dispatch + capability gating + request_id demux end-to-end.
#
#   ./run-s3.sh           # the two-peer loopback smoke gate (exits non-zero on FAIL)
#
# NOTE: `(require :asdf)` and `(require :sb-bsd-sockets)` MUST each be their own
# --eval, evaluated before any form that names those packages — SBCL's reader
# resolves `asdf:...` / `sb-bsd-sockets:...` at read time, before a preceding form
# in the SAME --eval string executes (the S2 run-s2.sh lesson).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/common-lisp-toolchain:latest"
WORKDIR="/work/protocol-generator/common-lisp"

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  sbcl --non-interactive \
    --eval '(require :asdf)' \
    --eval '(require :sb-bsd-sockets)' \
    --eval '(load #p"/opt/quicklisp/setup.lisp")' \
    --eval '(push (truename ".") asdf:*central-registry*)' \
    --eval '(handler-bind ((warning (function muffle-warning))) (asdf:load-system :entity-core/peer))' \
    --eval '(load "test/smoke.lisp")' \
    --eval '(unless (entity-core/smoke:run-smoke) (sb-ext:exit :code 1))'
