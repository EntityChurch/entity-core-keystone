#!/bin/sh
# Crypto-agility byte-verification harness — entity-core-protocol-ocaml.
#
# Runs the hybrid agility seam: Ed25519 + SHA-256/384 native, Ed448 (key_type
# 0x02) from libentitycore_codec over the C-ABI v1.1 (A-OC-002). Builds + runs
# entirely inside the ocaml-toolchain container, sealed-offline (--network=none).
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none -v "$PWD":/work:Z \
#     entity-core-keystone/ocaml-toolchain:latest sh /work/protocol-generator/ocaml/run-agility.sh
#
# FFI impl selection: defaults to the self-contained C impl (libc-only). Set
# FFI=rust to link/load the Rust impl instead — the artifact is byte-
# interchangeable (provenance is printed via ec_impl_info at run start).

set -eu

FFI="${FFI:-c}"
case "$FFI" in
  c)    SODIR=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build ;;
  rust) SODIR=/work/ffi-generator/c-abi/entity-core-codec-ffi-rust/target/release ;;
  *)    echo "unknown FFI impl: $FFI (want c|rust)" >&2; exit 2 ;;
esac

if [ ! -f "$SODIR/libentitycore_codec.so" ]; then
  echo "missing $SODIR/libentitycore_codec.so — build the FFI codec first" >&2
  exit 1
fi

PROJ=/work/protocol-generator/ocaml
cd "$PROJ"
eval "$(opam env --switch=ec-ocaml)"

# EC_AGILITY enables the guarded entitycore_agility lib + agility.exe stanzas;
# LIBRARY_PATH resolves -lentitycore_codec at link; LD_LIBRARY_PATH at runtime.
export EC_AGILITY=1
export LIBRARY_PATH="$SODIR${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$SODIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

dune build test/agility.exe
exec dune exec test/agility.exe
