#!/bin/sh
# containers/koji-fetch.sh — fetch a pinned Fedora RPM from Koji's permanent build
# archive (kojipkgs.fedoraproject.org) instead of the rolling dnf `updates`/`fedora`
# repos.
#
# WHY: the dnf repos only carry the CURRENT + recent build of each package — once a
# newer build ships, the exact NVR a Containerfile pins (e.g. `gcc-15.2.1-7.fc43`)
# disappears from the repo metadata entirely, and `dnf install` fails with "No match
# for argument" months later even though the pin never changed. Eleven images hit
# this on 2026-07-27 (see AGENTS.md's durable-lessons section). Koji, the build
# system that PRODUCES those RPMs, retains every NVR ever built, forever, at a
# stable URL — pinning there is reproducible from any machine, indefinitely, with no
# machine-local cache.
#
# Koji's raw build archive predates distro signing (no GPG signature yet), so
# integrity here rides on a SHA-256 recorded at pin time, not GPG — the same trust
# model this repo already uses for the Nim/APL source tarballs (NIM_SHA256 etc.).
#
# Usage: koji-fetch.sh <source-package> <version> <release> <binary-pkg>:<sha256> [...]
#   koji-fetch.sh gcc 15.3.1 1.fc43 \
#     gcc:5361a544a8412eecfdfb1dc117749b637bfcd19de41eaa9468f94cade6cf1824 \
#     gcc-gnat:2275b0231f79569bda75021130e7afbf1647c1b91d3b31247fd4a7b822190f70
#
# <source-package> is the Koji/SRPM name, which is not always the binary package
# name — e.g. gcc/gcc-c++/gcc-gnat/libstdc++*/libasan/libubsan all come from the
# "gcc" source package; rust/cargo/clippy/rustfmt all come from "rust"; the dotnet
# SDK RPMs come from "dotnet9.0". Verify with a HEAD request against
# https://kojipkgs.fedoraproject.org/packages/<source>/<ver>/<rel>/x86_64/ before
# assuming binary name == source name.
#
# Downloads each <binary-pkg>-<version>-<release>.x86_64.rpm into $OUT_DIR (default
# /tmp/rpms), verifying its SHA-256 before leaving it for a subsequent
# `dnf install -y "$OUT_DIR"/*.rpm ...` (mixing local files and normal repo package
# names in one dnf invocation is fine — only the explicitly pinned NVRs need to ride
# this path; ordinary transitive deps keep resolving from the live repo as before).
set -eu

SRC="$1"; VER="$2"; REL="$3"; shift 3
OUT_DIR="${OUT_DIR:-/tmp/rpms}"
mkdir -p "$OUT_DIR"

for spec in "$@"; do
  name="${spec%%:*}"
  sha="${spec#*:}"
  if [ "$name" = "$spec" ]; then
    echo "koji-fetch: $spec has no :sha256 suffix — refusing to fetch unverified" >&2
    exit 2
  fi
  # Arch is per-BINARY, not per-source: a single source package ships x86_64 and noarch
  # subpackages side by side (glibc -> glibc-static is x86_64, sysroot-aarch64-fc43-glibc
  # is noarch; rust -> rust is x86_64, rust-std-static-wasm32-wasip1 is noarch). Hardcoding
  # x86_64 turned that into a 404 that reads exactly like a rotted NVR. Try both.
  out=""
  for arch in x86_64 noarch; do
    url="https://kojipkgs.fedoraproject.org/packages/${SRC}/${VER}/${REL}/${arch}/${name}-${VER}-${REL}.${arch}.rpm"
    cand="$OUT_DIR/${name}-${VER}-${REL}.${arch}.rpm"
    echo "koji-fetch: $url" >&2
    if curl -fsSL --max-time 60 -o "$cand" "$url"; then
      out="$cand"
      break
    fi
    rm -f "$cand"
  done
  if [ -z "$out" ]; then
    echo "koji-fetch: $name-$VER-$REL not found under source '$SRC' (tried x86_64, noarch)" >&2
    echo "  Wrong SOURCE package name is the usual cause, not a missing build." >&2
    echo "  Resolve it with: python3 tools/koji-pin.py resolve containers/<image>" >&2
    exit 1
  fi
  got="$(sha256sum "$out" | cut -d' ' -f1)"
  if [ "$got" != "$sha" ]; then
    echo "koji-fetch: SHA-256 mismatch for $name-$VER-$REL: expected $sha, got $got" >&2
    exit 1
  fi
done
