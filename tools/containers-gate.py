#!/usr/bin/env python3
"""containers-gate.py — the offline invariants that keep every image buildable.

An image nobody can rebuild is not a recipe, it is a local accident. Four properties
decide whether a clean pull can build this tree, and all four are checkable without
touching the network, so they run in `make lint` rather than waiting for a release:

  1. NO ROLLING dnf NVR PINS. Fedora's repos keep only the current build of a package;
     a pinned NVR vanishes when superseded and `dnf install` dies with "No match for
     argument" -- eleven images at once on 2026-07-27, `clang` twice in one day. Every
     pinned RPM must come from Koji's permanent archive instead.

  2. EVERY BASE IMAGE PINNED BY DIGEST. A tag is republished in place. `fedora:43`
     moved between 2026-06-17 and 2026-08-27, so every image pinning the tag floated
     on whatever the registry served that day.

  3. EVERY REMOTE DOWNLOAD VERIFIED BY DIGEST. A tarball fetched by URL with no
     sha256 check is neither reproducible nor safe. `beam` was pulling the Erlang/OTP
     source and the Elixir release with no check at all; `riscv64` resolved Debian
     package paths out of the CURRENT index and its own comment called that a feature.

  4. BUILD PARALLELISM BOUNDED. `podman build` here gets --memory=4g but no usable cpu
     cap (rootless cpuset is undelegated on this host; --cpus does not change nproc), so
     `make -j$(nproc)` starts one compiler per HOST core inside that ceiling and the OOM
     killer takes cc1plus. apl-toolchain failed exactly this way. Note the inversion:
     it gets WORSE on a bigger machine, so it is precisely the class an author does not
     hit and an adopter does.

What this gate CANNOT see: whether the pins still resolve, whether a pin group carries
its version-locked siblings, and whether the thing actually builds. Those need the
network and are covered by `koji-pin.py verify`, `koji-pin.py closure`, and
`cold-build-gate.sh` respectively. Passing here means the recipes are well-formed, not
that they work.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "kp", Path(__file__).resolve().parent / "koji-pin.py")
kp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kp)

# Internal images built from this repo -- reproducible because their own base is pinned.
INTERNAL_BASE = re.compile(r"^(localhost/)?entity-core-keystone/")
# A fetch of a remote artifact we must be able to verify. Bare `curl`/`wget` appearing
# as a PACKAGE NAME in a dnf list is not a download.
FETCH = re.compile(r"(?:curl|wget)\s[^\n]*?(https?://\S+)")


def check(root: Path, quiet: bool = False) -> int:
    fails = []
    cfs = kp.containerfiles(root)

    # 1 -- rolling dnf pins
    for cf in cfs:
        pins = kp.scan_pins(cf)
        if pins:
            names = ", ".join(f"{n}-{v}-{r}" for (n, v, r) in list(pins)[:4])
            fails.append(f"{cf.parent.name}: {len(pins)} rolling dnf NVR pin(s) -- {names}"
                         f"\n    convert: python3 tools/koji-pin.py resolve containers/{cf.parent.name}")

    # 2 -- base image digests
    for cf in cfs:
        for line in cf.read_text().splitlines():
            m = re.match(r"^FROM\s+(\S+)", line)
            if not m:
                continue
            ref = m.group(1)
            if "@sha256:" in ref or INTERNAL_BASE.match(ref):
                continue
            fails.append(f"{cf.parent.name}: base '{ref}' pinned by TAG, not digest"
                         f"\n    a tag is republished in place; resolve it with"
                         f" `skopeo inspect docker://{ref}`")

    # 3 -- unverified remote downloads
    for cf in cfs:
        text = cf.read_text()
        for line in kp.logical_lines(text):
            if line.lstrip().startswith("#"):
                continue
            for m in FETCH.finditer(line):
                url = m.group(1).strip('"\'')
                # the same command chain must verify what it fetched. A detached-
                # signature check is verification too, and a stronger one than a
                # recorded digest -- swift imports the project signing keys and runs
                # `gpg --verify` on the tarball, which this must not flag.
                if re.search(r"sha256sum\s+-c|SHA256|sha256:|gpg\s+--verify", line):
                    continue
                # koji-fetch verifies internally
                if "koji-fetch" in line or "kojipkgs" in url:
                    continue
                fails.append(f"{cf.parent.name}: downloads without a digest check"
                             f"\n    {url[:88]}")

    # 4 -- unbounded build parallelism
    for cf in cfs:
        for i, line in enumerate(cf.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if re.search(r"-j\s*\"?\$\(nproc\)", line):
                fails.append(
                    f"{cf.parent.name}:{i}: `-j$(nproc)` — unbounded build parallelism"
                    f"\n    podman build has a memory cap but no usable cpu cap here, so this"
                    f"\n    starts one compiler per HOST core inside --memory=4g and the OOM"
                    f"\n    killer takes cc1plus. Use `-j\"${{BUILD_JOBS}}\"` with ARG BUILD_JOBS=4.")

    if fails:
        print(f"containers-gate: {len(fails)} problem(s)\n")
        for f in fails:
            print(f"  {f}")
        print("\nSee containers/README.md -- 'Every image must build from a clean pull.'")
        return 1
    if not quiet:
        print(f"containers-gate: OK -- {len(cfs)} images, "
              f"0 rolling pins, all bases digest-pinned, all downloads verified, "
              f"parallelism bounded")
    return 0


if __name__ == "__main__":
    sys.exit(check(Path(__file__).resolve().parent.parent,
                   quiet="--quiet" in sys.argv))
