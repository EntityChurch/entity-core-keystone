#!/usr/bin/env python3
"""koji-pin.py — make every pinned RPM in containers/ resolvable forever.

WHY THIS EXISTS
---------------
Fedora's `fedora`/`updates` dnf repos carry only the CURRENT + recent build of each
package. A Containerfile that pins an exact NVR (`gcc-15.2.1-7.fc43`) builds fine until
that NVR is superseded, then dies with `No match for argument` — sometimes months later,
sometimes hours. This repo hit it on 2026-07-27 (eleven images) and again the same day
(`clang` 21.1.8-4 -> -6.fc43).

The response, both times, was to convert the ONE package that broke to `koji-fetch.sh`
and move on. AGENTS.md even wrote that down as policy: "Packages that haven't yet been
observed to rot stay on a plain `dnf install` pin; convert them the same way the first
time they do." That is a policy of waiting to be broken, and it left 36 of 46 images on
rolling pins.

This tool converts them all mechanically, so the conversion is not a per-incident
hand-edit. Koji retains every NVR ever built, forever, at a stable URL.

USAGE
-----
    koji-pin.py scan                      # inventory every dnf-pinned NVR in containers/
    koji-pin.py resolve <containerfile>   # emit the koji-fetch.sh block for one image
    koji-pin.py resolve --all             # ... for every image that still has dnf pins
    koji-pin.py verify                    # every already-recorded koji pin still resolves
                                          #   AND its sha256 still matches
    koji-pin.py closure                   # every recorded pin carries its version-locked
                                          #   siblings (an incomplete group looks like rot)

`resolve` performs network fetches (it must download each RPM to record its SHA-256 --
Koji's raw archive predates distro GPG signing, so the digest IS the integrity control).
It prints; it never edits a Containerfile. Applying the block is a deliberate human edit.
"""

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections import OrderedDict
from pathlib import Path

KOJI = "https://kojipkgs.fedoraproject.org/packages"
ARCHES = ("x86_64", "noarch")

# Binary package -> Koji SOURCE package. The SRPM name is not always the binary name,
# and guessing wrong yields a 404 that reads like "this NVR is gone" rather than "you
# asked for the wrong source".
#
# EXACT match only. An earlier cut of this table used prefix matching and mapped
# `gcc-riscv64-linux-gnu` -> `gcc`, which is wrong -- the cross compilers are their own
# source packages. A prefix rule over package names is unsound because Fedora freely
# names an unrelated package `<family>-<something>`. Anything not listed here falls
# through to a HEAD probe on the binary name, then to `dnf repoquery`, which is
# authoritative.
SRC_MAP = {
    # gcc source package -- the compiler drivers and its runtime libraries
    "gcc": "gcc", "gcc-c++": "gcc", "gcc-gnat": "gcc", "gcc-gfortran": "gcc",
    "cpp": "gcc", "libgcc": "gcc", "libgomp": "gcc",
    "libstdc++": "gcc", "libstdc++-devel": "gcc", "libstdc++-static": "gcc",
    "libgfortran": "gcc", "libgnat": "gcc", "libgnat-devel": "gcc",
    "libasan": "gcc", "libubsan": "gcc", "libtsan": "gcc", "liblsan": "gcc",
    "libatomic": "gcc", "libquadmath": "gcc", "libquadmath-devel": "gcc",
    # rust source package
    "rust": "rust", "cargo": "rust", "clippy": "rust", "rustfmt": "rust",
    "rust-std-static": "rust", "rust-std-static-wasm32-wasip1": "rust",
    "rust-std-static-wasm32-unknown-unknown": "rust",
    # llvm source package
    "clang": "llvm", "clang-libs": "llvm", "clang-devel": "llvm",
    "libcxx": "llvm", "libcxx-devel": "llvm", "libcxxabi": "llvm",
    "lld": "llvm", "lld-libs": "llvm", "llvm": "llvm", "llvm-libs": "llvm",
    # dotnet
    "dotnet-sdk-9.0": "dotnet9.0", "dotnet-runtime-9.0": "dotnet9.0",
    "dotnet-host": "dotnet9.0", "aspnetcore-runtime-9.0": "dotnet9.0",
    "dotnet-targeting-pack-9.0": "dotnet9.0",
    "dotnet-apphost-pack-9.0": "dotnet9.0",
    "netstandard-targeting-pack-2.1": "dotnet9.0",
    # multi-binary singles whose subpackages differ from the source name
    "libsodium-devel": "libsodium", "libsodium-static": "libsodium",
    "ninja-build": "ninja",
    "golang-bin": "golang", "golang-src": "golang", "golang-docs": "golang",
    "golang-misc": "golang", "golang-tests": "golang",
    "openssl-devel": "openssl", "openssl-libs": "openssl",
    "zlib-devel": "zlib-ng", "zlib-ng-compat-devel": "zlib-ng",
    # glibc ships both its own static half and the cross sysroots as subpackages --
    # `sysroot-<arch>-fc43-glibc` has no source package of its own, which reads as a
    # dead NVR if you probe the obvious name.
    "glibc-static": "glibc", "glibc-devel": "glibc",
    "sysroot-aarch64-fc43-glibc": "glibc",
    "sysroot-riscv64-fc43-glibc": "glibc",
    # cross toolchains are their own source packages, NOT `gcc`/`binutils`
    "gcc-aarch64-linux-gnu": "cross-gcc", "gcc-riscv64-linux-gnu": "cross-gcc",
    "binutils-aarch64-linux-gnu": "cross-binutils",
    "binutils-riscv64-linux-gnu": "cross-binutils",
    "qemu-user-static-aarch64": "qemu", "qemu-user-static-riscv": "qemu",
}

# An NVR token inside a `dnf install` argument list: name-[epoch:]version-release.fcNN
# The name is greedy up to the last `-` that begins a version field.
NVR_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9._+][A-Za-z0-9._+-]*?)"
    r"-(?:(?P<epoch>\d+):)?(?P<ver>[0-9][A-Za-z0-9._+~]*)"
    r"-(?P<rel>[0-9][A-Za-z0-9._+~^]*\.fc\d+)$"
)


def containerfiles(root: Path):
    return sorted(root.glob("containers/*/Containerfile"))


def logical_lines(text: str):
    """Join backslash continuations so a wrapped `dnf install` is one line.

    A per-line scan misses pins on continuation lines, which is where most of them
    live -- the same wrapped-span blindness that has cost this repo real time in
    link-gate and spec-pin scanning.
    """
    out, buf = [], ""
    for raw in text.splitlines():
        s = raw.rstrip()
        if s.endswith("\\"):
            buf += s[:-1] + " "
        else:
            out.append(buf + s)
            buf = ""
    if buf:
        out.append(buf)
    return out


def koji_fetch_args(text: str):
    """Package names already riding koji-fetch.sh (`name:sha256`) -- never re-convert."""
    names = set()
    for m in re.finditer(r"([A-Za-z0-9._+-]+):([0-9a-f]{64})", text):
        names.add(m.group(1))
    return names


def scan_pins(path: Path):
    """Every dnf-installed NVR in one Containerfile that is NOT already koji-fetched."""
    text = path.read_text()
    already = koji_fetch_args(text)
    found = OrderedDict()
    for line in logical_lines(text):
        if "dnf install" not in line and "dnf -y install" not in line:
            continue
        # strip the command head so flags/paths don't parse as packages
        for tok in line.split():
            tok = tok.strip("\\").strip()
            if not tok or tok.startswith("-") or tok.startswith("/") or ":" in tok.split("-")[0]:
                pass
            m = NVR_RE.match(tok)
            if not m:
                continue
            name = m.group("name")
            if name in already:
                continue
            key = (name, m.group("ver"), m.group("rel"))
            found[key] = m.group("epoch")
    return found


def source_for(name: str) -> str:
    return SRC_MAP.get(name, name)


def head_ok(url: str) -> bool:
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status == 200
    except Exception:
        return False


def repoquery_source(name: str, ver: str, rel: str) -> str | None:
    """Ask Fedora itself for the SRPM name. Authoritative, but only for NVRs still
    present in the repo -- a rotted pin cannot be resolved this way, which is exactly
    why SRC_MAP exists as the durable fallback."""
    try:
        out = subprocess.run(
            ["podman", "run", "--rm", "--memory=2g", "--memory-swap=2g",
             "registry.fedoraproject.org/fedora:43",
             "dnf", "repoquery", "--qf", "%{sourcerpm}", f"{name}-{ver}-{rel}"],
            capture_output=True, text=True, timeout=300,
        )
    except Exception as e:
        # Silent failure here is how a resolvable package gets reported UNRESOLVED and
        # then hand-pinned wrong. Say so.
        print(f"# repoquery unavailable for {name}-{ver}-{rel}: {e}", file=sys.stderr)
        return None
    if out.returncode != 0:
        print(f"# repoquery failed for {name}-{ver}-{rel}: "
              f"{out.stderr.strip().splitlines()[-1] if out.stderr.strip() else 'rc=' + str(out.returncode)}",
              file=sys.stderr)
    for line in out.stdout.splitlines():
        line = line.strip()
        if line.endswith(".src.rpm"):
            stem = line[: -len(".src.rpm")]
            m = re.match(r"^(.*)-[^-]+-[^-]+$", stem)
            if m:
                return m.group(1)
    return None


def resolve_url(name: str, ver: str, rel: str):
    """Return (url, source_pkg, arch) for a binary NVR, or None."""
    candidates = [source_for(name)]
    if candidates[0] != name:
        candidates.append(name)
    queried = False
    while True:
        for src in candidates:
            for arch in ARCHES:
                url = f"{KOJI}/{src}/{ver}/{rel}/{arch}/{name}-{ver}-{rel}.{arch}.rpm"
                if head_ok(url):
                    return url, src, arch
        if queried:
            return None
        queried = True
        got = repoquery_source(name, ver, rel)
        if not got or got in candidates:
            return None
        candidates = [got]


def sha256_of(url: str) -> str:
    h = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=180) as r:
        for chunk in iter(lambda: r.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_and_hash(url: str, dest: Path) -> str:
    h = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=300) as r, open(dest, "wb") as f:
        for chunk in iter(lambda: r.read(1 << 20), b""):
            h.update(chunk)
            f.write(chunk)
    return h.hexdigest()


def locked_requires(rpm_path: Path, ver: str, rel: str):
    """Package names this RPM requires at EXACTLY this version-release.

    Pinning a package from Koji without its version-locked siblings is the failure
    that broke five images on the first cold build: `rust-1.96.1-1.fc43` requires
    `rust-std-static(x86-64) = 1.96.1-1.fc43`, `golang` requires `golang-bin` and
    `golang-src` at its own NVR. dnf can no longer satisfy those from the rolling
    repo -- it has moved on -- so the pin MUST carry its closure. Reads as
    "nothing provides X = <the exact version you pinned>".
    """
    try:
        out = subprocess.run(["rpm", "-qpR", str(rpm_path)],
                             capture_output=True, text=True, timeout=120)
    except Exception as e:
        print(f"# cannot inspect {rpm_path.name} for locked deps: {e}", file=sys.stderr)
        return []
    names = []
    want = f"{ver}-{rel}"
    for line in out.stdout.splitlines():
        m = re.match(r"^([A-Za-z0-9._+-]+)(?:\([^)]*\))?\s*=\s*(?:\d+:)?(\S+)\s*$", line.strip())
        if m and m.group(2) == want:
            names.append(m.group(1))
    return sorted(set(names))


def cmd_scan(root: Path) -> int:
    total = 0
    images = 0
    for cf in containerfiles(root):
        pins = scan_pins(cf)
        if not pins:
            continue
        images += 1
        total += len(pins)
        print(f"\n{cf.parent.name}  ({len(pins)} dnf-pinned)")
        for (name, ver, rel) in pins:
            print(f"    {name}-{ver}-{rel}   [source: {source_for(name)}]")
    print(f"\n{total} rolling dnf pins across {images} images -- each one rots when superseded.")
    return 0


def emit(cf: Path) -> int:
    pins = scan_pins(cf)
    if not pins:
        print(f"# {cf.parent.name}: no rolling dnf pins -- nothing to convert")
        return 0
    groups = OrderedDict()
    unresolved = []
    tmp = Path(tempfile.mkdtemp(prefix="kojipin-"))
    # work-list, so a locked dependency discovered mid-resolve is itself resolved
    # (and can pull in its own locked deps in turn)
    queue = [(k, False) for k in pins.keys()]
    seen = set(pins.keys())
    try:
        while queue:
            (name, ver, rel), from_closure = queue.pop(0)
            got = resolve_url(name, ver, rel)
            if not got:
                if from_closure:
                    # A locked requirement that is not itself a package: `golang-bin`
                    # Requires `go = <nvr>`, and `go` is a VIRTUAL PROVIDE satisfied by
                    # a sibling already in the group. Not an error -- dropping it is
                    # correct, and failing on it would block a good pin.
                    print(f"#   .. {name}-{ver}-{rel} is a virtual provide, not a package"
                          f" -- skipped", file=sys.stderr)
                    continue
                unresolved.append(f"{name}-{ver}-{rel}")
                print(f"# UNRESOLVED {name}-{ver}-{rel} (source guess: {source_for(name)})",
                      file=sys.stderr)
                continue
            url, src, arch = got
            local = tmp / f"{name}-{ver}-{rel}.{arch}.rpm"
            digest = fetch_and_hash(url, local)
            groups.setdefault((src, ver, rel), []).append((name, digest, arch))
            extra = [d for d in locked_requires(local, ver, rel)
                     if (d, ver, rel) not in seen]
            for d in extra:
                seen.add((d, ver, rel))
                queue.append(((d, ver, rel), True))
            note = f"  +locked: {', '.join(extra)}" if extra else ""
            print(f"#   ok {name}-{ver}-{rel} <= {src} [{arch}]{note}", file=sys.stderr)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n# ---- {cf.parent.name} ----")
    for (src, ver, rel), members in groups.items():
        print(f"    && koji-fetch.sh {src} {ver} {rel} \\")
        for i, (name, digest, _arch) in enumerate(members):
            tail = " \\" if i < len(members) - 1 else ""
            print(f"        {name}:{digest}{tail}")
    if unresolved:
        print(f"# STILL UNRESOLVED: {', '.join(unresolved)}")
        return 1
    return 0


def cmd_resolve(root: Path, target: str | None, do_all: bool) -> int:
    rc = 0
    if do_all:
        for cf in containerfiles(root):
            if scan_pins(cf):
                rc |= emit(cf)
        return rc
    p = Path(target)
    if p.is_dir():
        p = p / "Containerfile"
    return emit(p)


def koji_groups(cf: Path):
    """Every (source, ver, rel) -> [binary names] already recorded in a Containerfile."""
    groups = []
    for line in logical_lines(cf.read_text()):
        m = re.search(r"koji-fetch\.sh\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$", line)
        if not m:
            continue
        src, ver, rel, rest = m.groups()
        names = [s.group(1) for s in re.finditer(r"([A-Za-z0-9._+-]+):([0-9a-f]{64})", rest)]
        if names:
            groups.append((src, ver, rel, names))
    return groups


def cmd_closure(root: Path) -> int:
    """Audit committed pins for MISSING version-locked siblings.

    Pinning `rust-1.96.1-1.fc43` from Koji without `rust-std-static` at the same NVR
    builds until the rolling repo moves past it, then fails with "nothing provides
    rust-std-static(x86-64) = 1.96.1-1.fc43". The image is not broken by the pin --
    it is broken by the pin being INCOMPLETE, which looks identical to rot and is
    invisible until the repo advances. Four images shipped in that state.
    """
    bad = 0
    tmp = Path(tempfile.mkdtemp(prefix="kojiclosure-"))
    try:
        for cf in containerfiles(root):
            for src, ver, rel, names in koji_groups(cf):
                have = set(names)
                for name in names:
                    got = resolve_url(name, ver, rel)
                    if not got:
                        continue
                    url, _s, arch = got
                    local = tmp / f"{name}-{ver}-{rel}.{arch}.rpm"
                    if not local.exists():
                        fetch_and_hash(url, local)
                    missing = []
                    for dep in locked_requires(local, ver, rel):
                        if dep in have:
                            continue
                        if resolve_url(dep, ver, rel):     # a real package, not a provide
                            missing.append(dep)
                    if missing:
                        print(f"INCOMPLETE {cf.parent.name}: {name}-{ver}-{rel} "
                              f"requires {', '.join(missing)} at the same NVR, not pinned")
                        bad += 1
                        have.update(missing)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{bad} incomplete pin group(s)")
    return 1 if bad else 0


def cmd_verify(root: Path) -> int:
    """Every recorded koji pin must still resolve AND still hash to what we recorded.

    This is the control that makes the pin a pin. A recorded sha256 nobody re-checks is
    a claim, not an anchor.
    """
    bad = 0
    checked = 0
    for cf in containerfiles(root):
        text = cf.read_text()
        for line in logical_lines(text):
            m = re.search(r"koji-fetch\.sh\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$", line)
            if not m:
                continue
            src, ver, rel, rest = m.groups()
            for spec in re.finditer(r"([A-Za-z0-9._+-]+):([0-9a-f]{64})", rest):
                name, want = spec.group(1), spec.group(2)
                checked += 1
                url = f"{KOJI}/{src}/{ver}/{rel}/x86_64/{name}-{ver}-{rel}.x86_64.rpm"
                if not head_ok(url):
                    url_n = f"{KOJI}/{src}/{ver}/{rel}/noarch/{name}-{ver}-{rel}.noarch.rpm"
                    if not head_ok(url_n):
                        print(f"GONE     {cf.parent.name}: {name}-{ver}-{rel}")
                        bad += 1
                        continue
                    url = url_n
                got = sha256_of(url)
                if got != want:
                    print(f"MISMATCH {cf.parent.name}: {name}-{ver}-{rel}\n"
                          f"         recorded {want}\n         actual   {got}")
                    bad += 1
    print(f"\n{checked} koji pins checked, {bad} bad")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=("scan", "resolve", "verify", "closure"))
    ap.add_argument("target", nargs="?")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--root", default=None)
    a = ap.parse_args()
    root = Path(a.root) if a.root else Path(__file__).resolve().parent.parent

    if a.command == "scan":
        return cmd_scan(root)
    if a.command == "closure":
        return cmd_closure(root)
    if a.command == "resolve":
        if not a.target and not a.all:
            ap.error("resolve needs a containerfile path or --all")
        return cmd_resolve(root, a.target, a.all)
    return cmd_verify(root)


if __name__ == "__main__":
    sys.exit(main())
