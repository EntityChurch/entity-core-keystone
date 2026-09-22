#!/usr/bin/env python3
"""Build a pure-python wheel from a project's ``pyproject.toml``, with the stdlib only.

Why this exists: the sealed toolchain image (``--network=none``) carries no build backend
(no hatchling, no setuptools), so ``pip wheel`` cannot run.  The keystone peer contract's
``embed.package`` needs the contract host to be a SEPARATE PACKAGE that reaches the peer only
through the peer's DISTRIBUTION — so run-contract.sh builds both projects as wheels with this
script and installs them with ``pip install --no-index``, which is where the dependency is
actually resolved.  Everything in the wheel's metadata is read from the project's own
``[project]`` table and ``[tool.hatch.build.targets.wheel].packages`` — nothing is restated.

The output is deterministic (sorted entries, fixed zip timestamps), so the wheel's sha256 is a
meaningful delivery artifact digest.

Usage: wheel.py <project-dir> <out-dir>      prints the wheel path
"""

from __future__ import annotations

import base64
import hashlib
import io
import pathlib
import re
import sys
import tomllib
import zipfile

_EPOCH = (1980, 1, 1, 0, 0, 0)


def _dist_filename(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def build(project: pathlib.Path, out: pathlib.Path) -> pathlib.Path:
    doc = tomllib.loads((project / "pyproject.toml").read_text())
    proj = doc["project"]
    name, version = proj["name"], proj["version"]
    packages = doc["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]

    files: list[tuple[str, bytes]] = []
    for pkg in packages:
        src = project / pkg
        if not src.is_dir():
            raise SystemExit(f"wheel.py: package directory {src} is missing")
        for f in sorted(src.rglob("*")):
            if f.is_dir() or "__pycache__" in f.parts or f.suffix in (".pyc", ".pyo"):
                continue
            arc = pathlib.PurePosixPath(src.name, *f.relative_to(src).parts)
            files.append((str(arc), f.read_bytes()))

    dist_info = f"{_dist_filename(name)}-{version}.dist-info"
    meta = [
        "Metadata-Version: 2.1",
        f"Name: {name}",
        f"Version: {version}",
    ]
    if proj.get("description"):
        meta.append(f"Summary: {proj['description']}")
    if proj.get("requires-python"):
        meta.append(f"Requires-Python: {proj['requires-python']}")
    for dep in proj.get("dependencies", []):
        meta.append(f"Requires-Dist: {dep}")
    files.append((f"{dist_info}/METADATA", ("\n".join(meta) + "\n").encode()))
    files.append((f"{dist_info}/WHEEL", (
        "Wheel-Version: 1.0\nGenerator: keystone-contract-wheel.py\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    ).encode()))
    scripts = proj.get("scripts") or {}
    if scripts:
        ep = "[console_scripts]\n" + "".join(f"{k} = {v}\n" for k, v in sorted(scripts.items()))
        files.append((f"{dist_info}/entry_points.txt", ep.encode()))

    record = "".join(f"{arc},{_record_hash(data)},{len(data)}\n" for arc, data in files)
    record += f"{dist_info}/RECORD,,\n"
    files.append((f"{dist_info}/RECORD", record.encode()))

    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{_dist_filename(name)}-{version}-py3-none-any.whl"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arc, data in files:
            zi = zipfile.ZipInfo(arc, date_time=_EPOCH)
            zi.external_attr = 0o644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, data)
    path.write_bytes(buf.getvalue())
    return path


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(build(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])))
