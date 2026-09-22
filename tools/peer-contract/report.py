#!/usr/bin/env python3
"""Compute a keystone peer contract report from evidence. Nothing here is hand-edited.

INPUTS (all paths repo-relative):
  --cases    the driver's case records          (run-contract.sh → cases.json)
  --local    the peer's local test output        (run-contract.sh → local.txt; libtest format)
  --plants   the plant run's results, optional   (plant.py → plants.json)
  --peer     the peer directory name under protocol-generator/
  --out      where to write the report

The contract is protocol-generator/shared/peer-contract/{requirements.toml, CONTRACT-DRAFT.md,
FIXTURE-HOST.md}; the report cites it by `contract_digest`, a sha256 over those three files'
bytes in that order.

VERDICT RULES — the same function `--check` recomputes, so a report cannot say more than its rows:
  driver requirement   every listed case present and passing, and at least one listed CONTROL
                       passing. A listed case absent from the run → `unknown`.
  local requirement    >= min_tests tests with the requirement's prefix ran, none failed.
                       None ran → `unknown`.
  MODULE               `pass`, or `declined` when the peer's contract/declined.toml says so with a
                       reason. Anything else → the verdict it measured (never silently declined).
  core conformance     the peer's COMMITTED status/CONFORMANCE-REPORT.json: 0 failed, executed
                       check set equal to tools/oracle-pin.env's core_executed_check_set_digest,
                       no budget_exhausted category.
  certified            core ok, every REQUIRED `pass`, every MODULE `pass` or `declined`.

Usage:
  report.py --peer rust --cases C --local L [--plants P] --out R [--artifact name=path ...]
  report.py --check [--quiet]      recompute every committed KEYSTONE-PEER-REPORT.json
"""

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tomllib

REPO = pathlib.Path(__file__).resolve().parents[2]
CONTRACT_DIR = REPO / "protocol-generator" / "shared" / "peer-contract"
CONTRACT_FILES = ["requirements.toml", "CONTRACT-DRAFT.md", "FIXTURE-HOST.md"]
PIN = REPO / "tools" / "oracle-pin.env"
GENERATOR = "tools/peer-contract/report.py"


def contract_digest(root=REPO):
    h = hashlib.sha256()
    for f in CONTRACT_FILES:
        h.update((root / "protocol-generator/shared/peer-contract" / f).read_bytes())
    return h.hexdigest()


def load_registry(root=REPO):
    return tomllib.loads((root / "protocol-generator/shared/peer-contract/requirements.toml").read_text())


def pinned_core_digest():
    for line in PIN.read_text().splitlines():
        line = line.split("#", 1)[0]
        if line.strip().startswith("core_executed_check_set_digest"):
            return line.split("=", 1)[1].strip()
    return None


def test_prefix(name):
    return name.replace(".", "_") + "__"


LIBTEST = re.compile(r"^test (.+?) \.\.\. (ok|FAILED|ignored)\s*$")


def parse_local(text):
    """libtest lines → {test name: outcome}. A doctest's name is the last path segment of the
    item it documents (`src/x.rs - peer::handler::name (line 9) - compile fail` → `name`)."""
    out = {}
    for line in text.splitlines():
        m = LIBTEST.match(line.strip())
        if not m:
            continue
        name, outcome = m.group(1), m.group(2)
        if " - " in name:
            item = name.split(" - ", 1)[1].split(" (line", 1)[0]
            name = item.split("::")[-1]
        out.setdefault(name, []).append(outcome)
    return out


def core_summary(peer, root=REPO):
    path = root / "protocol-generator" / peer / "status" / "CONFORMANCE-REPORT.json"
    if not path.is_file():
        return {"report": str(path.relative_to(root)), "ok": False, "reason": "no committed report"}
    raw = path.read_bytes()
    doc = json.loads(raw)
    names = sorted(f'{c["category"]}/{c["name"]}' for c in doc.get("checks", []))
    executed = hashlib.sha256("\n".join(names).encode()).hexdigest()
    starved = sorted({c["category"] for c in doc.get("checks", [])
                      if "budget_exhausted" in (c.get("message") or "")})
    s = doc.get("summary", {})
    pinned = pinned_core_digest()
    ok = s.get("failed", 1) == 0 and executed == pinned and not starved
    return {
        "report": str(path.relative_to(root)),
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "executed_check_set_digest": executed,
        "pinned_check_set_digest": pinned,
        "total": s.get("total"), "passed": s.get("passed"), "warned": s.get("warned"),
        "failed": s.get("failed"), "skipped": s.get("skipped"),
        "skips_note": "core-profile carve-out skips; every one is explained by tools/skip-provenance-gate.py",
        "starved_categories": starved,
        "ok": ok,
    }


def evaluate(registry, cases, local, declined):
    """Pure function of the evidence → requirement rows. `--check` calls this too."""
    controls = set(registry.get("controls", []))
    by_id = {c["id"]: c for c in cases}
    rows = []
    for req in registry["requirement"]:
        row = {"name": req["name"], "level": req["level"], "evidence": req["evidence"],
               "supersedes": req.get("supersedes", [])}
        if req["evidence"] == "driver":
            listed = req["cases"]
            present = [by_id[c] for c in listed if c in by_id]
            missing = [c for c in listed if c not in by_id]
            failed = [c["id"] for c in present if not c["pass"]]
            held = [c["id"] for c in present if c["pass"] and c["id"] in controls]
            row["cases"] = [{"id": c["id"], "pass": c["pass"], "control": c["id"] in controls,
                             "observed": c["observed"]} for c in present]
            if missing:
                row["verdict"], row["reason"] = "unknown", f"not measured: {missing}"
            elif failed:
                row["verdict"], row["reason"] = "fail", f"failed: {failed}"
            elif not held:
                row["verdict"], row["reason"] = "fail", "no control case held in this run"
            else:
                row["verdict"] = "pass"
        else:
            prefix = test_prefix(req["name"])
            mine = {n: o for n, o in local.items() if n.startswith(prefix)}
            ran = {n: o for n, o in mine.items() if any(x in ("ok", "FAILED") for x in o)}
            bad = sorted(n for n, o in ran.items() if "FAILED" in o)
            row["tests"] = sorted(ran)
            row["tests_run"], row["min_tests"] = len(ran), req.get("min_tests", 1)
            if bad:
                row["verdict"], row["reason"] = "fail", f"failed: {bad}"
            elif not ran:
                row["verdict"], row["reason"] = "unknown", f"no test named {prefix}* ran"
            elif len(ran) < row["min_tests"]:
                row["verdict"], row["reason"] = "fail", f"{len(ran)} of {row['min_tests']} required tests ran"
            else:
                row["verdict"] = "pass"
        if req["level"] == "MODULE" and row["verdict"] != "pass" and req["name"] in declined:
            row["measured_verdict"] = row["verdict"]
            row["verdict"], row["reason"] = "declined", declined[req["name"]]
        rows.append(row)
    return rows


def certify(rows, core_ok):
    required_ok = all(r["verdict"] == "pass" for r in rows if r["level"] == "REQUIRED")
    modules_ok = all(r["verdict"] in ("pass", "declined") for r in rows if r["level"] == "MODULE")
    return "certified" if (core_ok and required_ok and modules_ok) else "not-certified"


def git(*args):
    try:
        return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return ""


def image_digest(image):
    try:
        return subprocess.run(["podman", "image", "inspect", image, "--format", "{{.Id}}"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return ""


def build(args):
    registry = load_registry()
    cases_doc = json.loads((REPO / args.cases).read_text())
    local = parse_local((REPO / args.local).read_text()) if args.local and (REPO / args.local).is_file() else {}
    declined_path = REPO / "protocol-generator" / args.peer / "contract" / "declined.toml"
    declined = tomllib.loads(declined_path.read_text()).get("declined", {}) if declined_path.is_file() else {}
    rows = evaluate(registry, cases_doc.get("cases", []), local, declined)
    bindings_path = REPO / "protocol-generator" / args.peer / "contract" / "bindings.toml"
    bindings = tomllib.loads(bindings_path.read_text()).get("bindings", {}) if bindings_path.is_file() else {}
    for r in rows:
        r["binding"] = bindings.get(r["name"])
    core = core_summary(args.peer)
    verdict = certify(rows, core["ok"])
    artifacts = {}
    for a in args.artifact or []:
        name, _, p = a.partition("=")
        fp = REPO / p
        artifacts[name] = {"path": p, "sha256": hashlib.sha256(fp.read_bytes()).hexdigest() if fp.is_file() else None}
    prov = REPO / "output" / "s4-oracles" / "PROVENANCE.txt"
    report = {
        "contract": registry["contract"],
        "contract_version": registry["version"],
        "contract_digest": contract_digest(),
        "peer": args.peer,
        "generated_by": GENERATOR,
        "measured_at": cases_doc.get("started_at"),
        "verdict": verdict,
        "core_conformance": core,
        "requirements": rows,
        "summary": {
            "required": sum(1 for r in rows if r["level"] == "REQUIRED"),
            "required_pass": sum(1 for r in rows if r["level"] == "REQUIRED" and r["verdict"] == "pass"),
            "modules": {r["name"]: r["verdict"] for r in rows if r["level"] == "MODULE"},
            "driver_cases": len(cases_doc.get("cases", [])),
            "driver_cases_pass": sum(1 for c in cases_doc.get("cases", []) if c["pass"]),
        },
        "driver": {"version": cases_doc.get("driver"), "setup_error": cases_doc.get("setup_error"),
                   "ready_record": cases_doc.get("ready_record")},
        "delivery": {
            "commit": git("rev-parse", "HEAD"),
            "tree_dirty": bool(git("status", "--porcelain", "--", f"protocol-generator/{args.peer}",
                                   "protocol-generator/shared/peer-contract", "tools/peer-contract")),
            "artifacts": artifacts,
            "toolchain_image": {"name": args.image, "id": image_digest(args.image)} if args.image else None,
            "oracle_provenance_sha256": hashlib.sha256(prov.read_bytes()).hexdigest() if prov.is_file() else None,
        },
    }
    if args.plants and (REPO / args.plants).is_file():
        report["plants"] = json.loads((REPO / args.plants).read_text())
    out = REPO / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"report: {args.peer} → {verdict}  "
          f"({report['summary']['required_pass']}/{report['summary']['required']} REQUIRED pass, "
          f"modules {report['summary']['modules']}, core ok={core['ok']}, "
          f"{report['summary']['driver_cases_pass']}/{report['summary']['driver_cases']} driver cases)  → {args.out}")
    for r in rows:
        if r["verdict"] not in ("pass", "declined"):
            print(f"  {r['verdict']:8} {r['name']}: {r.get('reason', '')}")
    return 0


def contract_consistency(root=REPO):
    """The registry and the prose name the same requirements; every requirement has a normative
    statement and an observation; every driver case listed as a control is listed by a requirement."""
    errors = []
    registry = load_registry(root)
    names = [q["name"] for q in registry["requirement"]]
    text = (root / "protocol-generator/shared/peer-contract/CONTRACT-DRAFT.md").read_text()
    headed = re.findall(r"^###\s+([a-z_]+\.[a-z_]+)", text, re.MULTILINE)
    for n in names:
        if n not in headed:
            errors.append(f"contract: {n} is in requirements.toml but has no section in CONTRACT-DRAFT.md")
    for h in headed:
        if h not in names:
            errors.append(f"contract: CONTRACT-DRAFT.md has a section for {h}, which requirements.toml does not declare")
    sections = re.split(r"^###\s+", text, flags=re.MULTILINE)
    for sec in sections[1:]:
        name = sec.split(None, 1)[0]
        if name in names:
            if "**Normative.**" not in sec:
                errors.append(f"contract: {name} has no **Normative.** statement")
            if "**Observation.**" not in sec:
                errors.append(f"contract: {name} has no **Observation.**")
    listed = {c for q in registry["requirement"] for c in q.get("cases", [])}
    for c in registry.get("controls", []):
        if c not in listed:
            errors.append(f"contract: control {c} is not a case of any requirement")
    for q in registry["requirement"]:
        if q["evidence"] == "driver" and not any(c in registry.get("controls", []) for c in q["cases"]):
            errors.append(f"contract: {q['name']} lists no control case — its pass could be vacuous")
    return errors, len(names)


def check_report(peer, doc, registry, current):
    """Errors in one committed report, judged only against its own rows and the registry."""
    errors = []
    if doc.get("generated_by") != GENERATOR:
        return [f"{peer}: not generated by {GENERATOR}"]
    rows = doc.get("requirements", [])
    for r in rows:
        if r.get("evidence") == "driver" and r.get("verdict") == "pass":
            cs = r.get("cases", [])
            if not cs or not all(c["pass"] for c in cs) or not any(c["control"] and c["pass"] for c in cs):
                errors.append(f"{peer}: {r['name']} says pass but its own cases do not support it")
        if r.get("evidence") == "local" and r.get("verdict") == "pass" and r.get("tests_run", 0) < r.get("min_tests", 1):
            errors.append(f"{peer}: {r['name']} says pass with {r.get('tests_run')} < {r.get('min_tests')} tests")
    missing = {q["name"] for q in registry["requirement"]} - {r["name"] for r in rows}
    want = certify(rows, doc.get("core_conformance", {}).get("ok", False))
    if doc.get("contract_digest") == current and missing:
        errors.append(f"{peer}: report at the current contract lacks rows {sorted(missing)}")
        want = "not-certified"
    if doc.get("verdict") != want:
        errors.append(f"{peer}: verdict {doc.get('verdict')!r} but its rows compute {want!r}")
    return errors


def check(quiet=False):
    """Recompute every committed report's verdict from its own rows, and say which are stale."""
    reports = sorted(REPO.glob("protocol-generator/*/status/KEYSTONE-PEER-REPORT.json"))
    current = contract_digest()
    registry = load_registry()
    errors, n_requirements = contract_consistency()
    stale = []
    for p in reports:
        peer = p.parent.parent.name
        doc = json.loads(p.read_text())
        errors += check_report(peer, doc, registry, current)
        if doc.get("contract_digest") != current:
            stale.append(peer)
    if errors:
        print("peer-contract --check: FAIL", file=sys.stderr)
        for e in errors:
            print("  " + e, file=sys.stderr)
        return 1
    if not quiet or stale:
        print(f"peer-contract --check: OK — {n_requirements} requirements consistent; "
              f"{len(reports)} committed report(s) examined, verdicts recompute"
              + (f"; STALE against the current contract (reported, not failed): {stale}" if stale else ""))
    return 0


def self_test():
    """Plant each defect --check exists to catch; assert it is caught. Every plant is asserted
    APPLIED first — a mutation that silently fails to apply produces a confident green."""
    import shutil
    import tempfile
    failures = 0

    def expect(name, errors, needle):
        nonlocal failures
        if any(needle in e for e in errors):
            print(f"  ok   plant caught: {name}")
        else:
            failures += 1
            print(f"  FAIL plant NOT caught: {name} (wanted {needle!r}, got {errors})", file=sys.stderr)

    clean, n = contract_consistency()
    if clean:
        print(f"self-test: the clean contract must pass first: {clean}", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        dst = root / "protocol-generator/shared/peer-contract"
        shutil.copytree(CONTRACT_DIR, dst)
        draft = (dst / "CONTRACT-DRAFT.md").read_text()
        cut = draft.replace("### context.frame_budget", "### context.frame-budget-removed")
        assert cut != draft, "plant did not apply: section heading"
        (dst / "CONTRACT-DRAFT.md").write_text(cut)
        expect("requirement with no section", contract_consistency(root)[0], "has no section")
        (dst / "CONTRACT-DRAFT.md").write_text(draft)
        reg = (dst / "requirements.toml").read_text()
        noctl = reg.replace('  "context.frame_budget/by-value",\n', "", 1)
        assert noctl != reg, "plant did not apply: control removal"
        (dst / "requirements.toml").write_text(noctl)
        expect("driver requirement with no control", contract_consistency(root)[0], "lists no control")

    registry = load_registry()
    rows = evaluate(registry, [], {}, {})
    forged = {"generated_by": GENERATOR, "contract_digest": "x", "verdict": "certified",
              "core_conformance": {"ok": True}, "requirements": rows}
    expect("forged certified verdict", check_report("plant", forged, registry, "y"), "rows compute")
    lying = json.loads(json.dumps(forged))
    lying["verdict"] = "not-certified"
    for r in lying["requirements"]:
        if r["evidence"] == "driver":
            r["verdict"], r["cases"] = "pass", [{"id": "x", "pass": True, "control": False, "observed": ""}]
            break
    expect("pass row with no control that held", check_report("plant", lying, registry, "y"), "do not support it")
    hand = dict(forged, generated_by="a person")
    expect("hand-written report", check_report("plant", hand, registry, "y"), "not generated by")

    if n < 20:
        failures += 1
        print(f"  FAIL vacuity: only {n} requirements examined", file=sys.stderr)
    else:
        print(f"  ok   vacuity control: {n} requirements examined, not zero")
    print("peer-contract --self-test:", "OK" if not failures else f"{failures} FAILED")
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--peer")
    ap.add_argument("--cases")
    ap.add_argument("--local")
    ap.add_argument("--plants")
    ap.add_argument("--out")
    ap.add_argument("--image")
    ap.add_argument("--artifact", action="append")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if a.check:
        return check(a.quiet)
    if not (a.peer and a.cases and a.out):
        ap.error("--peer, --cases and --out are required")
    return build(a)


if __name__ == "__main__":
    sys.exit(main())
