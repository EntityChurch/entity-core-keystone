#!/usr/bin/env python3
"""Prove the contract suite can fail on a peer: plant each defect in a scratch copy and require the
named cases to go red. Writes protocol-generator/<peer>/status/KEYSTONE-PEER-PLANTS.json with --to-status.

A plant is a list of exact source edits (`anchor` → `replacement`) and the cases it must redden
(`expect_fail`, driver case ids) and/or local tests it must redden (`expect_local_fail`). The tool:

  1. copies protocol-generator/<peer>/ (without target/ and output/) to output/scratch/kpc-plants/<peer>/tree
  2. runs the UNPLANTED copy through the peer's own run-contract.sh — every case must pass, or the
     plants below would be measured against a red baseline and prove nothing
  3. for each plant: restores the pristine copy, asserts every anchor is PRESENT (a plant whose
     anchor moved applies nothing and passes vacuously — this repo has shipped that twice),
     applies it, runs run-contract.sh against the copy, and records which cases went red

A plant passes when every expected case failed. Other cases that also failed are recorded, not
judged: one defect legitimately breaks several things.

Usage: plant.py <peer> [--to-status] [--only name,name]
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]


def run_copy(peer, copy_rel, out_rel, target_rel, local):
    env = dict(os.environ, PEER_REL=copy_rel, OUT=out_rel, CARGO_TARGET_REL=target_rel,
               KPC_SKIP_LOCAL="0" if local else "1")
    script = REPO / "protocol-generator" / peer / "run-contract.sh"
    r = subprocess.run([str(script)], cwd=REPO, env=env, capture_output=True, text=True)
    cases_path = REPO / out_rel / "cases.json"
    cases = json.loads(cases_path.read_text()).get("cases", []) if cases_path.is_file() else []
    local_txt = (REPO / out_rel / "local.txt").read_text() if local and (REPO / out_rel / "local.txt").is_file() else ""
    return r.returncode, cases, local_txt, r.stderr[-2000:]


def failed_local(text):
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("test ") and line.endswith("FAILED"):
            name = line[5:].rsplit(" ... ", 1)[0]
            if " - " in name:
                name = name.split(" - ", 1)[1].split(" (line", 1)[0].split("::")[-1]
            out.add(name)
    return out


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    peer = args[0]
    to_status = "--to-status" in args
    only = None
    if "--only" in args:
        only = set(args[args.index("--only") + 1].split(","))
    spec = json.loads((REPO / "protocol-generator" / peer / "contract" / "plants.json").read_text())
    plants = [p for p in spec["plants"] if not only or p["name"] in only]

    base = REPO / "output" / "scratch" / "kpc-plants" / peer
    tree = base / "tree"
    src = REPO / "protocol-generator" / peer
    if tree.exists():
        shutil.rmtree(tree)
    # symlinks=True: copy a link as a link. Followed, node_modules/.bin/tsc became a file whose
    # relative require no longer resolved (a red baseline for a reason unrelated to the peer), and
    # a link to an ancestor directory would recurse without end.
    shutil.copytree(src, tree, symlinks=True, ignore=shutil.ignore_patterns("target", "output"))
    # Peer tests and build steps reach `../shared/` from the peer directory (seed-policy examples,
    # test vectors). The copy must see the same sibling, or the baseline is red for a reason that
    # has nothing to do with the peer.
    link = base / "shared"
    if not link.exists():
        link.symlink_to(os.path.relpath(REPO / "protocol-generator" / "shared", base))
    copy_rel = str(tree.relative_to(REPO))
    target_rel = str((base / "target").relative_to(REPO))

    need_local = any(p.get("expect_local_fail") for p in plants)
    print(f"plant: baseline (unplanted copy of {peer})")
    rc, cases, local_txt, err = run_copy(peer, copy_rel, str((base / "baseline").relative_to(REPO)), target_rel, need_local)
    red = [c["id"] for c in cases if not c["pass"]]
    baseline_ok = rc == 0 and cases and not red and not failed_local(local_txt)
    print(f"  baseline: rc={rc} cases={len(cases)} red={red} local_failed={sorted(failed_local(local_txt))}")
    if not baseline_ok:
        print("plant: the unplanted copy is not green — plants would prove nothing. stderr tail:\n" + err, file=sys.stderr)
        return 1

    results = []
    for p in plants:
        edits = p.get("edits") or [{"file": p["file"], "anchor": p["anchor"], "replacement": p["replacement"]}]
        for e in edits:
            shutil.copy2(src / e["file"], tree / e["file"])
        missing = []
        for e in edits:
            f = tree / e["file"]
            text = f.read_text()
            if e["anchor"] not in text:
                missing.append(e["file"])
                continue
            f.write_text(text.replace(e["anchor"], e["replacement"], 1))
        if missing:
            results.append({"name": p["name"], "applied": False, "caught": False,
                            "note": f"anchor absent in {missing} — the plant did not apply"})
            print(f"  NOT APPLIED {p['name']}: anchor absent in {missing}")
            continue
        local = bool(p.get("expect_local_fail"))
        rc, cases, local_txt, err = run_copy(peer, copy_rel, str((base / p["name"]).relative_to(REPO)), target_rel, local)
        red = sorted(c["id"] for c in cases if not c["pass"])
        lred = failed_local(local_txt)
        want = set(p.get("expect_fail", []))
        want_local = set(p.get("expect_local_fail", []))
        caught = (want <= set(red)) and (want_local <= lred) and (cases or not want)
        results.append({"name": p["name"], "applied": True, "caught": bool(caught),
                        "expect_fail": sorted(want), "expect_local_fail": sorted(want_local),
                        "red_cases": red, "red_local_tests": sorted(lred), "run_exit": rc})
        print(f"  {'CAUGHT' if caught else 'MISSED'} {p['name']}: expected {sorted(want | want_local)} red={red} local_red={sorted(lred)}"
              + ("" if cases or not want else f" (no cases — build failed? {err[-300:]})"))
        shutil.copy2(src / edits[0]["file"], tree / edits[0]["file"])
        for e in edits:
            shutil.copy2(src / e["file"], tree / e["file"])

    doc = {"generated_by": "tools/peer-contract/plant.py", "peer": peer, "baseline_green": True,
           "plants": results, "caught": sum(r["caught"] for r in results), "total": len(results)}
    dest = (REPO / "protocol-generator" / peer / "status" / "KEYSTONE-PEER-PLANTS.json") if to_status \
        else (base / "plants.json")
    dest.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"plant: {doc['caught']} of {doc['total']} plants caught → {dest.relative_to(REPO)}")
    return 0 if doc["caught"] == doc["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
