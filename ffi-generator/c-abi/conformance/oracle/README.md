# Interim dev oracle

Wraps the **real** entity-core-go reference encoder (`core/ecf.Encode` = fxamacker `CoreDetEncOptions`, RFC 8949 §4.2) and prints canonical ECF hex for a curated set of basic-ECF inputs. Lets the codec C-ABI impls (`entity-core-codec-ffi-{rust,c}`) and native codecs diff against the reference **during development**, before the arch-blessed fixture exists.

**This is NOT the authoritative conformance generator.** It produces nothing canonical-of-record. The versioned, cross-blessed fixture is architecture's to produce per `PROPOSAL-WIRE-ENCODING-CONFORMANCE-VECTORS.md` (Appendix E). When that lands, this oracle becomes a CI hash-check, not the source.

## How it consumes entity-core-go

`go.mod` has a relative `replace entity-core-go/core => ../../../../../entity-core-go/core` (sibling repo under `entity-systems/`). The container must therefore mount the **parent** (`entity-systems/`), preserving the sibling layout.

## Run

Verified with the inline command below (fedora:43 + golang 1.25.10). Preferred going forward: build `containers/go/` first (pinned, S11), then run.

```sh
# from entity-systems/ (the parent of both repos)
podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --security-opt label=disable \
  -v "$PWD":/work \
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=mod -e GOSUMDB=off \
  registry.fedoraproject.org/fedora:43 \
  bash -c "dnf install -y -q golang >/dev/null 2>&1; \
           cd /work/entity-core-keystone/ffi-generator/c-abi/conformance/oracle && go run ."
```

**Ownership gotcha (rootless podman):** the container runs as root, which maps to a host *subuid* (not your uid). If go writes `go.sum` etc., fix ownership afterward from the host with:

```sh
podman unshare chown -R 0:0 .
```

(`0:0` inside `podman unshare` = your real host user.) Avoid `chown 1000:1000` *inside* the container — that maps to the wrong subuid.

## What it validates

All printed bytes are correct canonical ECF: shortest-float (`1.0→f93c00`, `65504→f97bff`, `100000→fa47c35000`, NaN `f97e00`, `-0→f98000`), minimal ints, definite-length, length-then-lex key sort (`{"z":1,"aa":2}→a2617a0162616102`). Self-check: `ECF({})=a0`, `sha256(a0)=c19a797f…` → PASS.

## Finding it surfaced

**F5:** spec Appendix A.1 pins the empty-map wire hash as `44136fa3…`, which is **not** `sha256(0xA0)` (`=c19a797f…`, verified via Go + coreutils). No impl computes it. Escalated to arch — `research/stewardship/SPEC-FINDINGS-LOG.md` F5. This is the spec-quality-crawler payoff: a real encoder oracle caught a wrong pinned hash on first run.
