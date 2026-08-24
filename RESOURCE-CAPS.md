# Resource Caps — `make` + `podman` standard

Per-container resource ceilings so a containerized build or run can't take the
host down (memory thrash → freeze, or a fork bomb). This is the standard across
entity-systems projects; the knobs live in the `Makefile` and are overridable
per-machine without editing tracked files.

## How it works

The `Makefile` defines cap variables with `?=` (override-able) and assembles two
flag strings applied to every podman call:

```
CAP_MEM   → --memory       (build + run)
CAP_SWAP  → --memory-swap  (build + run)   kept == CAP_MEM ⇒ no swap
CAP_PIDS  → --pids-limit   (run only)
CAP_CPUS  → --cpus         (run only)
CAP_CGROUP_PARENT → --cgroup-parent (build + run, if set)
```

**Precedence (highest first): env var → `caps.local.mk` → committed defaults.**

**`CAP_SWAP == CAP_MEM` means zero swap on purpose.** A container that hits the
ceiling is OOM-killed cleanly *at* the cap, instead of being allowed to spill
into swap and thrash the whole host into an unresponsive freeze. Raise swap
above mem only deliberately.

### The one gotcha: build and run take different flags

Verified on podman 5.8: `podman build` accepts **only** `--memory`,
`--memory-swap`, and `--cgroup-parent` — **not** `--cpus` or `--pids-limit`.
`podman run` accepts the full set. That's why there are two strings
(`PODMAN_BUILD_CAPS`, `PODMAN_RUN_CAPS`); a single merged string errors on
build. Don't combine them.

Build-time fork-bomb protection therefore can't come from `--pids-limit` (no
such flag on build). It comes from capping the build's own parallelism
(`go build -p N`, `make -jN`, `cargo -j`) and/or the host-wide `dev-heavy.slice`
below.

## Per-machine overrides (no edit to the tracked Makefile)

- **One-off via env:**
  ```bash
  CAP_MEM=2g CAP_CPUS=2 make build
  ```
- **Persistent:** create `caps.local.mk` next to the Makefile (it's
  `.gitignore`d). Use `?=` so an env one-off still wins:
  ```make
  # caps.local.mk — per-machine, NOT committed
  CAP_MEM  ?= 12g
  CAP_CPUS ?= 8
  CAP_PIDS ?= 8192
  CAP_CGROUP_PARENT ?= dev-heavy.slice
  ```

## Committed defaults for this project

| Knob | Value | Rationale |
|------|-------|-----------|
| `CAP_MEM` / `CAP_SWAP` | `4g` | Heaviest target `make race` peaks ~2.5 GiB; 4g gives ~60% headroom (absorbs sampling miss + growth) and is still genuinely protective. |
| `CAP_PIDS` | `2048` | Ample for the Go toolchain; trips only a runaway. |
| `CAP_CPUS` | `8` | Of 12 host cores — leaves the desktop responsive while letting the build parallelize. |

Measured peaks (this repo, golang:1.25 toolchain image, host 12c/46G, sampled
via `podman stats` at 2s):

| Target | Peak container memory |
|--------|-----------------------|
| `make build` | ~1.9 GiB |
| `make test` | ~2.2 GiB |
| `make race` | ~2.5 GiB |

These are the honest requirement. A machine that can't meet the committed
`CAP_MEM` fails cleanly at the cap rather than freezing; bump it locally via
`caps.local.mk` if your box has the headroom and you want more.

## Runtime peer caps (peer-manager)

The caps aren't only a build-time concern. `peer-manager` launches the Rust and
Python peers as `podman run` containers (see `cmd/peer-manager/podman.go`), and a
runaway peer must not take the host down either. Every peer container is capped
the same way — a peer is a `podman run`, so it gets the full set
(`--memory`, `--memory-swap`, `--pids-limit`, `--cpus`).

peer-manager honors the same `CAP_*` env vars (the env layer of the precedence
chain), but its **committed defaults are sized for a running peer** — an
in-memory store + network listener, far lighter than a build — not the
Makefile's build/test numbers:

| Knob | peer default | Note |
|------|--------------|------|
| `CAP_MEM` / `CAP_SWAP` | `2g` | Validation peers use tens–hundreds of MB; 2g is generous + protective. |
| `CAP_PIDS` | `1024` | Plenty for the tokio / asyncio thread pools; trips only a fork bomb. |
| `CAP_CPUS` | `2` | A peer is not CPU-bound; keeps one peer from hogging during multi-peer runs. |

Override per-run exactly like a build, e.g. `CAP_MEM=512m make` … or
`CAP_MEM=4g go run ./cmd/peer-manager start --name p --type rust`. (peer-manager
reads the env layer only — `caps.local.mk` is Make syntax and applies to the
Makefile targets.)

## Host-wide protection (optional): `dev-heavy.slice`

The per-container caps bound one container. To bound *all* dev work on a machine
at once (and to get build-time `TasksMax` fork-bomb protection that
`podman build` can't provide per-container), nest containers under a systemd
slice and set `CAP_CGROUP_PARENT=dev-heavy.slice` in `caps.local.mk`.

Example host unit (`/etc/systemd/system/dev-heavy.slice`, root-owned, per-machine
— never committed):

```ini
[Slice]
MemoryMax=24G
MemorySwapMax=24G
TasksMax=16384
CPUQuota=800%
```

```bash
sudo systemctl daemon-reload      # then set CAP_CGROUP_PARENT in caps.local.mk
```

This is a per-machine concern, not a committed default — only set
`CAP_CGROUP_PARENT` on machines where the slice exists.

## Sizing the committed defaults for a new project

1. Run the heaviest target once and watch peak memory:
   `podman stats`, `/usr/bin/time -v`, or `systemd-cgtop`.
2. Set committed `CAP_MEM` to **peak + ~25%** — too low false-OOMs your own
   build; too high gives no protection.
3. `CAP_CPUS` ≈ what the build parallelizes to (often cores − 2 to keep the
   desktop usable).
4. `CAP_PIDS` `2048` is fine unless you hit pid-limit errors.

The committed value is the project's honest requirement, the same on every
machine; per-machine reality is expressed through env / `caps.local.mk` /
`dev-heavy.slice`.
