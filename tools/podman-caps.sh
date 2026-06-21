# Sourceable POSIX-sh podman resource caps — the shared standard for every
# `podman run` / `podman build` that the per-language run-scripts invoke
# directly (the Makefile carries the same caps for image builds). This is the
# entity-systems RESOURCE-CAPS.md standard applied OUTSIDE the Makefile so a
# runaway conformance host (e.g. a peer mis-handling an oversize frame) is
# OOM-killed cleanly at the cap instead of thrashing the host into a freeze.
#
# Usage (in a run-script, after REPO_ROOT is computed):
#     . "$REPO_ROOT/tools/podman-caps.sh"
#     podman run  $PODMAN_RUN_CAPS   ...     # full set: memory+zero-swap+pids+cpus
#     podman build $PODMAN_BUILD_CAPS ...     # build: memory+zero-swap only
#
# Override precedence (highest first):  env var  >  caps.local.{sh,mk}  >  defaults.
#   - one-off:      CAP_MEM=2g CAP_CPUS=2 ./run-s4.sh ...
#   - persistent:   gitignored caps.local.sh at repo root (sh syntax, use := form
#                   so env still wins):  : "${CAP_MEM:=12g}"
#   The Makefile reads caps.local.mk; this reads caps.local.sh — keep them in
#   sync if you set both. Committed defaults below match the Makefile.

# Per-machine persistent override (gitignored). Use `: "${CAP_X:=...}"` inside so
# an env var passed on the command line still wins.
_ec_caps_root="${REPO_ROOT:-${ROOT:-.}}"
[ -f "$_ec_caps_root/caps.local.sh" ] && . "$_ec_caps_root/caps.local.sh"

# Committed defaults — match the Makefile. CAP_SWAP == CAP_MEM => zero swap.
: "${CAP_MEM:=4g}"
: "${CAP_SWAP:=$CAP_MEM}"
: "${CAP_PIDS:=2048}"
: "${CAP_CPUS:=4}"

_ec_cgp=""
[ -n "${CAP_CGROUP_PARENT:-}" ] && _ec_cgp="--cgroup-parent=$CAP_CGROUP_PARENT"

# podman BUILD accepts memory/memory-swap/cgroup-parent only (NOT --cpus/--pids-limit).
PODMAN_BUILD_CAPS="--memory=$CAP_MEM --memory-swap=$CAP_SWAP $_ec_cgp"
# podman RUN accepts the full set.
PODMAN_RUN_CAPS="--memory=$CAP_MEM --memory-swap=$CAP_SWAP --pids-limit=$CAP_PIDS --cpus=$CAP_CPUS $_ec_cgp"
export PODMAN_BUILD_CAPS PODMAN_RUN_CAPS
