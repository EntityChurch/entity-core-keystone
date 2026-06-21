# Packaging — entity-core-protocol-dart (pub.dev)

Dart has a **single central package registry, [pub.dev](https://pub.dev/)**, so "packaging" here is
just the `pubspec.yaml` package manifest (unlike the C++ peer, which authors a CMake package + vcpkg
port + conan recipe because C++ has no single registry). This directory documents the publish path;
the manifest itself lives at [`../pubspec.yaml`](../pubspec.yaml).

## State: publish-READY, parked at `0.1.0-pre` (NOT published)

`/entity-rosetta` never publishes (lifecycle §Publishing) — it produces a ready-to-publish artifact;
an operator publishes after review. The package is well-formed and passes pub.dev validation
(`dart pub publish --dry-run` green); it is deliberately **not** pushed to pub.dev.

Two guards keep the parked state honest:

1. **`version: 0.1.0-pre`** — pub.dev's native SemVer pre-release form. Carried directly in the
   pubspec `version:` field (no doc-only split — pub.dev's version grammar accepts the `-pre`
   qualifier, unlike the CMake / ASDF dotted-numeric peers).
2. **`publish_to: none`** — the accidental-deploy guard. With this line, a `dart pub publish` is a
   no-op; `dart pub get` / local use still work. **`dart pub publish --dry-run` ignores this field**
   and still runs the full pub.dev validation suite — which is exactly how the package's
   well-formedness is proven without going online. Remove this line at the real publish.

## Manifest metadata (cohort convention)

| Field | Value | Note |
|---|---|---|
| `name` | `entity_core_protocol` | pub.dev names are `lowercase_with_underscores` — hyphens NOT allowed, so the keystone peer id `entity-core-protocol-dart` maps to this (A-DART-007). |
| `version` | `0.1.0-pre` | Parked pre-release (cohort `0.1.0-pre` convention). |
| `description` | pure-Dart V7 Layers 0–4 peer | 60–180 chars, the pub.dev length window. |
| `environment.sdk` | `^3.6.0` | Consumer-facing MINIMUM SDK floor (Dart-3 sealed classes / patterns / records). The peer is *built + certified* on the pinned SDK **3.11.6** (`containers/dart-toolchain`); it only *requires* 3.6 of a consumer — a deliberately wide reach floor, not a hard pin to 3.11. |
| `dependencies` | `cryptography_plus: 2.7.1`, `crypto: 3.0.6` | Exact pins (S11), mirrored in `containers/dart-toolchain/prefetch/pubspec.yaml`. |
| `dev_dependencies` | `test: 1.25.15` | DEV-scope only; never shipped in the published package. |
| `repository` / `homepage` / `documentation` / `issue_tracker` | keystone GitHub | pub.dev surfaces these on the package page; finalized at publish (or repointed to a per-language sibling repo if the S10 lift-out is taken). |
| `topics` | protocol, cbor, cryptography, networking | pub.dev discovery tags (lowercase, ≤5). |
| LICENSE | Apache-2.0 (`../LICENSE`) | S9 default; ecosystem-compatible (BSD-3 / Apache-2.0-leaning). pub.dev detects the `LICENSE` file. |

`pubspec.lock` is committed alongside the manifest (transitive deps locked); it stays coherent with
the exact pins above.

## Verify (in-container, sealed-offline)

```sh
# Full pub.dev validation suite (lint, structure, license, version, deps) — no upload.
podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none -v "$PWD":/work:Z -w /work/protocol-generator/dart \
  entity-core-keystone/dart-toolchain:latest dart pub publish --dry-run
```

`--dry-run` runs entirely offline against the warm `PUB_CACHE` in the image (`dart pub get --offline`
already satisfied). Any pub.dev *score* checks that would need network (e.g. live "is this version
new?" queries) are not exercised by `--dry-run` and are documented here rather than run online.

## Operator handoff — how to actually publish

When architecture signs off the v0.1 conformance bar, an external consumer confirms the peer, AND a
pub.dev publisher namespace is claimed:

1. **Decide in-repo vs standalone repo** (S10 lift-out is deferred keystone-wide; current default is
   in-repo under `protocol-generator/dart/`). Repoint `repository`/`homepage` if standalone.
2. **Claim the pub.dev verified publisher namespace** (e.g. `entitycore.org`) via the pub.dev
   publisher flow (DNS / Google account ownership) — the gate that cannot be done before first deploy
   (A-DART-007). Set `publisher` in `profile.toml [publishing]`.
3. **Settle the public-surface freeze** — lock the Tier-1 (`entity_core_protocol`) / Tier-2
   (`entity_core_peer`) library exports; mark internal `lib/src/...` units as such.
4. **Promote version** `0.1.0-pre → 0.1.0` in `pubspec.yaml` + `CHANGELOG.md` once the promotion gate
   is met (S4 fully green ✅ AND ≥1 external consumer confirms — not yet met).
5. **Remove `publish_to: none`**, set `repository:` to the final home, then
   `dart pub publish` (interactive auth against the verified publisher). **Tag the release** at the
   reviewed commit at this point only (lifecycle §"no auto-tag").
6. **Pin discipline** (S11): Dart SDK 3.11.6 + `cryptography_plus` 2.7.1 + `crypto` 3.0.6 +
   `test` 1.25.15 pins stay exact; re-pinning is deliberate + reviewed.
