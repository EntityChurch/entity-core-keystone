# Test vectors — pd peer (#33)

Real wire frames captured from the conformance oracle, used as offline
known-answer tests (KATs). These carry **real Ed25519 crypto** that hand-rolled
offline Python clients cannot produce (the reason S4 uses the live oracle).

- **`authenticate-frame.bin`** — a §4.6 `authenticate` EXECUTE frame (bare
  `{root, included}` wire envelope, 905 bytes) captured from `validate-peer`
  (oracle pin `cc1970f`, `tools/oracle-pin.env`) via a loopback tee in front of
  the real `pd` peer. Contents: the authenticate entity
  (`{peer_id, public_key, key_type, nonce}`) plus its `system/peer` and
  target-matching `system/signature` in `included`. Drives `make authkat`
  (`test/auth-verify-offline.c`): recompute the authenticate hash, find + verify
  the signature, and confirm the peer_id↔public_key identity binding — the
  accept-path of the §4.6 verification the oracle's tamper probes can't cover
  directly. (The nonce-echo rung needs the peer's per-connection issued nonce, so
  it is oracle-tested, not in this KAT.)

- **`authenticated-execute-frame.bin`** — a post-establishment authenticated
  `system/tree:get` EXECUTE (1790 bytes) captured from `validate-peer`. Contents:
  `root.data.{author, capability, operation, resource, ...}` plus an `included` map
  carrying the capability token (echoed back from the grant), both peer entities
  (author + granter), and two `system/signature`s (over the execute and over the
  token). Drives `make authzkat` (`test/authz-verify-offline.c`): the §5.2
  verify_request steps 1-4 — content-hash integrity, request signature
  (author-signed), grantee == author, and the single-link capability-chain
  signature (granter-signed) — all verifiable from the envelope's own included map.
  `check_permission` (§5.2 step 5, scope matching) is a separate increment.

- **`authz-deny-*.bin`** — four real DENY EXECUTEs captured from `validate-peer`'s
  `authz` category (via the loopback tee, `build/tee-capture.py`), one per DENY
  surface the §5.2a enumeration pins to a distinct `(status, code)`:
  - `authz-deny-deny_default.bin` — `get system/tree`, resource outside the cap's
    grant scope → **403 `capability_denied`** at `check_permission` (step 5).
  - `authz-deny-grantee-401.bin` — cap whose `grantee` ≠ author *and* does not
    resolve to a `system/peer` entity → **401 `unresolvable_grantee`** (§5.5/PR-3,
    the single authz→401 carve-out).
  - `authz-deny-no_catchall.bin` — cap whose `granter` is absent from `included`
    (chain unverifiable) → **403 `capability_denied`** (§5.5 `granter is null → DENY`).
  - `authz-deny-expired.bin` — cap with `expires_at` in the past → **403
    `capability_denied`** (§5.6 temporal validity; no separate `capability_expired`).

  Drive `make authzdenykat` (`test/authz-deny-offline.c`): each vector asserts the
  discriminating condition its rung keys on produces the spec-correct verdict —
  the offline logic cross-check for the seam rungs the live oracle drives end-to-end.
