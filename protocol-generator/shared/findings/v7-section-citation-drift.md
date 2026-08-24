# HANDOFF-TO-ARCH — 2026-08-17: stale "V7 §6.6" citation in the reference oracle, wire-observable

**To:** `entity-system-architecture` — cc `entity-core-go`
**From:** `entity-core-keystone` @ (this session, on top of `4027fbb`)
**Context:** found while starting the §6.2 reserved-pattern remediation
(`SESSION-HANDOFF-2026-08-17-oracle-repin-de8f807-and-reserved-pattern-gap.md`,
W-REGISTER-GUARD). Non-blocking — does not affect this week's release or the current
census verdict. D8 (surface spec drift) filing, not a fix request with a deadline.

## What we found

`entity-core-go` `de8f807`, `ext/handlers/handler.go:100,106,133-135,283-285,327-330`, and
`cmd/internal/validate/core_register_gate.go:376-377` all cite **"V7 §6.6"** for the
system-path-reservation rule ("user-installed handlers MUST NOT register at `system/*`
paths"). One of those citations is **wire-observable**: the `forbidden_pattern` 403
response body literally reads `"V7 §6.6: user-installed handlers MUST NOT register at
system/* paths: "+pattern`.

Checked against the current spec snapshot (`protocol-generator/shared/spec-data/v0.8.0/
ENTITY-CORE-PROTOCOL.md`, pinned, byte-verified):

- **§6.2 "System Handlers"** (line 2918) is where this rule actually lives now — matches
  keystone's own citation in the W-REGISTER-GUARD handoff and the spec's own informative
  summary (line 4001: *"System path reservation — user handlers MUST NOT register at
  `system/*` (§6.2)"*).
- **§6.6 is now "Path Dispatch"** (line 3370) — the longest-prefix handler-resolution walk.
  Unrelated rule. Citing §6.6 for the reservation guard points a reader at the wrong
  section entirely.

Also: the `v0.8.0/MANIFEST.md` cutover note (line 9) states the release-prep pass
stripped "bare V7 self-naming" from the *published spec document* — but `entity-core-go`'s
own source (134 files, `grep -rn "V7 §" cmd/ ext/`) still carries the pre-cutover
`V7 §X.Y` citation style throughout, including this now-mis-numbered one. Likely explanation:
the section moved during the V8 renumbering and this particular citation (plus its
`Declare()` twin) wasn't updated when the rest of the spec was.

## Why this matters (small, but real)

Not gated — `core_register_reserved_refused` checks status `403` only, not the message
body, so this doesn't affect conformance today. But:

1. It's returned over the wire in production peer responses, so any caller reading the
   error message for a human-facing citation gets pointed at the wrong section.
2. Keystone's own W-REGISTER-GUARD fix guidance quoted this exact string as the "reference
   fix shape" for all 45 peers to replicate. We caught it before any peer copied it — using
   `§6.2` (bare, no version prefix, matching the de-versioned convention) in our own peers
   instead — but if any other implementer copy-pastes Go's source comment/string verbatim,
   the wrong citation propagates further.

## Ask

Not urgent, no release blocker. When convenient: fix the 3 sites in `handler.go` (comment
at line 100, wire string at line 135, wire string at line 285, comment at line 328-329) and
the two `Declare()` strings in `core_register_gate.go` from `V7 §6.6` to `§6.2` (or
`ENTITY-CORE-PROTOCOL.md §6.2`, whichever citation style arch is standardizing on now that
the spec file is de-versioned). Worth a broader pass at some point over the other 130+
`V7 §X.Y` citations in `entity-core-go` to catch any other post-renumbering drift, but that's
a separate, larger cleanup — flagging the one we tripped over, not asking for the full sweep.

No response needed to unblock keystone; we're proceeding with `§6.2` in our own peers
regardless.
