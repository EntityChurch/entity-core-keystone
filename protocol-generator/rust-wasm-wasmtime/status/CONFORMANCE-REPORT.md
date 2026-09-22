<!-- current-pin-banner:d30c3dd0d4a1 -->
> **CURRENT (2026-09-01) — spec snapshot `v0.8.2.3`, executed check set `d30c3dd0d4a1…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **756 total · 310 pass · 337 warn · 0 FAIL · 109 skip** (elapsed 83503 ms).
>
> That digest is the pinned `core_executed_check_set_digest`, so this number is
> comparable to every other row in `CONFORMANCE-MATRIX.md` §1 — and it is a CONTENT
> anchor, which is the only kind that survives the release boundary ([ADR-0012] Am. 1).
> The machine-readable `CONFORMANCE-REPORT.json` beside this file is the authoritative
> artifact; `tools/check-set-gate.py --tracked` gates it, and this banner is generated
> from it by `tools/status-banner.py` rather than typed.

---

