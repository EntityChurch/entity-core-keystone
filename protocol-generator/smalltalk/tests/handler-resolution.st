"entity-core-protocol-smalltalk — 6.6 index/tree-walk EQUIVALENCE unit test (F62).

WHY THIS EXISTS AND WHY NO CONFORMANCE CHECK REPLACES IT. 6.6 resolve_handler walks path
prefixes for a system/handler entity and ends: an implementation MAY use a pre-built
dispatch index, and the index MUST produce equivalent results to the tree walk. This peer
has two containers -- the in-image `handlers` map, written at bootstrap, and the entity
tree, which is where the wire register op (6.2 WRITE 1) puts its system/handler entity.
Until 2026-09-09 only the map was consulted, so the peer answered 404 handler_not_found at
a pattern it had just answered 200 to a register for, and where the oracle can retrieve
the handler entity.

The oracle cannot catch it: core_register_* is nine checks that prove every WRITE and not
one of them then dispatches at the pattern it just proved exists. Measured -- this peer is
778 total / 333 pass / 338 warn / 0 FAIL / 107 skip with the defect and byte-identical
without it, 0 of 740 severities moved. So the gate is here or it is nowhere.

WHAT EACH CASE IS FOR. Case 1 is the ACCEPT direction and it is the one that validates the
FIXTURE: a test built only from deny cases is indistinguishable from one asserting that
resolution always fails. Cases 2 and 5 are the DENY controls that stop case 1 passing
because everything resolves. Case 3 is the walk itself rather than an exact-key hit. Case 4
separates a resolution miss (404) from a resolved handler with no runnable body (501) --
they are different failures and collapsing them is the defect this file gates. Case 6 is
the type test: system/handler/<pattern> carries a system/handler/interface entity, which is
a manifest and not a dispatch target, so it must NOT become resolvable.

Prints one line per case and a count. Prints OK / FAILED. Requires libentitycore_codec.so
on LD_LIBRARY_PATH (bootstrapWithSeed: derives the peer identity through the FFI)."

| out fails cases p pat abs ent res run |
out := WriteStream on: String new.
fails := 0.
cases := 0.
p := EcPeer new.
p bootstrapWithSeed: (ByteArray new: 32 withAll: 7).
pat := 'app/validate/f62/echo'.
abs := p peerAbs: pat.

"1 (DENY control) — nothing bound anywhere: resolution must MISS."
cases := cases + 1.
(p resolveHandler: pat) isNil
	ifTrue: [ out nextPutAll: 'PASS unbound pattern does not resolve'; nextPut: Character lf ]
	ifFalse: [ fails := fails + 1. out nextPutAll: 'FAIL unbound pattern resolved'; nextPut: Character lf ].

"Bind ONLY the tree entity — no `handlers` map entry. This is exactly what the wire
 register op leaves behind, and the whole point is that dispatch must see it."
ent := EcEntity type: 'system/handler' data: (EcVal map: {
	'interface' -> (EcVal text: 'system/handler/', pat).
	'expression_path' -> (EcVal text: 'system/compute/x') }).
p store bind: abs to: ent.

"2 (ACCEPT — validates the fixture) — a tree-bound system/handler MUST resolve."
cases := cases + 1.
(p resolveHandler: pat) = pat
	ifTrue: [ out nextPutAll: 'PASS tree-bound handler resolves (6.6 equivalence)'; nextPut: Character lf ]
	ifFalse: [ fails := fails + 1. out nextPutAll: 'FAIL tree-bound handler did not resolve'; nextPut: Character lf ].

"3 — the WALK: a deeper path resolves to its longest bound prefix, not by exact key."
cases := cases + 1.
(p resolveHandler: pat, '/deeper/still') = pat
	ifTrue: [ out nextPutAll: 'PASS deeper path walks back to the bound prefix'; nextPut: Character lf ]
	ifFalse: [ fails := fails + 1. out nextPutAll: 'FAIL backward walk did not reach the prefix'; nextPut: Character lf ].

"4 — resolved-but-no-body is 501, NOT 404. The two misses are different failures."
cases := cases + 1.
run := p runHandler: pat exec: nil envelope: nil on: nil.
(run status = 501 and: [ (run result field: 'code') string = 'no_handler_body' ])
	ifTrue: [ out nextPutAll: 'PASS resolved handler with no body answers 501 no_handler_body'; nextPut: Character lf ]
	ifFalse: [ fails := fails + 1. out nextPutAll: 'FAIL expected 501 no_handler_body, got '; print: run status; nextPut: Character lf ].

"6 (type test) — the 6.2 manifest path must NOT become a dispatch target. It carries a
 system/handler/interface entity; resolution must walk PAST it to the built-in handler."
cases := cases + 1.
p store bind: (p peerAbs: 'system/handler/', pat) to: (EcEntity type: 'system/handler/interface' data: (EcVal map: { 'pattern' -> (EcVal text: pat) })).
res := p resolveHandler: 'system/handler/', pat.
res = 'system/handler'
	ifTrue: [ out nextPutAll: 'PASS interface entity is not a dispatch target'; nextPut: Character lf ]
	ifFalse: [ fails := fails + 1. out nextPutAll: 'FAIL manifest path resolved to '; nextPutAll: res printString; nextPut: Character lf ].

"5 (DENY control) — unregister unbinds the path, so resolution must stop. No second
 teardown exists or is wanted: the tree IS the index, so one unbind is the whole story."
cases := cases + 1.
p store unbind: abs.
(p resolveHandler: pat) isNil
	ifTrue: [ out nextPutAll: 'PASS unbound handler stops resolving'; nextPut: Character lf ]
	ifFalse: [ fails := fails + 1. out nextPutAll: 'FAIL resolution survived the unbind'; nextPut: Character lf ].

out nextPut: Character lf.
"The COUNT is asserted, not just the failure list: an empty failure list is the output of a
 passing suite AND of one that examined nothing."
cases = 6
	ifFalse: [ fails := fails + 1. out nextPutAll: 'FAIL expected 6 cases, ran '; print: cases; nextPut: Character lf ].
fails = 0
	ifTrue: [ out nextPutAll: '=== handler-resolution: OK ('; print: cases; nextPutAll: ' cases) ===' ]
	ifFalse: [ out nextPutAll: '=== handler-resolution: FAILED ('; print: fails; nextPutAll: ') ===' ].
out contents
